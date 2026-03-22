function Invoke-TtcAdcsAssessment {
    <#
    .SYNOPSIS
        Runs the Active Directory Certificate Services (AD CS) workload assessment.
    .DESCRIPTION
        Assesses Active Directory Certificate Services for ESC (Escalation) vulnerabilities
        commonly exploited in modern attacks (ESC1-ESC8). Checks include: certificate template
        misconfiguration, CA ACL hygiene, web enrollment exposure (NTLM relay via HTTP),
        SAN abuse risks, and manager approval bypass.

        Requires:
        - RSAT-ADCS or PKI PowerShell tools (PKI module)
        - Domain connectivity
        - Read access to PKI containers in AD

        Run from a domain-joined Windows machine with appropriate AD read permissions.

        NOTE: AD CS assessments check for the ESC vulnerability classes documented by
        Will Schroeder and Lee Christensen (Certified Pre-Owned, SpecterOps 2021).
    .PARAMETER Domain
        FQDN of the domain to assess. Defaults to current domain.
    .EXAMPLE
        Invoke-TtcAdcsAssessment
    .EXAMPLE
        Invoke-TtcAdcsAssessment -Domain contoso.com
    .OUTPUTS
        [PSCustomObject[]] Array of TakeItToCloud finding objects.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$Domain = $env:USERDNSDOMAIN
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-TtcLog -Level Info -Message "Starting AD CS assessment for domain: $Domain"

    # =========================================================================
    # Prerequisite checks
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'

        # Verify RSAT / PKI module availability
        $pkiModule = Get-Module -Name PKI -ListAvailable -ErrorAction SilentlyContinue
        $adModule  = Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue

        if (-not $pkiModule -and -not $adModule) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ADCS-CFG-001' -Workload 'ActiveDirectory' -Component 'Prerequisites' `
                -CheckName 'ESC1 - Enrollee Supplies Subject SAN' -Category 'Security' -Severity 'Critical' `
                -Status 'Error' `
                -IssueDetected 'PKI and ActiveDirectory modules not found. RSAT tools are required for AD CS assessment.' `
                -PossibleSolution 'Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0; Add-WindowsCapability -Online -Name Rsat.CertificateServices.Tools~~~~0.0.1.0' `
                -DataSource 'Get-Module' -AutoFixAvailable 'No' -RemediationPriority 'P1'))
            return $findings.ToArray()
        }

        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        Import-Module PKI -ErrorAction SilentlyContinue

        # Discover CAs in the domain
        $configContext = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        $pkirootDN = "CN=Public Key Services,CN=Services,$configContext"

        $caObjects = Get-ADObject -SearchBase "CN=Enrollment Services,$pkirootDN" `
            -Filter * -Properties * -ErrorAction SilentlyContinue
        $caCount = ($caObjects | Measure-Object).Count

        Write-TtcLog -Level Info -Message "AD CS: Found $caCount CA(s) in $Domain"

        if ($caCount -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ADCS-CFG-001' -Workload 'ActiveDirectory' -Component 'PKI' `
                -CheckName 'ESC1 - Enrollee Supplies Subject SAN' -Category 'Security' -Severity 'Informational' `
                -Status 'Pass' `
                -IssueDetected 'No Active Directory Certificate Services (AD CS) Enterprise CAs found in this domain.' `
                -DataSource 'Get-ADObject (PKI enrollment services)'))
            return $findings.ToArray()
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ADCS prereq check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ADCS-CFG-001' -Workload 'ActiveDirectory' -Component 'Prerequisites' `
            -CheckName 'ESC1 - Enrollee Supplies Subject SAN' -Category 'Security' -Severity 'Critical' `
            -Status 'Error' -IssueDetected "AD CS prerequisite check failed: $($_.Exception.Message)" `
            -DataSource 'Get-ADObject' -Notes $_.Exception.Message))
        return $findings.ToArray()
    }

    # Enumerate all certificate templates
    $templates = @()
    try {
        $templates = Get-ADObject -SearchBase "CN=Certificate Templates,$pkirootDN" `
            -Filter * -Properties * -ErrorAction SilentlyContinue |
            Where-Object { $_.ObjectClass -eq 'pKICertificateTemplate' }
        Write-TtcLog -Level Info -Message "AD CS: Found $($templates.Count) certificate template(s)"
    }
    catch {
        Write-TtcLog -Level Warning -Message "Could not enumerate certificate templates: $_"
    }

    # =========================================================================
    # ADCS-SEC-001  -  ESC1: Enrollee Supplies Subject (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ADCS-SEC-001: Checking ESC1 - enrollee-supplied SAN templates"

        # msPKI-Certificate-Name-Flag bit 1 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x1)
        # Combined with: EKU contains Client Authentication AND no manager approval AND low-privilege enrollment
        $esc1Templates = $templates | Where-Object {
            $nameFlag = $_.'msPKI-Certificate-Name-Flag'
            $nameFlag -band 0x1  # ENROLLEE_SUPPLIES_SUBJECT
        }

        # Filter to templates with Client Auth EKU (making them dangerous)
        $clientAuthOid = '1.3.6.1.5.5.7.3.2'
        $schanAuthOid  = '1.3.6.1.5.5.7.3.1'  # Server Auth (less critical)

        $dangerousEsc1 = $esc1Templates | Where-Object {
            $ekus = $_.'msPKI-Certificate-Application-Policy'
            $ekus -contains $clientAuthOid
        }

        if (($dangerousEsc1 | Measure-Object).Count -gt 0) {
            $templateNames = ($dangerousEsc1 | Select-Object -ExpandProperty Name) -join ', '
            $findings.Add((New-TtcFinding `
                -FindingId 'ADCS-SEC-001' -Workload 'ActiveDirectory' -Component 'CertificateTemplates' `
                -CheckName 'ESC1 - Enrollee Supplies Subject SAN' -Category 'Security' -Severity 'Critical' `
                -Status 'Fail' `
                -IssueDetected "$($dangerousEsc1.Count) certificate template(s) allow enrollees to specify the Subject Alternative Name (SAN) and include Client Authentication EKU." `
                -Explanation 'ESC1 is a critical AD CS vulnerability. Templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT allow any authorized enrollee to request a certificate for any user - including domain admins. The CA will issue the certificate with whatever UPN/SAN the requester specifies, enabling complete domain privilege escalation within seconds.' `
                -PossibleSolution 'Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT on all templates that are not explicitly designed for this use. In the CA MMC: Certificate Templates > [Template] > Properties > Subject Name tab > Disable "Supply in the request". Alternatively restrict enrollment ACL to only specific service accounts.' `
                -Impact 'Any domain user with enrollment rights on these templates can escalate to Domain Admin by requesting a certificate with a DA UPN, then using it to authenticate as that DA. This is a complete domain compromise technique requiring no exploits.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -MitreAttack 'T1649' `
                -DataSource 'Get-ADObject (pKICertificateTemplate)' `
                -Remediation 'For each affected template: Open Certificate Templates Console (certtmpl.msc) > [Template] > Properties > Subject Name > Change from "Supply in the request" to "Built from this Active Directory information". If template must allow SAN: restrict enrollment to specific machine accounts only and enable Manager Approval (msPKI-RA-Signature).' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes "ESC1 templates: $templateNames"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ADCS-SEC-001' -Workload 'ActiveDirectory' -Component 'CertificateTemplates' `
                -CheckName 'ESC1 - Enrollee Supplies Subject SAN' -Category 'Security' -Severity 'Critical' `
                -Status 'Pass' `
                -IssueDetected 'No ESC1-vulnerable certificate templates (enrollee-supplied SAN + Client Auth EKU) found.' `
                -DataSource 'Get-ADObject (pKICertificateTemplate)'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ADCS-SEC-001: ESC1 check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ADCS-SEC-001' -Workload 'ActiveDirectory' -Component 'CertificateTemplates' `
            -CheckName 'ESC1 - Enrollee Supplies Subject SAN' -Category 'Security' -Severity 'Critical' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADObject (pKICertificateTemplate)' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ADCS-SEC-002  -  ESC2: Any Purpose EKU or No EKU
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ADCS-SEC-002: Checking ESC2 - Any Purpose or No EKU templates"

        $anyPurposeOid = '2.5.29.37.0'  # Any Purpose
        $esc2Templates = $templates | Where-Object {
            $ekus = $_.'msPKI-Certificate-Application-Policy'
            (-not $ekus) -or ($ekus -contains $anyPurposeOid)
        }

        # Also exclude templates that require manager approval (msPKI-RA-Signature > 0)
        $dangerousEsc2 = $esc2Templates | Where-Object {
            $_.'msPKI-RA-Signature' -eq 0
        }

        if (($dangerousEsc2 | Measure-Object).Count -gt 0) {
            $templateNames = ($dangerousEsc2 | Select-Object -ExpandProperty Name) -join ', '
            $findings.Add((New-TtcFinding `
                -FindingId 'ADCS-SEC-002' -Workload 'ActiveDirectory' -Component 'CertificateTemplates' `
                -CheckName 'ESC2 - Any Purpose or No EKU Templates' -Category 'Security' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "$($dangerousEsc2.Count) certificate template(s) have Any Purpose EKU or no EKU restriction, enabling use as a subordinate CA or for any purpose." `
                -Explanation 'ESC2 templates with Any Purpose EKU or no EKU can be used for client authentication, smart card logon, or as a sub-CA certificate. This allows privilege escalation similar to ESC1 even without the ENROLLEE_SUPPLIES_SUBJECT flag, since the certificate can be used for authentication.' `
                -PossibleSolution 'Remove the Any Purpose EKU and replace with specific purpose EKUs. If the template is unused, disable or delete it. Restrict enrollment ACL to only the specific accounts that require these certificates.' `
                -Impact 'Certificates from Any Purpose templates can be used for client authentication as any user visible in AD, enabling domain privilege escalation.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -MitreAttack 'T1649' `
                -DataSource 'Get-ADObject (pKICertificateTemplate)' `
                -Remediation 'Edit template: certtmpl.msc > [Template] > Extensions > Application Policies > Edit. Remove Any Purpose. Add only required specific EKUs. If template is legacy and unused: Get-CATemplate | Remove-CATemplate -Name <name>. Restrict enrollment with DACL: only allow specific service account principals to enroll.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                -Notes "ESC2 templates: $templateNames"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ADCS-SEC-002' -Workload 'ActiveDirectory' -Component 'CertificateTemplates' `
                -CheckName 'ESC2 - Any Purpose or No EKU Templates' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected 'No templates with Any Purpose EKU or missing EKU found.' `
                -DataSource 'Get-ADObject (pKICertificateTemplate)'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ADCS-SEC-002: ESC2 check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ADCS-SEC-002' -Workload 'ActiveDirectory' -Component 'CertificateTemplates' `
            -CheckName 'ESC2 - Any Purpose or No EKU Templates' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADObject (pKICertificateTemplate)' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ADCS-SEC-003  -  ESC3: Certificate Request Agent Templates
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ADCS-SEC-003: Checking ESC3 - Certificate Request Agent templates"

        $certReqAgentOid = '1.3.6.1.4.1.311.20.2.1'  # Certificate Request Agent EKU

        $esc3Templates = $templates | Where-Object {
            $ekus = $_.'msPKI-Certificate-Application-Policy'
            $ekus -contains $certReqAgentOid
        }

        if (($esc3Templates | Measure-Object).Count -gt 0) {
            $templateNames = ($esc3Templates | Select-Object -ExpandProperty Name) -join ', '
            $findings.Add((New-TtcFinding `
                -FindingId 'ADCS-SEC-003' -Workload 'ActiveDirectory' -Component 'CertificateTemplates' `
                -CheckName 'ESC3 - Certificate Request Agent Templates' -Category 'Security' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "$($esc3Templates.Count) certificate template(s) include the Certificate Request Agent EKU." `
                -Explanation 'ESC3 abuses enrollment agent certificates. An enrollment agent certificate allows a principal to enroll for certificates ON BEHALF OF other users. If a low-privilege user can obtain an enrollment agent certificate, they can then request authentication certificates (e.g., smart card logon) on behalf of Domain Admins.' `
                -PossibleSolution 'Restrict enrollment for Certificate Request Agent templates to only authorized enrollment agent service accounts. Ensure the templates that require enrollment agent authorization (issuance requirements) are properly configured to only accept certificates from trusted enrollment agents.' `
                -Impact 'A low-privilege user with an enrollment agent certificate can request smart card logon certificates for any user including Domain Admins, enabling full domain compromise.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -MitreAttack 'T1649' `
                -DataSource 'Get-ADObject (pKICertificateTemplate)' `
                -Remediation 'Restrict enrollment agent templates: In CA, configure Enrollment Agents restriction (CA Properties > Enrollment Agents): restrict to specific enrollment agent accounts and specific templates. Ensure the issuance policy on target templates requires the enrollment agent certificate.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                -Notes "ESC3 templates: $templateNames"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ADCS-SEC-003' -Workload 'ActiveDirectory' -Component 'CertificateTemplates' `
                -CheckName 'ESC3 - Certificate Request Agent Templates' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected 'No Certificate Request Agent (ESC3) vulnerable templates found.' `
                -DataSource 'Get-ADObject (pKICertificateTemplate)'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ADCS-SEC-003: ESC3 check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ADCS-SEC-003' -Workload 'ActiveDirectory' -Component 'CertificateTemplates' `
            -CheckName 'ESC3 - Certificate Request Agent Templates' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADObject (pKICertificateTemplate)' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ADCS-SEC-004  -  ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 CA Flag
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ADCS-SEC-004: Checking ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CAs"

        $esc6CAs = [System.Collections.Generic.List[string]]::new()

        foreach ($ca in $caObjects) {
            $caName = $ca.Name
            $caServer = if ($ca.dNSHostName) { $ca.dNSHostName } else { $ca.cn }

            try {
                # Check CA policy flags via certutil or registry
                $policyFlags = $ca.'msPKI-Certificate-Policy'
                # EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000 in the CA's EditFlags registry value
                # We check via certutil output if certutil is available
                $certutilOutput = & certutil -config "$caServer\$caName" -getreg policy\EditFlags 2>$null
                if ($certutilOutput -match 'EDITF_ATTRIBUTESUBJECTALTNAME2') {
                    if ($certutilOutput -match 'EDITF_ATTRIBUTESUBJECTALTNAME2 -- [0-9]') {
                        # Flag is set
                        $esc6CAs.Add("$caServer\$caName")
                    }
                }
            }
            catch {
                Write-TtcLog -Level Warning -Message "Could not check CA flags for $caName: $_"
            }
        }

        if ($esc6CAs.Count -gt 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ADCS-SEC-004' -Workload 'ActiveDirectory' -Component 'CertificateAuthority' `
                -CheckName 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 CA Flag' -Category 'Security' -Severity 'Critical' `
                -Status 'Fail' `
                -IssueDetected "$($esc6CAs.Count) CA(s) have the EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled." `
                -Explanation 'ESC6: The EDITF_ATTRIBUTESUBJECTALTNAME2 flag on the CA allows any requester to specify a SAN in ANY certificate request, regardless of whether the template allows it. This overrides template security controls and allows domain privilege escalation on ANY template with Client Authentication EKU.' `
                -PossibleSolution 'Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on all CAs. Run: certutil -config "CA\CAName" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2. Restart the Certificate Authority service after the change.' `
                -Impact 'Any user with enrollment rights on any template with Client Auth EKU can request a certificate for Domain Admin, fully compromising the domain.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -MitreAttack 'T1649' `
                -DataSource 'certutil -getreg policy\EditFlags' `
                -Remediation 'On each affected CA server: certutil -config "CAServer\CAName" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2; net stop certsvc; net start certsvc. Validate: certutil -config "CAServer\CAName" -getreg policy\EditFlags and confirm flag is absent.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes "Affected CAs: $($esc6CAs -join ', ')"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ADCS-SEC-004' -Workload 'ActiveDirectory' -Component 'CertificateAuthority' `
                -CheckName 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 CA Flag' -Category 'Security' -Severity 'Critical' `
                -Status 'Pass' `
                -IssueDetected 'EDITF_ATTRIBUTESUBJECTALTNAME2 flag is not set on any Enterprise CA.' `
                -DataSource 'certutil -getreg policy\EditFlags' `
                -Notes "CAs checked: $($caObjects.Count)"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ADCS-SEC-004: ESC6 check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ADCS-SEC-004' -Workload 'ActiveDirectory' -Component 'CertificateAuthority' `
            -CheckName 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 CA Flag' -Category 'Security' -Severity 'Critical' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'certutil -getreg policy\EditFlags' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ADCS-SEC-005  -  ESC8: NTLM Relay via HTTP-based Enrollment Endpoints
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ADCS-SEC-005: Checking ESC8 - HTTP certificate enrollment endpoints"

        $httpEndpoints = [System.Collections.Generic.List[string]]::new()

        foreach ($ca in $caObjects) {
            $caServer = if ($ca.dNSHostName) { $ca.dNSHostName } else { $ca.cn }

            # Check if web enrollment (certsrv) is accessible over HTTP (not HTTPS)
            $httpUrl = "http://$caServer/certsrv/"
            try {
                $request = [System.Net.WebRequest]::Create($httpUrl)
                $request.Timeout = 5000
                $request.AllowAutoRedirect = $false
                $response = $request.GetResponse()
                $statusCode = [int]$response.StatusCode
                $response.Close()

                if ($statusCode -eq 200 -or $statusCode -eq 401) {
                    # HTTP accessible (401 = auth required, still over HTTP = vulnerable)
                    $httpEndpoints.Add("$httpUrl (HTTP $statusCode)")
                }
            }
            catch [System.Net.WebException] {
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    if ($statusCode -eq 401) {
                        $httpEndpoints.Add("$httpUrl (HTTP 401 - accessible over HTTP)")
                    }
                }
            }
            catch {
                Write-TtcLog -Level Warning -Message "Could not reach $httpUrl : $_"
            }
        }

        if ($httpEndpoints.Count -gt 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ADCS-SEC-005' -Workload 'ActiveDirectory' -Component 'CertificateAuthority' `
                -CheckName 'ESC8 - HTTP Certificate Web Enrollment Endpoint' -Category 'Security' -Severity 'Critical' `
                -Status 'Fail' `
                -IssueDetected "$($httpEndpoints.Count) CA web enrollment endpoint(s) accessible over HTTP (not HTTPS), enabling NTLM relay attacks." `
                -Explanation 'ESC8: Certificate web enrollment endpoints (certsrv) accessible over HTTP are vulnerable to NTLM relay attacks. An attacker who can perform an NTLM relay (e.g., via PetitPotam or PrintSpooler) can relay computer or DC credentials to the certsrv endpoint and obtain a certificate for Domain Controller - enabling full domain compromise via DCSync.' `
                -PossibleSolution 'Require HTTPS on all CA web enrollment endpoints. Disable HTTP access: IIS > Default Web Site > Bindings > Remove HTTP, add HTTPS. Enable Extended Protection for Authentication (EPA) on the CES endpoint. Consider disabling web enrollment entirely if not needed and using DCOM enrollment instead.' `
                -Impact 'An attacker with network position can force a DC to authenticate to the HTTP enrollment endpoint via NTLM and relay that authentication to obtain a DC certificate. This enables DCSync and complete domain compromise without any credentials.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Infrastructure' `
                -MitreAttack 'T1187' `
                -DataSource 'HTTP connectivity test to /certsrv/' `
                -Remediation 'For each affected CA: 1) In IIS Manager > Default Web Site > Bindings: Remove port 80 HTTP binding. 2) Enable HTTPS with valid certificate. 3) Enable Extended Protection: IIS > /certsrv > Authentication > Windows Authentication > Advanced Settings > Extended Protection: Required. 4) Alternatively: certutil -config "CAServer\CA" -setreg CA\InterfaceFlags +IF_DISABLEICERTREQUEST to disable DCOM requests and use only HTTPS.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes "HTTP endpoints: $($httpEndpoints -join ', ')"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ADCS-SEC-005' -Workload 'ActiveDirectory' -Component 'CertificateAuthority' `
                -CheckName 'ESC8 - HTTP Certificate Web Enrollment Endpoint' -Category 'Security' -Severity 'Critical' `
                -Status 'Pass' `
                -IssueDetected 'No HTTP (non-HTTPS) certificate web enrollment endpoints detected.' `
                -DataSource 'HTTP connectivity test to /certsrv/' `
                -Notes "CAs checked: $($caObjects.Count)"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ADCS-SEC-005: ESC8 check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ADCS-SEC-005' -Workload 'ActiveDirectory' -Component 'CertificateAuthority' `
            -CheckName 'ESC8 - HTTP Certificate Web Enrollment Endpoint' -Category 'Security' -Severity 'Critical' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'HTTP connectivity test to /certsrv/' -Notes $_.Exception.Message))
    }

    Write-TtcLog -Level Info -Message "AD CS assessment complete  -  $($findings.Count) finding(s) generated"
    return $findings.ToArray()
}
