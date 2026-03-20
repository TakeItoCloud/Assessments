function Invoke-TtcExoAssessment {
    <#
    .SYNOPSIS
        Runs the Exchange Online workload assessment.
    .DESCRIPTION
        Performs a comprehensive assessment of Exchange Online mail security and configuration,
        covering: unified audit log status, mailbox audit logging, modern authentication, anti-malware
        policy configuration, DKIM signing, SPF/DMARC DNS records, automatic external forwarding,
        connector TLS enforcement, outbound spam notification, and Exchange admin role hygiene.

        Requires:
        - ExchangeOnlineManagement module v2+ connected via Connect-ExchangeOnline

        Recommended permissions (least-privilege):
        - View-Only Organization Management role group, OR
        - Global Reader + Exchange Administrator
    .PARAMETER MaxOrgMgmtMembers
        Maximum acceptable number of direct members in the Organization Management role group.
        Findings with membership exceeding this threshold are flagged as Fail.
        Default: 5
    .PARAMETER IncludeOnmicrosoftDomains
        When specified, includes .onmicrosoft.com domains in DKIM and SPF/DMARC checks.
        Default: $false (skips .onmicrosoft.com and .mail.onmicrosoft.com domains as they are
        Microsoft-managed and not customer-controlled)
    .EXAMPLE
        Invoke-TtcExoAssessment
    .EXAMPLE
        Invoke-TtcExoAssessment -MaxOrgMgmtMembers 3
    .OUTPUTS
        [PSCustomObject[]] Array of TakeItToCloud finding objects.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter()]
        [ValidateRange(1, 20)]
        [int]$MaxOrgMgmtMembers = 5,

        [Parameter()]
        [switch]$IncludeOnmicrosoftDomains
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-TtcLog -Level Info -Message "Starting Exchange Online assessment"

    # =========================================================================
    # Prerequisite: verify Exchange Online connection
    # =========================================================================
    $exoConnected = $false
    $orgConfig    = $null

    try {
        $ErrorActionPreference = 'Stop'
        $orgConfig    = Get-OrganizationConfig -ErrorAction Stop
        $exoConnected = $true
        Write-TtcLog -Level Info -Message "Exchange Online connected — org: $($orgConfig.DisplayName)"
    }
    catch {
        Write-TtcLog -Level Warning -Message "Exchange Online not connected or Get-OrganizationConfig failed: $($_.Exception.Message)"
    }

    if (-not $exoConnected) {
        $findings.Add((New-TtcFinding `
            -FindingId 'EXO-MON-002' -Workload 'ExchangeOnline' -Component 'Prerequisites' `
            -CheckName 'Unified Audit Log Status' -Category 'Monitoring' -Severity 'High' `
            -Status 'Error' `
            -IssueDetected 'Exchange Online is not connected — EXO assessment cannot proceed.' `
            -Explanation 'The Exchange Online assessment requires an active ExchangeOnlineManagement session. All checks in this workload are skipped.' `
            -PossibleSolution 'Run: Install-Module ExchangeOnlineManagement -Force; Connect-ExchangeOnline. Requires Exchange Administrator or Global Administrator credentials.' `
            -Impact 'No Exchange Online assessment data can be collected.' `
            -FrameworkMapping 'CIS-ContinuousMonitoring' -ZeroTrustPillar 'Infrastructure' `
            -DataSource 'Get-OrganizationConfig' -AutoFixAvailable 'No' -RemediationPriority 'P1'))
        return $findings.ToArray()
    }

    # Cache accepted domains for multi-check reuse
    $acceptedDomains = $null
    try {
        $acceptedDomains = Get-AcceptedDomain -ErrorAction SilentlyContinue
    }
    catch {
        Write-TtcLog -Level Warning -Message "Could not retrieve accepted domains: $($_.Exception.Message)"
    }

    # =========================================================================
    # EXO-MON-002 — Unified Audit Log Status
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "EXO-MON-002: Checking Unified Audit Log status"

        $auditConfig = Get-AdminAuditLogConfig -ErrorAction Stop

        if ($auditConfig.UnifiedAuditLogIngestionEnabled -eq $true) {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-MON-002' -Workload 'ExchangeOnline' -Component 'AuditLog' `
                -CheckName 'Unified Audit Log Status' -Category 'Monitoring' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected 'Unified Audit Log ingestion is enabled.' `
                -Explanation 'The Unified Audit Log records user and admin activity across Microsoft 365 services, supporting incident investigation and compliance reporting.' `
                -DataSource 'Get-AdminAuditLogConfig'))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-MON-002' -Workload 'ExchangeOnline' -Component 'AuditLog' `
                -CheckName 'Unified Audit Log Status' -Category 'Monitoring' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected 'Unified Audit Log ingestion is DISABLED — user and admin activity is not being recorded.' `
                -Explanation 'The Unified Audit Log records actions across Exchange Online, SharePoint, Teams, Entra ID, and other Microsoft 365 services. When disabled, there is no centralized record of user or admin activity for incident response, compliance investigations, or forensics.' `
                -PossibleSolution 'Enable via: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true. Or in the Microsoft Purview compliance portal: Audit > Start recording user and admin activity.' `
                -Impact 'Without audit logging, there is no forensic trail for security incidents. Compliance frameworks (SOC 2, ISO 27001, HIPAA) require audit logging. Incident response capabilities are severely limited.' `
                -FrameworkMapping 'CIS-ContinuousMonitoring' -ZeroTrustPillar 'Infrastructure' `
                -SecureScoreMapping 'Turn on audit data recording' `
                -DataSource 'Get-AdminAuditLogConfig' `
                -Remediation 'Enable: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true. Verify: (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled should return True. Microsoft enables this by default for new tenants since 2019 but it can be manually disabled. Confirm logs are flowing: search Purview Audit for activity from the past 24 hours.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P1'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "EXO-MON-002: Unified Audit Log check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'EXO-MON-002' -Workload 'ExchangeOnline' -Component 'AuditLog' `
            -CheckName 'Unified Audit Log Status' -Category 'Monitoring' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-AdminAuditLogConfig' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # EXO-MON-001 — Mailbox Audit Logging
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "EXO-MON-001: Checking mailbox audit logging configuration"

        # AuditDisabled = $false means audit IS enabled (double-negative property)
        if ($orgConfig.AuditDisabled -eq $false) {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-MON-001' -Workload 'ExchangeOnline' -Component 'MailboxAudit' `
                -CheckName 'Mailbox Audit Logging' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected 'Mailbox audit logging is enabled at the organization level.' `
                -Explanation 'Organization-level mailbox audit logging records mailbox access and modification events for all licensed mailboxes, enabling investigation of unauthorized access or data exfiltration.' `
                -DataSource 'Get-OrganizationConfig'))
        }
        elseif ($orgConfig.AuditDisabled -eq $true) {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-MON-001' -Workload 'ExchangeOnline' -Component 'MailboxAudit' `
                -CheckName 'Mailbox Audit Logging' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Fail' `
                -IssueDetected 'Mailbox audit logging has been DISABLED at the organization level.' `
                -Explanation 'Microsoft enables mailbox audit logging by default for all E3/E5 licensed mailboxes since January 2019. Disabling it removes the audit trail for mailbox access, delegate actions, and owner activity, hampering incident investigation when a mailbox is compromised.' `
                -PossibleSolution 'Re-enable: Set-OrganizationConfig -AuditDisabled $false. Verify: (Get-OrganizationConfig).AuditDisabled should return $false.' `
                -Impact 'No audit trail for mailbox access. Cannot determine what data was read or forwarded in a compromised mailbox scenario. Significant compliance impact for regulated industries.' `
                -FrameworkMapping 'CIS-ContinuousMonitoring' -ZeroTrustPillar 'Data' `
                -DataSource 'Get-OrganizationConfig' `
                -Remediation 'Enable: Set-OrganizationConfig -AuditDisabled $false. Verify audit actions are being logged: Get-Mailbox -ResultSize 10 | Select-Object AuditEnabled, AuditAdmin, AuditDelegate, AuditOwner. Default audit actions include: Update, MoveToDeletedItems, SoftDelete, HardDelete, FolderBind, SendAs, SendOnBehalf, Create.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P2'))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-MON-001' -Workload 'ExchangeOnline' -Component 'MailboxAudit' `
                -CheckName 'Mailbox Audit Logging' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'Mailbox audit status could not be definitively determined from organization config.' `
                -DataSource 'Get-OrganizationConfig' `
                -Notes "AuditDisabled property value: $($orgConfig.AuditDisabled)"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "EXO-MON-001: Mailbox audit check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'EXO-MON-001' -Workload 'ExchangeOnline' -Component 'MailboxAudit' `
            -CheckName 'Mailbox Audit Logging' -Category 'Monitoring' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-OrganizationConfig' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # EXO-SEC-001 — Modern Authentication Status
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "EXO-SEC-001: Checking modern authentication status"

        # OAuth2ClientProfileEnabled = $true means Modern Auth is ON
        if ($orgConfig.OAuth2ClientProfileEnabled -eq $true) {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-SEC-001' -Workload 'ExchangeOnline' -Component 'Authentication' `
                -CheckName 'Modern Authentication Status' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected 'Modern authentication (OAuth 2.0) is enabled for Exchange Online.' `
                -Explanation 'Modern authentication enables MFA and Conditional Access policies to apply to Exchange Online clients including Outlook for Windows, Mac, iOS, and Android.' `
                -DataSource 'Get-OrganizationConfig'))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-SEC-001' -Workload 'ExchangeOnline' -Component 'Authentication' `
                -CheckName 'Modern Authentication Status' -Category 'Security' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected 'Modern authentication (OAuth 2.0) is DISABLED for Exchange Online — clients use Basic authentication and bypass MFA.' `
                -Explanation 'Modern authentication is required for MFA and Conditional Access policies to apply to Exchange Online clients. When disabled, clients fall back to Basic authentication, which transmits credentials with every request and completely bypasses MFA controls regardless of Entra ID policy.' `
                -PossibleSolution 'Enable: Set-OrganizationConfig -OAuth2ClientProfileEnabled $true. This is enabled by default in new tenants. After enabling, verify Outlook and other clients reconnect using modern auth tokens.' `
                -Impact 'MFA and Conditional Access policies do not protect Exchange Online access. Credentials are transmitted with every request, increasing exposure to credential theft and replay attacks. BEC (Business Email Compromise) risk is significantly elevated.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -SecureScoreMapping 'Enable modern authentication for Exchange Online' `
                -DataSource 'Get-OrganizationConfig' `
                -Remediation 'Enable: Set-OrganizationConfig -OAuth2ClientProfileEnabled $true. Also block remaining legacy auth via Conditional Access: create a CA policy with condition "Client apps: Exchange ActiveSync clients, Other clients" and grant "Block access". This ensures no Basic auth fallback path remains. Verify: (Get-OrganizationConfig).OAuth2ClientProfileEnabled.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P1'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "EXO-SEC-001: Modern auth check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'EXO-SEC-001' -Workload 'ExchangeOnline' -Component 'Authentication' `
            -CheckName 'Modern Authentication Status' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-OrganizationConfig' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # EXO-SEC-002 — Anti-Malware Policy Configuration
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "EXO-SEC-002: Checking anti-malware policy configuration"

        $malwarePolicies = Get-MalwareFilterPolicy -ErrorAction Stop
        $defaultPolicy   = $malwarePolicies | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1
        if (-not $defaultPolicy) {
            $defaultPolicy = $malwarePolicies | Select-Object -First 1
        }

        if ($defaultPolicy) {
            $issues = [System.Collections.Generic.List[string]]::new()

            if ($defaultPolicy.EnableFileFilter -ne $true) {
                $issues.Add('File type filtering is not enabled (EnableFileFilter = false)')
            }
            if ($defaultPolicy.ZapEnabled -ne $true) {
                $issues.Add('Zero-Hour Auto Purge (ZAP) for malware is not enabled (ZapEnabled = false)')
            }
            if ($defaultPolicy.EnableInternalSenderAdminNotifications -ne $true -and
                $defaultPolicy.EnableExternalSenderAdminNotifications -ne $true) {
                $issues.Add('No admin notification address configured for detected malware')
            }

            $customCount = ($malwarePolicies | Where-Object { $_.IsDefault -ne $true } | Measure-Object).Count
            $notes = "Policy: $($defaultPolicy.Name) | FileFilter: $($defaultPolicy.EnableFileFilter) | ZAP: $($defaultPolicy.ZapEnabled) | CustomPolicies: $customCount"

            if ($issues.Count -gt 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'EXO-SEC-002' -Workload 'ExchangeOnline' -Component 'AntiMalware' `
                    -CheckName 'Anti-Malware Policy Configuration' -Category 'Security' -Severity 'High' `
                    -Status 'Warning' `
                    -IssueDetected "$($issues.Count) anti-malware policy gap(s): $($issues -join '; ')." `
                    -Explanation 'The Exchange Online anti-malware policy is the baseline defense against malware in email. File type filtering blocks dangerous attachment types before delivery. ZAP retroactively removes malware-positive messages from mailboxes after signature updates. Admin notifications alert the security team when malware is detected.' `
                    -PossibleSolution 'Enable file type filtering: Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true. Enable ZAP: Set-MalwareFilterPolicy -Identity Default -ZapEnabled $true. Add admin notification: Set-MalwareFilterPolicy -Identity Default -EnableInternalSenderAdminNotifications $true -InternalSenderAdminAddress secops@yourdomain.com.' `
                    -Impact 'Malicious email attachments may be delivered to users. Without ZAP, malware delivered before signature updates remain in mailboxes. Without file filtering, high-risk file types (.exe, .ps1, .vbs, .lnk) reach end users.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Enable anti-malware policies' `
                    -DataSource 'Get-MalwareFilterPolicy' `
                    -Remediation 'Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true -ZapEnabled $true -EnableInternalSenderAdminNotifications $true -InternalSenderAdminAddress <secops-email>. Consider upgrading to Defender for Office 365 Safe Attachments for sandbox-based detonation (requires P1 license). Review in Security portal: security.microsoft.com > Email & Collaboration > Policies & Rules > Threat policies > Anti-malware.' `
                    -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                    -Notes $notes))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'EXO-SEC-002' -Workload 'ExchangeOnline' -Component 'AntiMalware' `
                    -CheckName 'Anti-Malware Policy Configuration' -Category 'Security' -Severity 'High' `
                    -Status 'Pass' `
                    -IssueDetected 'Anti-malware policy has file type filtering, ZAP, and admin notification configured.' `
                    -DataSource 'Get-MalwareFilterPolicy' `
                    -Notes $notes))
            }
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-SEC-002' -Workload 'ExchangeOnline' -Component 'AntiMalware' `
                -CheckName 'Anti-Malware Policy Configuration' -Category 'Security' -Severity 'High' `
                -Status 'Error' -IssueDetected 'No anti-malware filter policy found — unexpected state in Exchange Online.' `
                -DataSource 'Get-MalwareFilterPolicy'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "EXO-SEC-002: Anti-malware check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'EXO-SEC-002' -Workload 'ExchangeOnline' -Component 'AntiMalware' `
            -CheckName 'Anti-Malware Policy Configuration' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MalwareFilterPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # EXO-SEC-003 — DKIM Signing Configuration
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "EXO-SEC-003: Checking DKIM signing configuration"

        $dkimConfigs = Get-DkimSigningConfig -ErrorAction Stop

        $domainsToCheck = if ($IncludeOnmicrosoftDomains) {
            $dkimConfigs
        }
        else {
            $dkimConfigs | Where-Object { $_.Domain -notlike '*.onmicrosoft.com' }
        }

        $checkedCount  = ($domainsToCheck | Measure-Object).Count
        $disabledItems = $domainsToCheck | Where-Object { $_.Enabled -eq $false }
        $disabledCount = ($disabledItems | Measure-Object).Count
        $enabledCount  = $checkedCount - $disabledCount

        if ($checkedCount -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-SEC-003' -Workload 'ExchangeOnline' -Component 'DKIM' `
                -CheckName 'DKIM Signing Configuration' -Category 'Security' -Severity 'High' `
                -Status 'Warning' `
                -IssueDetected 'No custom accepted domains have DKIM configuration — tenant may only use .onmicrosoft.com domain.' `
                -Explanation 'DKIM is applicable to custom domains only. A production tenant should have custom domains with DKIM configured. If this is intentional (brand-new tenant), add custom domains and configure DKIM.' `
                -DataSource 'Get-DkimSigningConfig' `
                -Notes 'No non-onmicrosoft.com DKIM configs found'))
        }
        elseif ($disabledCount -gt 0) {
            $disabledList = ($disabledItems | Select-Object -ExpandProperty Domain) -join '; '
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-SEC-003' -Workload 'ExchangeOnline' -Component 'DKIM' `
                -CheckName 'DKIM Signing Configuration' -Category 'Security' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "$disabledCount custom domain(s) do not have DKIM signing enabled: $disabledList" `
                -Explanation 'DKIM (DomainKeys Identified Mail) cryptographically signs outbound email, allowing receiving servers to verify the message was not tampered with in transit and originates from an authorized sender. Without DKIM, email spoofing is easier and DMARC enforcement falls back to SPF alignment only.' `
                -PossibleSolution 'For each disabled domain: (1) Retrieve CNAME values: Get-DkimSigningConfig -Identity <domain> | Select-Object Selector1CNAME, Selector2CNAME. (2) Publish both CNAME records in your DNS (selector1._domainkey.<domain>, selector2._domainkey.<domain>). (3) After DNS propagation: Set-DkimSigningConfig -Identity <domain> -Enabled $true.' `
                -Impact 'Email from your domains cannot be cryptographically verified by recipients. DMARC enforcement without DKIM relies solely on SPF alignment. Spoofed email from your domain is harder for recipients to detect.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                -SecureScoreMapping 'Enable DKIM signatures for your domain' `
                -DataSource 'Get-DkimSigningConfig' `
                -Remediation 'For each disabled domain: $cfg = Get-DkimSigningConfig -Identity <domain>. Create DNS CNAME records: selector1._domainkey.<domain> -> $cfg.Selector1CNAME and selector2._domainkey.<domain> -> $cfg.Selector2CNAME. After DNS propagation (up to 48h): Set-DkimSigningConfig -Identity <domain> -Enabled $true. Validate: Get-DkimSigningConfig -Identity <domain> | Select-Object Enabled, Selector1PublicKey.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                -Notes "DKIM disabled: $disabledList | Enabled: $enabledCount domain(s)"))
        }
        else {
            $enabledList = ($domainsToCheck | Select-Object -ExpandProperty Domain) -join '; '
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-SEC-003' -Workload 'ExchangeOnline' -Component 'DKIM' `
                -CheckName 'DKIM Signing Configuration' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected "DKIM signing is enabled for all $enabledCount assessed custom domain(s)." `
                -DataSource 'Get-DkimSigningConfig' `
                -Notes "Signed domains: $enabledList"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "EXO-SEC-003: DKIM check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'EXO-SEC-003' -Workload 'ExchangeOnline' -Component 'DKIM' `
            -CheckName 'DKIM Signing Configuration' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-DkimSigningConfig' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # EXO-CFG-001 — SPF and DMARC Record Configuration
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "EXO-CFG-001: Checking SPF and DMARC DNS records"

        $domainsToAudit = if ($acceptedDomains) {
            $acceptedDomains | Where-Object {
                (-not $IncludeOnmicrosoftDomains) -and
                $_.DomainName -notlike '*.onmicrosoft.com' -and
                $_.DomainName -notlike '*.mail.onmicrosoft.com'
            }
            if ($IncludeOnmicrosoftDomains) { $acceptedDomains }
        }
        else { @() }

        # Rebuild correctly: filter once
        $domainsToAudit = if ($acceptedDomains) {
            if ($IncludeOnmicrosoftDomains) {
                $acceptedDomains
            }
            else {
                $acceptedDomains | Where-Object {
                    $_.DomainName -notlike '*.onmicrosoft.com' -and
                    $_.DomainName -notlike '*.mail.onmicrosoft.com'
                }
            }
        }
        else { @() }

        $domainCount = ($domainsToAudit | Measure-Object).Count

        if ($domainCount -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-CFG-001' -Workload 'ExchangeOnline' -Component 'EmailAuthentication' `
                -CheckName 'SPF and DMARC Record Configuration' -Category 'Configuration' -Severity 'High' `
                -Status 'NotAssessed' -IssueDetected 'No custom accepted domains found — SPF/DMARC check not applicable.' `
                -DataSource 'Get-AcceptedDomain;Resolve-DnsName'))
        }
        else {
            $spfMissing   = [System.Collections.Generic.List[string]]::new()
            $dmarcMissing = [System.Collections.Generic.List[string]]::new()
            $dmarcWeak    = [System.Collections.Generic.List[string]]::new()
            $checked      = [System.Collections.Generic.List[string]]::new()

            foreach ($domain in $domainsToAudit) {
                $domainName = $domain.DomainName
                $checked.Add($domainName)

                # SPF check
                try {
                    $spfRecord = Resolve-DnsName -Name $domainName -Type TXT -ErrorAction SilentlyContinue |
                        Where-Object { $_.Strings -and ($_.Strings -join '') -like 'v=spf1*' } |
                        Select-Object -First 1

                    if (-not $spfRecord) {
                        $spfMissing.Add("$domainName (no SPF TXT record)")
                    }
                    elseif (($spfRecord.Strings -join '') -notlike '*spf.protection.outlook.com*' -and
                            ($spfRecord.Strings -join '') -notlike '*protection.outlook.com*') {
                        $spfMissing.Add("$domainName (SPF exists but does not include spf.protection.outlook.com)")
                    }
                }
                catch {
                    Write-TtcLog -Level Debug -Message "SPF DNS query failed for ${domainName}: $_"
                    $spfMissing.Add("$domainName (DNS lookup failed)")
                }

                # DMARC check
                try {
                    $dmarcRecord = Resolve-DnsName -Name "_dmarc.$domainName" -Type TXT -ErrorAction SilentlyContinue |
                        Where-Object { $_.Strings -and ($_.Strings -join '') -like 'v=DMARC1*' } |
                        Select-Object -First 1

                    if (-not $dmarcRecord) {
                        $dmarcMissing.Add("$domainName (no DMARC record at _dmarc.$domainName)")
                    }
                    else {
                        $dmarcValue = $dmarcRecord.Strings -join ''
                        if ($dmarcValue -notmatch 'p=(quarantine|reject)') {
                            $dmarcWeak.Add("$domainName (DMARC p=none — monitor only, no enforcement)")
                        }
                    }
                }
                catch {
                    Write-TtcLog -Level Debug -Message "DMARC DNS query failed for ${domainName}: $_"
                    $dmarcMissing.Add("$domainName (DNS lookup failed)")
                }
            }

            $criticalCount = $spfMissing.Count + $dmarcMissing.Count
            $notesBase     = "Domains assessed: $($checked -join ', ')"

            if ($criticalCount -gt 0) {
                $issueDesc = [System.Collections.Generic.List[string]]::new()
                if ($spfMissing.Count -gt 0)   { $issueDesc.Add("SPF issues ($($spfMissing.Count)): $($spfMissing -join '; ')") }
                if ($dmarcMissing.Count -gt 0)  { $issueDesc.Add("DMARC missing ($($dmarcMissing.Count)): $($dmarcMissing -join '; ')") }

                $findings.Add((New-TtcFinding `
                    -FindingId 'EXO-CFG-001' -Workload 'ExchangeOnline' -Component 'EmailAuthentication' `
                    -CheckName 'SPF and DMARC Record Configuration' -Category 'Configuration' -Severity 'High' `
                    -Status 'Fail' `
                    -IssueDetected "$criticalCount critical email authentication gap(s) found: $($issueDesc -join ' | ')" `
                    -Explanation 'SPF (Sender Policy Framework) identifies authorized mail servers for your domain. DMARC (Domain-based Message Authentication, Reporting and Conformance) ties SPF and DKIM together and instructs receivers how to handle authentication failures. Both are essential to prevent domain spoofing used in BEC, phishing, and brand abuse.' `
                    -PossibleSolution 'SPF: Add TXT record on yourdomain.com: "v=spf1 include:spf.protection.outlook.com -all". DMARC: Add TXT record on _dmarc.yourdomain.com: "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com". Validate with MXToolbox.com or the Microsoft DMARC diagnostics tool.' `
                    -Impact 'Without SPF: attackers can send email appearing to originate from your domain. Without DMARC: no automated enforcement even when SPF and DKIM are configured. Domain spoofing enables BEC, phishing, and brand damage.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Set up DMARC for your email domains' `
                    -DataSource 'Get-AcceptedDomain;Resolve-DnsName' `
                    -Remediation 'SPF: Publish TXT record "v=spf1 include:spf.protection.outlook.com ~all" (use -all for hard fail after testing). DMARC: Publish TXT at _dmarc.yourdomain.com: "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com". Start with p=none to review reports, advance to p=quarantine then p=reject. Ensure DKIM is also configured (EXO-SEC-003) for full email authentication.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                    -Notes $notesBase))
            }
            elseif ($dmarcWeak.Count -gt 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'EXO-CFG-001' -Workload 'ExchangeOnline' -Component 'EmailAuthentication' `
                    -CheckName 'SPF and DMARC Record Configuration' -Category 'Configuration' -Severity 'High' `
                    -Status 'Warning' `
                    -IssueDetected "SPF exists for all domains; DMARC exists but $($dmarcWeak.Count) domain(s) use policy=none (monitoring only): $($dmarcWeak -join '; ')" `
                    -Explanation 'DMARC policy=none only collects reporting data — it does not instruct receivers to quarantine or reject authentication failures. The domain is being monitored but not actively protected against spoofing. This is acceptable as a starting point but must be advanced to p=quarantine or p=reject.' `
                    -PossibleSolution 'Review DMARC aggregate reports at the rua address. Once SPF and DKIM are confirmed passing in the reports, update DMARC to p=quarantine. Progressively move to p=reject. DNS update: change TXT record at _dmarc.yourdomain.com.' `
                    -Impact 'Email that fails SPF/DKIM checks from your domain is not blocked by receivers. Spoofed email can still reach recipients. Brand protection is in monitoring mode only.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Set up DMARC for your email domains' `
                    -DataSource 'Get-AcceptedDomain;Resolve-DnsName' `
                    -Remediation 'Advance DMARC policy: 1. Confirm SPF/DKIM passing via DMARC reports. 2. Change to p=quarantine; pct=10. 3. Increase pct to 100. 4. Move to p=reject. Use DMARC Analyzer or Valimail for report analysis. DNS change: update _dmarc.yourdomain.com TXT record.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                    -Notes $notesBase))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'EXO-CFG-001' -Workload 'ExchangeOnline' -Component 'EmailAuthentication' `
                    -CheckName 'SPF and DMARC Record Configuration' -Category 'Configuration' -Severity 'High' `
                    -Status 'Pass' `
                    -IssueDetected "SPF and DMARC records are correctly configured for all $domainCount assessed custom domain(s)." `
                    -DataSource 'Get-AcceptedDomain;Resolve-DnsName' `
                    -Notes $notesBase))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "EXO-CFG-001: SPF/DMARC check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'EXO-CFG-001' -Workload 'ExchangeOnline' -Component 'EmailAuthentication' `
            -CheckName 'SPF and DMARC Record Configuration' -Category 'Configuration' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-AcceptedDomain;Resolve-DnsName' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # EXO-CFG-002 — Automatic External Email Forwarding
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "EXO-CFG-002: Checking automatic external email forwarding policy"

        $outboundPolicies = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop
        $defaultOutbound  = $outboundPolicies | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1
        if (-not $defaultOutbound) { $defaultOutbound = $outboundPolicies | Select-Object -First 1 }

        # AutoForwardingMode: Off (blocked), Automatic (Microsoft heuristics), On (unrestricted)
        $fwdMode = $defaultOutbound.AutoForwardingMode

        if ($fwdMode -eq 'Off') {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-CFG-002' -Workload 'ExchangeOnline' -Component 'MailForwarding' `
                -CheckName 'Automatic External Email Forwarding' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected 'Automatic external email forwarding is blocked (AutoForwardingMode = Off).' `
                -Explanation 'Blocking automatic external forwarding prevents attackers who compromise a mailbox from silently redirecting all incoming email to an external address — a primary Business Email Compromise (BEC) technique.' `
                -DataSource 'Get-HostedOutboundSpamFilterPolicy' `
                -Notes "AutoForwardingMode: $fwdMode"))
        }
        elseif ($fwdMode -eq 'On') {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-CFG-002' -Workload 'ExchangeOnline' -Component 'MailForwarding' `
                -CheckName 'Automatic External Email Forwarding' -Category 'Security' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected 'Automatic external email forwarding is fully ENABLED (AutoForwardingMode = On) — any user can silently exfiltrate email externally.' `
                -Explanation 'When AutoForwardingMode = On, Exchange Online permits inbox rules to automatically forward messages to any external address without restriction. After compromising a mailbox, attackers configure a forwarding rule to receive copies of all email silently — including invoices, wire transfer confirmations, credentials, and sensitive business communications.' `
                -PossibleSolution 'Immediately block: Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off. Audit existing forwarding: Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress -ne $null } | Select-Object Name, ForwardingSmtpAddress.' `
                -Impact 'Any compromised mailbox can silently forward all incoming email to an attacker-controlled address. Sensitive information, invoices, wire transfer requests, and strategic communications are exfiltrated continuously until the forwarding rule is discovered.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                -SecureScoreMapping 'Do not allow email forwarding to external domains' `
                -DataSource 'Get-HostedOutboundSpamFilterPolicy' `
                -Remediation 'Immediately: Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off. Audit active forwarding: Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress } | Select-Object UserPrincipalName, ForwardingAddress, ForwardingSmtpAddress | Export-Csv forwarding-audit.csv. Also check transport rules: Get-TransportRule | Where-Object { $_.RedirectMessageTo -or $_.BlindCopyTo }. Document and remediate each external forwarding destination.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P1' `
                -Notes "AutoForwardingMode: $fwdMode"))
        }
        else {
            # Automatic — Microsoft default, uses heuristics
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-CFG-002' -Workload 'ExchangeOnline' -Component 'MailForwarding' `
                -CheckName 'Automatic External Email Forwarding' -Category 'Security' -Severity 'High' `
                -Status 'Warning' `
                -IssueDetected "Automatic external forwarding is set to 'Automatic' (Microsoft heuristics) — forwarding is partially controlled but not fully blocked." `
                -Explanation 'AutoForwardingMode = Automatic applies Microsoft heuristics and reputation signals to decide whether to permit automatic forwarding. While this provides some protection, it does not guarantee all forwarding rules are blocked. Microsoft recommends setting this to Off to prevent all BEC-style email exfiltration through forwarding rules.' `
                -PossibleSolution 'Set to Off: Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off. Identify legitimate forwarding requirements first: Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress -ne $null }. Replace user-controlled forwarding with IT-managed transport rules for approved scenarios.' `
                -Impact 'Determined attackers who compromise high-reputation accounts may still establish forwarding rules. Heuristics-based filtering is not a substitute for explicit blocking of all automatic external forwarding.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                -SecureScoreMapping 'Do not allow email forwarding to external domains' `
                -DataSource 'Get-HostedOutboundSpamFilterPolicy' `
                -Remediation 'Inventory existing forwarding: Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress -ne $null } | Select-Object UserPrincipalName, ForwardingSmtpAddress. Obtain business sign-off on any legitimate forwarding. Create explicit transport rules for approved cases. Then: Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                -Notes "AutoForwardingMode: $fwdMode"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "EXO-CFG-002: External forwarding check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'EXO-CFG-002' -Workload 'ExchangeOnline' -Component 'MailForwarding' `
            -CheckName 'Automatic External Email Forwarding' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-HostedOutboundSpamFilterPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # EXO-CFG-003 — Connector TLS Enforcement
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "EXO-CFG-003: Checking connector TLS enforcement"

        $outboundConnectors = Get-OutboundConnector -ErrorAction Stop
        $inboundConnectors  = Get-InboundConnector  -ErrorAction Stop

        # Partner outbound connectors route to specific hosts (UseMxRecord = $false)
        $partnerOutbound    = $outboundConnectors | Where-Object { $_.Enabled -eq $true -and $_.UseMxRecord -eq $false }
        # TlsSettings of None means no TLS is required
        $outboundNoTls      = $partnerOutbound | Where-Object { $_.TlsSettings -eq 'None' -or [string]::IsNullOrEmpty($_.TlsSettings) }

        # Partner inbound connectors should require TLS
        $partnerInbound     = $inboundConnectors | Where-Object { $_.Enabled -eq $true -and $_.ConnectorType -eq 'Partner' }
        $inboundNoTls       = $partnerInbound | Where-Object { $_.RequireTls -ne $true }

        $outNoTlsCount = ($outboundNoTls | Measure-Object).Count
        $inNoTlsCount  = ($inboundNoTls | Measure-Object).Count
        $notes = "Outbound partner connectors: $(($partnerOutbound|Measure-Object).Count) | Inbound partner connectors: $(($partnerInbound|Measure-Object).Count)"

        if ($outNoTlsCount -eq 0 -and $inNoTlsCount -eq 0 -and
            ($partnerOutbound | Measure-Object).Count -eq 0 -and ($partnerInbound | Measure-Object).Count -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-CFG-003' -Workload 'ExchangeOnline' -Component 'Connectors' `
                -CheckName 'Connector TLS Enforcement' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected 'No custom partner connectors configured — default Exchange Online routing uses opportunistic TLS.' `
                -Explanation 'Default Exchange Online mail routing negotiates opportunistic TLS with receiving servers. No custom connector TLS configuration issues to report.' `
                -DataSource 'Get-OutboundConnector;Get-InboundConnector' `
                -Notes $notes))
        }
        elseif ($outNoTlsCount -gt 0 -or $inNoTlsCount -gt 0) {
            $issueList = [System.Collections.Generic.List[string]]::new()
            if ($outNoTlsCount -gt 0) {
                $names = ($outboundNoTls | Select-Object -ExpandProperty Name) -join '; '
                $issueList.Add("Outbound connectors without TLS ($outNoTlsCount): $names")
            }
            if ($inNoTlsCount -gt 0) {
                $names = ($inboundNoTls | Select-Object -ExpandProperty Name) -join '; '
                $issueList.Add("Inbound partner connectors without RequireTls ($inNoTlsCount): $names")
            }

            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-CFG-003' -Workload 'ExchangeOnline' -Component 'Connectors' `
                -CheckName 'Connector TLS Enforcement' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected "$($outNoTlsCount + $inNoTlsCount) connector(s) do not enforce TLS: $($issueList -join ' | ')" `
                -Explanation 'Partner connectors that do not enforce TLS transmit email in plaintext between Exchange Online and the partner system. This exposes potentially sensitive business communications to interception on the network path.' `
                -PossibleSolution 'Outbound: Set-OutboundConnector -Identity <name> -TlsSettings DomainValidation (requires valid cert on partner) or EncryptionOnly. Inbound: Set-InboundConnector -Identity <name> -RequireTls $true. Coordinate TLS certificate readiness with partner organizations before enforcing.' `
                -Impact 'Email between your organization and specific partner systems may traverse the internet in plaintext. Sensitive business communications, contracts, financial data, and credentials are vulnerable to interception.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Networks' `
                -DataSource 'Get-OutboundConnector;Get-InboundConnector' `
                -Remediation 'For outbound: Set-OutboundConnector -Identity <ConnectorName> -TlsSettings DomainValidation. Options: DomainValidation (cert + domain validation), CertificateValidation (cert validation only), EncryptionOnly (encrypt without cert validation). For inbound: Set-InboundConnector -Identity <ConnectorName> -RequireTls $true. Test connectivity after change: Test-OutboundConnector -Identity <ConnectorName>.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P3' `
                -Notes $notes))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-CFG-003' -Workload 'ExchangeOnline' -Component 'Connectors' `
                -CheckName 'Connector TLS Enforcement' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected "All partner connectors enforce TLS. Outbound: $(($partnerOutbound|Measure-Object).Count), Inbound: $(($partnerInbound|Measure-Object).Count)." `
                -DataSource 'Get-OutboundConnector;Get-InboundConnector' `
                -Notes $notes))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "EXO-CFG-003: Connector TLS check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'EXO-CFG-003' -Workload 'ExchangeOnline' -Component 'Connectors' `
            -CheckName 'Connector TLS Enforcement' -Category 'Configuration' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-OutboundConnector;Get-InboundConnector' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # EXO-CFG-004 — Anti-Spam Outbound Notification Configuration
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "EXO-CFG-004: Checking anti-spam outbound notification configuration"

        $outboundPolicies = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop
        $defaultOutbound  = $outboundPolicies | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1
        if (-not $defaultOutbound) { $defaultOutbound = $outboundPolicies | Select-Object -First 1 }

        $notifyEnabled = $defaultOutbound.NotifyOutboundSpam
        $bccEnabled    = $defaultOutbound.BccSuspiciousOutboundMail
        $notifyAddrs   = $defaultOutbound.NotifyOutboundSpamRecipients

        $notes = "NotifyOutboundSpam: $notifyEnabled | BccSuspiciousOutbound: $bccEnabled | NotifyRecipients: $($notifyAddrs -join ', ')"

        if ($notifyEnabled -eq $true -or $bccEnabled -eq $true) {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-CFG-004' -Workload 'ExchangeOnline' -Component 'AntiSpam' `
                -CheckName 'Anti-Spam Outbound Notification' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected 'Outbound spam admin notification is configured — security team will be alerted on compromised senders.' `
                -DataSource 'Get-HostedOutboundSpamFilterPolicy' `
                -Notes $notes))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-CFG-004' -Workload 'ExchangeOnline' -Component 'AntiSpam' `
                -CheckName 'Anti-Spam Outbound Notification' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'No admin notification configured for outbound spam detection — compromised accounts sending spam will not alert the security team.' `
                -Explanation 'When Exchange Online detects an account exceeding outbound spam thresholds (indicating credential compromise or malware), it can notify administrators. Without this notification, compromised accounts may continue sending spam undetected until external blocklists are triggered, causing email deliverability issues for the entire organization.' `
                -PossibleSolution 'Configure notification: Set-HostedOutboundSpamFilterPolicy -Identity Default -NotifyOutboundSpam $true -NotifyOutboundSpamRecipients @("secops@yourdomain.com"). Consider also enabling BCC copy: -BccSuspiciousOutboundMail $true.' `
                -Impact 'Compromised accounts sending spam are not detected until external systems (Spamhaus, Microsoft block lists) flag your mail server IP range. Delayed detection extends the spam campaign duration and causes mail delivery failures for all users.' `
                -FrameworkMapping 'NIST-Detect' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-HostedOutboundSpamFilterPolicy' `
                -Remediation 'Set-HostedOutboundSpamFilterPolicy -Identity Default -NotifyOutboundSpam $true -NotifyOutboundSpamRecipients @("secops@yourdomain.com"). Optionally add BCC: -BccSuspiciousOutboundMail $true -BccSuspiciousOutboundAdditionalRecipients @("secops@yourdomain.com"). Verify in Security portal: security.microsoft.com > Email & Collaboration > Policies & Rules > Threat policies > Anti-spam > Outbound spam filter.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P3' `
                -Notes $notes))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "EXO-CFG-004: Anti-spam notification check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'EXO-CFG-004' -Workload 'ExchangeOnline' -Component 'AntiSpam' `
            -CheckName 'Anti-Spam Outbound Notification' -Category 'Configuration' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-HostedOutboundSpamFilterPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # EXO-GOV-001 — Exchange Admin Role Hygiene
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "EXO-GOV-001: Checking Exchange Organization Management role membership"

        $orgMgmtMembers = Get-RoleGroupMember -Identity 'Organization Management' -ErrorAction Stop
        $orgMgmtCount   = ($orgMgmtMembers | Measure-Object).Count
        $memberNames    = ($orgMgmtMembers | Select-Object -ExpandProperty Name) -join '; '

        if ($orgMgmtCount -gt $MaxOrgMgmtMembers) {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-GOV-001' -Workload 'ExchangeOnline' -Component 'AdminRoles' `
                -CheckName 'Exchange Admin Role Hygiene' -Category 'Governance' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "$orgMgmtCount members in the Organization Management role group exceeds threshold of $MaxOrgMgmtMembers." `
                -Explanation 'The Organization Management role group in Exchange Online has the highest level of access, including the ability to manage all recipients, connectors, transport rules, compliance settings, and mail flow. Excessive membership increases the attack surface and the risk of accidental or deliberate misconfiguration.' `
                -PossibleSolution 'Review members: Get-RoleGroupMember -Identity "Organization Management". Remove accounts that do not require full Exchange admin access. Use least-privilege alternatives: Recipient Management (mailbox management), View-Only Organization Management (read-only), or Compliance Management (compliance only).' `
                -Impact 'Over-privileged Exchange admins can create mail flow bypass rules, disable security policies, create mailbox content search and export operations, or exfiltrate data. A compromised over-privileged account provides full control of email infrastructure.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                -SecureScoreMapping 'Reduce Exchange admin role membership' `
                -DataSource 'Get-RoleGroupMember' `
                -Remediation 'Review members: Get-RoleGroupMember -Identity "Organization Management" | Select-Object Name, RecipientType. Remove unneeded: Remove-RoleGroupMember -Identity "Organization Management" -Member <name>. Consider PIM (Privileged Identity Management) for time-bound Exchange admin access. Align with a documented admin roster reviewed quarterly.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                -Notes "Members ($orgMgmtCount/$MaxOrgMgmtMembers threshold): $memberNames"))
        }
        elseif ($orgMgmtCount -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-GOV-001' -Workload 'ExchangeOnline' -Component 'AdminRoles' `
                -CheckName 'Exchange Admin Role Hygiene' -Category 'Governance' -Severity 'High' `
                -Status 'Warning' `
                -IssueDetected 'Organization Management role group has 0 direct members — Exchange admin access may be via Global Administrator only.' `
                -Explanation 'Exchange Organization Management should have at least one explicitly assigned member for accountability and break-glass access. If managed solely via Global Administrator, all GAs have implicit full Exchange access which may not be intentional and should be documented.' `
                -DataSource 'Get-RoleGroupMember' `
                -Notes 'Direct members: 0'))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'EXO-GOV-001' -Workload 'ExchangeOnline' -Component 'AdminRoles' `
                -CheckName 'Exchange Admin Role Hygiene' -Category 'Governance' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected "$orgMgmtCount member(s) in Organization Management — within the $MaxOrgMgmtMembers-member threshold." `
                -DataSource 'Get-RoleGroupMember' `
                -Notes "Members: $memberNames"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "EXO-GOV-001: Admin role check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'EXO-GOV-001' -Workload 'ExchangeOnline' -Component 'AdminRoles' `
            -CheckName 'Exchange Admin Role Hygiene' -Category 'Governance' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-RoleGroupMember' -Notes $_.Exception.Message))
    }

    Write-TtcLog -Level Info -Message "Exchange Online assessment complete — $($findings.Count) finding(s) generated"
    return $findings.ToArray()
}
