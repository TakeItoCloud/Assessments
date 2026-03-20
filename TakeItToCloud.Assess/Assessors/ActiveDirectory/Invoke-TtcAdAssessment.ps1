function Invoke-TtcAdAssessment {
    <#
    .SYNOPSIS
        Runs the Active Directory workload assessment.
    .DESCRIPTION
        Performs a comprehensive assessment of on-premises Active Directory infrastructure
        covering replication health, domain controller redundancy and OS version, FSMO role
        availability, privileged group hygiene, Kerberos security, password policies,
        and audit policy configuration.

        Requires the ActiveDirectory RSAT module and domain connectivity.
        Run as a domain user with read access to AD objects and domain controllers.
    .PARAMETER DomainFQDN
        The fully qualified domain name of the domain to assess.
        Defaults to the current user's domain if not specified.
    .PARAMETER StaleDaysThreshold
        Number of days without logon before an account is considered stale.
        Default: 90
    .PARAMETER KrbtgtPasswordAgeDays
        Maximum acceptable age (in days) for the krbtgt account password before flagging.
        Default: 180
    .EXAMPLE
        Invoke-TtcAdAssessment
        Assesses the current domain with default thresholds.
    .EXAMPLE
        Invoke-TtcAdAssessment -DomainFQDN "corp.contoso.com" -StaleDaysThreshold 60
        Assesses the specified domain with a 60-day stale account threshold.
    .OUTPUTS
        [PSCustomObject[]] Array of TakeItToCloud finding objects.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter()]
        [string]$DomainFQDN = '',

        [Parameter()]
        [ValidateRange(30, 365)]
        [int]$StaleDaysThreshold = 90,

        [Parameter()]
        [ValidateRange(90, 730)]
        [int]$KrbtgtPasswordAgeDays = 180
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-TtcLog -Level Info -Message "Starting Active Directory assessment"

    # =========================================================================
    # Prerequisite: Verify ActiveDirectory module
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            Write-TtcLog -Level Warning -Message "ActiveDirectory module not available — returning NotAssessed"
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-HLT-001' -Workload 'ActiveDirectory' -Component 'Prerequisites' `
                -CheckName 'Domain Controller Replication Health' -Category 'Health' -Severity 'High' `
                -Status 'Error' `
                -IssueDetected 'ActiveDirectory RSAT module is not installed on the assessment machine.' `
                -Explanation 'The ActiveDirectory PowerShell module is required to assess on-premises AD. Install RSAT on Windows 10/11 or add the RSAT-AD-PowerShell feature on Windows Server.' `
                -PossibleSolution 'Windows 10/11: Add-WindowsCapability -Online -Name RSAT.ActiveDirectory*. Windows Server: Install-WindowsFeature -Name RSAT-AD-PowerShell.' `
                -Impact 'No Active Directory assessment data can be collected.' `
                -FrameworkMapping 'NIST-Identify' -ZeroTrustPillar 'Infrastructure' `
                -DataSource 'Get-Module' -AutoFixAvailable 'No' -RemediationPriority 'P1'))
            return $findings.ToArray()
        }
        Import-Module -Name ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-TtcLog -Level Error -Message "Failed to import ActiveDirectory module" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-HLT-001' -Workload 'ActiveDirectory' -Component 'Prerequisites' `
            -CheckName 'Domain Controller Replication Health' -Category 'Health' -Severity 'High' `
            -Status 'Error' `
            -IssueDetected "ActiveDirectory module import failed: $($_.Exception.Message)" `
            -DataSource 'Import-Module' -Notes $_.Exception.Message))
        return $findings.ToArray()
    }

    # =========================================================================
    # Establish domain context
    # =========================================================================
    $domain = $null
    $forest = $null
    try {
        $ErrorActionPreference = 'Stop'
        $domain = if ($DomainFQDN) { Get-ADDomain -Identity $DomainFQDN } else { Get-ADDomain }
        $forest = Get-ADForest
        Write-TtcLog -Level Info -Message "Assessing domain: $($domain.DNSRoot) (Forest: $($forest.Name))"
    }
    catch {
        Write-TtcLog -Level Error -Message "Cannot connect to domain" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-HLT-001' -Workload 'ActiveDirectory' -Component 'Domain' `
            -CheckName 'Domain Controller Replication Health' -Category 'Health' -Severity 'Critical' `
            -Status 'Error' `
            -IssueDetected "Cannot connect to Active Directory: $($_.Exception.Message)" `
            -DataSource 'Get-ADDomain' -Notes $_.Exception.Message))
        return $findings.ToArray()
    }

    # =========================================================================
    # AD-HLT-001 — DC Replication Health
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "AD-HLT-001: Checking replication health"

        $replFailures = Get-ADReplicationFailure -Scope Domain -Target $domain.DNSRoot -ErrorAction SilentlyContinue

        if ($replFailures -and ($replFailures | Measure-Object).Count -gt 0) {
            $failDetails = $replFailures | ForEach-Object {
                "$($_.Server) -> $($_.Partner): $($_.NumberOfFailures) failure(s), last: $($_.LastError)"
            }
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-HLT-001' -Workload 'ActiveDirectory' -Component 'Replication' `
                -CheckName 'Domain Controller Replication Health' -Category 'Health' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "$($replFailures.Count) replication failure(s) detected between domain controllers." `
                -Explanation 'AD replication failures prevent directory changes from propagating. This causes split-brain scenarios, stale group memberships, inconsistent Group Policy, and authentication failures depending on which DC a user hits.' `
                -PossibleSolution 'Run repadmin /replsummary and repadmin /showrepl to identify the failure path. Check DC-to-DC network connectivity, DNS resolution between DCs, and review Event IDs 1311, 1388, 2042 in the Directory Service log.' `
                -Impact 'Users may authenticate against stale data. Security group changes may not propagate. Group Policy may be inconsistently applied across sites.' `
                -FrameworkMapping 'NIST-Detect' -ZeroTrustPillar 'Infrastructure' `
                -DataSource 'Get-ADReplicationFailure' `
                -Remediation 'Run: repadmin /syncall /AdeP on each affected DC. If lingering objects exist: repadmin /removelingeringobjects. For tombstone-related failures, see Microsoft KB article 216783. Resolve underlying DNS or network issues between replication partners.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes ($failDetails -join '; ')))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-HLT-001' -Workload 'ActiveDirectory' -Component 'Replication' `
                -CheckName 'Domain Controller Replication Health' -Category 'Health' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected 'No AD replication failures detected.' `
                -DataSource 'Get-ADReplicationFailure'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "AD-HLT-001: Replication check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-HLT-001' -Workload 'ActiveDirectory' -Component 'Replication' `
            -CheckName 'Domain Controller Replication Health' -Category 'Health' -Severity 'High' `
            -Status 'Error' -IssueDetected "Replication check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADReplicationFailure' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # AD-HLT-002 — DC Redundancy + AD-HLT-003 — DC OS Version
    # =========================================================================
    $allDcs = $null
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "AD-HLT-002/003: Checking DC count and OS versions"

        $allDcs = Get-ADDomainController -Filter * -Server $domain.DNSRoot
        $dcCount = ($allDcs | Measure-Object).Count
        $dcNames = ($allDcs | Select-Object -ExpandProperty HostName) -join ', '

        if ($dcCount -lt 2) {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-HLT-002' -Workload 'ActiveDirectory' -Component 'DomainControllers' `
                -CheckName 'Domain Controller Redundancy' -Category 'Resilience' -Severity 'Critical' `
                -Status 'Fail' `
                -IssueDetected "Only $dcCount domain controller(s) found — single point of failure." `
                -Explanation 'A domain with one DC is a catastrophic single point of failure. If the DC fails or is rebooted for patching, all Kerberos authentication, LDAP queries, Group Policy, and DNS resolution for AD-joined systems fails.' `
                -PossibleSolution 'Deploy a minimum of two domain controllers in separate physical locations or Azure availability zones. Consider an Azure IaaS domain controller or Azure AD DS as an off-site hot standby.' `
                -Impact 'Complete authentication outage if the single DC becomes unavailable. No AD writes, no GP updates, DNS failures for AD-integrated zones.' `
                -FrameworkMapping 'NIST-Recover' -ZeroTrustPillar 'Infrastructure' `
                -DataSource 'Get-ADDomainController' `
                -Remediation 'Promote a second DC: Install-WindowsFeature AD-Domain-Services; Install-ADDSDomainController -DomainName $domain.DNSRoot. Place in a separate physical site or Azure region. Configure site links appropriately.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes "DCs found: $dcNames"))
        }
        elseif ($dcCount -eq 2) {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-HLT-002' -Workload 'ActiveDirectory' -Component 'DomainControllers' `
                -CheckName 'Domain Controller Redundancy' -Category 'Resilience' -Severity 'Low' `
                -Status 'Warning' `
                -IssueDetected 'Two domain controllers detected — minimum redundancy met but no buffer for maintenance.' `
                -Explanation 'With two DCs, patching or planned downtime of one leaves the environment running on a single DC, creating a temporary single point of failure. This is especially risky during patch windows.' `
                -PossibleSolution 'Consider promoting a third DC to maintain redundancy during maintenance windows. Stagger patching schedules to ensure at least two DCs are online at all times.' `
                -Impact 'During maintenance of either DC, authentication redundancy is temporarily lost.' `
                -FrameworkMapping 'NIST-Recover' -ZeroTrustPillar 'Infrastructure' `
                -DataSource 'Get-ADDomainController' -AutoFixAvailable 'No' -RemediationPriority 'P4' `
                -Notes "DCs: $dcNames"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-HLT-002' -Workload 'ActiveDirectory' -Component 'DomainControllers' `
                -CheckName 'Domain Controller Redundancy' -Category 'Resilience' -Severity 'Low' `
                -Status 'Pass' `
                -IssueDetected "$dcCount domain controllers detected — adequate redundancy." `
                -DataSource 'Get-ADDomainController' `
                -Notes "DCs: $dcNames"))
        }

        # AD-HLT-003 — OS Version (within same try block to reuse $allDcs)
        $eolDcs = $allDcs | Where-Object { $_.OperatingSystem -match '2003|2008|2012' }
        $eolCount = ($eolDcs | Measure-Object).Count

        if ($eolCount -gt 0) {
            $eolDetails = ($eolDcs | ForEach-Object { "$($_.HostName): $($_.OperatingSystem)" }) -join '; '
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-HLT-003' -Workload 'ActiveDirectory' -Component 'DomainControllers' `
                -CheckName 'Domain Controller OS Version' -Category 'Health' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "$eolCount DC(s) running an end-of-life Windows Server version (2012 R2 or earlier)." `
                -Explanation 'DCs running Windows Server 2012 R2 or older are beyond Microsoft extended support and receive no security patches. They remain exposed to known critical vulnerabilities including MS17-010 (EternalBlue) and cannot participate in modern domain/forest functional levels.' `
                -PossibleSolution 'Promote replacement DCs on Windows Server 2022, transfer FSMO roles, demote old DCs. Raise domain and forest functional level with Set-ADDomainMode / Set-ADForestMode after removing all downlevel DCs.' `
                -Impact 'Unpatched DCs expose the entire domain. EOL OS blocks forest functional level upgrades, preventing access to modern AD security features.' `
                -FrameworkMapping 'CIS-SecureConfig' -ZeroTrustPillar 'Infrastructure' `
                -DataSource 'Get-ADDomainController' `
                -Remediation 'Deploy new DC: Install-ADDSDomainController. Transfer FSMO: Move-ADDirectoryServerOperationMasterRole. Demote old DC: Uninstall-ADDSDomainController. Raise DFL: Set-ADDomainMode -Mode Windows2016Domain.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes $eolDetails))
        }
        else {
            $currentVersionDetails = ($allDcs | ForEach-Object { "$($_.HostName): $($_.OperatingSystem)" }) -join '; '
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-HLT-003' -Workload 'ActiveDirectory' -Component 'DomainControllers' `
                -CheckName 'Domain Controller OS Version' -Category 'Health' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected 'All domain controllers are running supported Windows Server versions.' `
                -DataSource 'Get-ADDomainController' `
                -Notes $currentVersionDetails))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "AD-HLT-002/003: DC health check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-HLT-002' -Workload 'ActiveDirectory' -Component 'DomainControllers' `
            -CheckName 'Domain Controller Redundancy' -Category 'Resilience' -Severity 'Critical' `
            -Status 'Error' -IssueDetected "DC health check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADDomainController' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # AD-HLT-004 — FSMO Role Holder Accessibility
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "AD-HLT-004: Checking FSMO role accessibility"

        $fsmoRoles = [ordered]@{
            'PDC Emulator'           = $domain.PDCEmulator
            'RID Master'             = $domain.RIDMaster
            'Infrastructure Master'  = $domain.InfrastructureMaster
            'Schema Master'          = $forest.SchemaMaster
            'Domain Naming Master'   = $forest.DomainNamingMaster
        }

        $unreachable = @()
        foreach ($role in $fsmoRoles.GetEnumerator()) {
            $reachable = Test-NetConnection -ComputerName $role.Value -Port 389 `
                -InformationLevel Quiet -WarningAction SilentlyContinue
            if (-not $reachable) {
                $unreachable += "$($role.Key): $($role.Value)"
            }
        }

        if ($unreachable.Count -gt 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-HLT-004' -Workload 'ActiveDirectory' -Component 'FSMO' `
                -CheckName 'FSMO Role Holder Accessibility' -Category 'Health' -Severity 'Critical' `
                -Status 'Fail' `
                -IssueDetected "$($unreachable.Count) FSMO role holder(s) not responding on LDAP port 389." `
                -Explanation 'FSMO role holders perform critical, non-replicated operations. PDC handles password changes and time sync; RID issues security identifiers; Infrastructure Master resolves cross-domain references; Schema/Naming Masters govern forest changes. Unreachable holders block these operations.' `
                -PossibleSolution 'Verify network connectivity and DNS resolution to FSMO holders. If a DC is permanently offline, seize the FSMO role using ntdsutil.exe or Move-ADDirectoryServerOperationMasterRole with the -Force parameter.' `
                -Impact 'Password changes may fail (PDC). New object creation blocked (RID). Cross-domain group references broken (Infrastructure Master). Schema and domain additions blocked (forest roles).' `
                -FrameworkMapping 'NIST-Identify' -ZeroTrustPillar 'Infrastructure' `
                -DataSource 'Get-ADDomain;Get-ADForest;Test-NetConnection' `
                -Remediation 'Test-NetConnection -ComputerName <FSMOHolder> -Port 389. For permanently offline DC: ntdsutil "roles" "connections" "connect to server <workingDC>" "seize <role name>" quit quit. Use with extreme caution — seizing should only occur if the original FSMO holder is permanently lost.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes ($unreachable -join '; ')))
        }
        else {
            $roleDetails = ($fsmoRoles.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join '; '
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-HLT-004' -Workload 'ActiveDirectory' -Component 'FSMO' `
                -CheckName 'FSMO Role Holder Accessibility' -Category 'Health' -Severity 'Critical' `
                -Status 'Pass' `
                -IssueDetected 'All five FSMO role holders are reachable on LDAP port 389.' `
                -DataSource 'Get-ADDomain;Get-ADForest;Test-NetConnection' `
                -Notes $roleDetails))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "AD-HLT-004: FSMO check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-HLT-004' -Workload 'ActiveDirectory' -Component 'FSMO' `
            -CheckName 'FSMO Role Holder Accessibility' -Category 'Health' -Severity 'Critical' `
            -Status 'Error' -IssueDetected "FSMO check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADDomain;Get-ADForest' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # AD-SEC-001 — Stale Privileged Group Members
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "AD-SEC-001: Checking privileged group membership freshness"

        $staleThreshold   = (Get-Date).AddDays(-$StaleDaysThreshold)
        $privilegedGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Group Policy Creator Owners','Administrators')
        $staleMembers     = [System.Collections.Generic.List[string]]::new()
        $totalPrivCount   = 0

        foreach ($groupName in $privilegedGroups) {
            try {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Server $domain.DNSRoot -ErrorAction SilentlyContinue
                if (-not $group) { continue }

                $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
                $userMembers = $members | Where-Object { $_.objectClass -eq 'user' }
                $totalPrivCount += ($userMembers | Measure-Object).Count

                foreach ($member in $userMembers) {
                    try {
                        $user = Get-ADUser -Identity $member.SamAccountName `
                            -Properties LastLogonDate, Enabled -Server $domain.DNSRoot -ErrorAction Stop
                        if ($user.Enabled -eq $false) {
                            $staleMembers.Add("[$groupName] $($member.SamAccountName) — DISABLED")
                        }
                        elseif (-not $user.LastLogonDate) {
                            $staleMembers.Add("[$groupName] $($member.SamAccountName) — NEVER LOGGED IN")
                        }
                        elseif ($user.LastLogonDate -lt $staleThreshold) {
                            $days = [int]((Get-Date) - $user.LastLogonDate).TotalDays
                            $staleMembers.Add("[$groupName] $($member.SamAccountName) — last logon ${days}d ago")
                        }
                    }
                    catch {
                        Write-TtcLog -Level Warning -Message "Could not query user $($member.SamAccountName): $_"
                    }
                }
            }
            catch {
                Write-TtcLog -Level Warning -Message "Could not enumerate group '$groupName': $_"
            }
        }

        if ($staleMembers.Count -gt 0) {
            $severity = if ($staleMembers.Count -ge 5) { 'Critical' } else { 'High' }
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-SEC-001' -Workload 'ActiveDirectory' -Component 'PrivilegedGroups' `
                -CheckName 'Stale Privileged Group Members' -Category 'Security' -Severity $severity `
                -Status 'Fail' `
                -IssueDetected "$($staleMembers.Count) privileged account(s) are stale (inactive >$StaleDaysThreshold days or disabled)." `
                -Explanation 'Stale administrator accounts are a primary lateral movement vector. Disabled accounts retain group membership and can be re-enabled by an attacker with sufficient privilege. Forgotten admin credentials are high-value targets for password spraying and credential stuffing.' `
                -PossibleSolution "Remove or disable inactive accounts from privileged groups immediately. Implement a quarterly privileged account review. Deploy a PAM solution (e.g., Microsoft Entra PIM, CyberArk) for Just-in-Time admin access." `
                -Impact 'An attacker who discovers or brute-forces a stale admin credential gains immediate Domain Admin access. Disabled admin accounts that are re-enabled become an instant privilege escalation path.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                -SecureScoreMapping 'Remove inactive accounts' `
                -DataSource 'Get-ADGroupMember;Get-ADUser' `
                -Remediation "For each stale account: Remove-ADGroupMember -Identity 'Domain Admins' -Members <user>. For disabled accounts: also remove from all other privileged groups. Implement CyberArk/BeyondTrust or Entra PIM for JIT admin access, eliminating standing privilege entirely." `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P1' `
                -Notes ($staleMembers -join '; ')))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-SEC-001' -Workload 'ActiveDirectory' -Component 'PrivilegedGroups' `
                -CheckName 'Stale Privileged Group Members' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected "All $totalPrivCount privileged account(s) have authenticated within $StaleDaysThreshold days." `
                -DataSource 'Get-ADGroupMember;Get-ADUser'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "AD-SEC-001: Stale member check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-SEC-001' -Workload 'ActiveDirectory' -Component 'PrivilegedGroups' `
            -CheckName 'Stale Privileged Group Members' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADGroupMember' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # AD-SEC-002 — Default Administrator Account Hygiene
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "AD-SEC-002: Checking built-in Administrator account"

        $adminSID      = New-Object System.Security.Principal.SecurityIdentifier("$($domain.DomainSID.Value)-500")
        $builtinAdmin  = Get-ADUser -Identity $adminSID `
            -Properties Enabled, LastLogonDate, SamAccountName, PasswordLastSet `
            -Server $domain.DNSRoot

        $issues = [System.Collections.Generic.List[string]]::new()
        if ($builtinAdmin.Enabled) {
            $issues.Add('Account is ENABLED')
        }
        if ($builtinAdmin.SamAccountName -ieq 'Administrator') {
            $issues.Add('Account name has not been changed from default "Administrator"')
        }

        if ($issues.Count -gt 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-SEC-002' -Workload 'ActiveDirectory' -Component 'LocalAccounts' `
                -CheckName 'Default Administrator Account Hygiene' -Category 'Security' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "Built-in Administrator (RID-500) issues: $($issues -join '; ')." `
                -Explanation 'The built-in Administrator (RID-500) has a well-known, predictable SID across all domains. This makes it a top target for brute-force and pass-the-hash attacks. The account cannot be locked out by account lockout policy, making password spray attacks more effective.' `
                -PossibleSolution 'Rename the account to a non-guessable name. Disable the account entirely if a named admin account exists. Ensure a strong, unique password is set even when disabled.' `
                -Impact 'The account cannot be locked out. If its credentials are compromised, the attacker gains permanent domain admin access that is immune to lockout policies.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-ADUser' `
                -Remediation 'Rename: Get the DN with (Get-ADUser -Identity $adminSID).DistinguishedName then use Rename-ADObject. Disable: Disable-ADAccount -Identity $adminSID. Set complex password: Set-ADAccountPassword -Identity $adminSID. Configure via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > "Accounts: Rename administrator account".' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                -Notes "SamAccountName: $($builtinAdmin.SamAccountName) | Enabled: $($builtinAdmin.Enabled) | LastLogon: $($builtinAdmin.LastLogonDate) | PwdLastSet: $($builtinAdmin.PasswordLastSet)"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-SEC-002' -Workload 'ActiveDirectory' -Component 'LocalAccounts' `
                -CheckName 'Default Administrator Account Hygiene' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected 'Built-in Administrator is renamed and disabled.' `
                -DataSource 'Get-ADUser' `
                -Notes "SamAccountName: $($builtinAdmin.SamAccountName) | Enabled: $($builtinAdmin.Enabled)"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "AD-SEC-002: Admin account check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-SEC-002' -Workload 'ActiveDirectory' -Component 'LocalAccounts' `
            -CheckName 'Default Administrator Account Hygiene' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADUser' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # AD-SEC-003 — Unconstrained Kerberos Delegation
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "AD-SEC-003: Checking unconstrained Kerberos delegation"

        # DCs always have unconstrained delegation by design — exclude them
        $dcDNS = if ($allDcs) {
            $allDcs | Select-Object -ExpandProperty Name
        }
        else {
            (Get-ADDomainController -Filter * -Server $domain.DNSRoot).Name
        }

        $unconstrainedComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation, OperatingSystem -Server $domain.DNSRoot |
            Where-Object { $_.Name -notin $dcDNS }

        $unconstrainedUsers = Get-ADUser -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation -Server $domain.DNSRoot

        $compCount = ($unconstrainedComputers | Measure-Object).Count
        $userCount = ($unconstrainedUsers    | Measure-Object).Count
        $totalUnconstrained = $compCount + $userCount

        if ($totalUnconstrained -gt 0) {
            $details = [System.Collections.Generic.List[string]]::new()
            $unconstrainedComputers | ForEach-Object { $details.Add("Computer: $($_.Name) ($($_.OperatingSystem))") }
            $unconstrainedUsers    | ForEach-Object { $details.Add("User: $($_.SamAccountName)") }

            $findings.Add((New-TtcFinding `
                -FindingId 'AD-SEC-003' -Workload 'ActiveDirectory' -Component 'Delegation' `
                -CheckName 'Unconstrained Kerberos Delegation' -Category 'Security' -Severity 'Critical' `
                -Status 'Fail' `
                -IssueDetected "$totalUnconstrained non-DC object(s) configured with unconstrained Kerberos delegation ($compCount computers, $userCount users)." `
                -Explanation 'Unconstrained delegation allows the host to impersonate any user to any service. Attackers exploit this via the "Printer Bug" (MS-RPRN) or PetitPotam to coerce DC computer accounts to authenticate to a compromised server, capturing TGTs that enable DCSync and full domain compromise.' `
                -PossibleSolution 'Remove unconstrained delegation and replace with constrained delegation (KCD) or Resource-Based Constrained Delegation (RBCD). Mandate sensitive accounts join the "Protected Users" group or be flagged "Account is sensitive and cannot be delegated".' `
                -Impact 'A single compromised host with unconstrained delegation can be leveraged to capture Domain Controller TGTs, enabling a Golden Ticket attack and complete domain compromise.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-ADComputer;Get-ADUser' `
                -Remediation 'For each computer: Set-ADComputer -Identity <name> -TrustedForDelegation $false. Then configure constrained delegation: Set-ADComputer -Identity <name> -Add @{''msDS-AllowedToDelegateTo''=''http/targetserver.contoso.com''}. For user accounts: Set-ADUser -Identity <user> -TrustedForDelegation $false. Remove unnecessary SPNs.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P1' `
                -Notes ($details -join '; ')))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-SEC-003' -Workload 'ActiveDirectory' -Component 'Delegation' `
                -CheckName 'Unconstrained Kerberos Delegation' -Category 'Security' -Severity 'Critical' `
                -Status 'Pass' `
                -IssueDetected 'No non-DC objects configured with unconstrained Kerberos delegation.' `
                -DataSource 'Get-ADComputer;Get-ADUser'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "AD-SEC-003: Delegation check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-SEC-003' -Workload 'ActiveDirectory' -Component 'Delegation' `
            -CheckName 'Unconstrained Kerberos Delegation' -Category 'Security' -Severity 'Critical' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADComputer;Get-ADUser' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # AD-SEC-004 — Krbtgt Account Password Age
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "AD-SEC-004: Checking krbtgt password age"

        $krbtgt = Get-ADUser -Identity 'krbtgt' `
            -Properties PasswordLastSet, Created -Server $domain.DNSRoot

        $ageSource = if ($krbtgt.PasswordLastSet) { $krbtgt.PasswordLastSet } else { $krbtgt.Created }
        $krbtgtAge = [int]((Get-Date) - $ageSource).TotalDays

        if ($krbtgtAge -gt $KrbtgtPasswordAgeDays) {
            $severity = if ($krbtgtAge -gt 365) { 'Critical' } else { 'High' }
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-SEC-004' -Workload 'ActiveDirectory' -Component 'Kerberos' `
                -CheckName 'Krbtgt Account Password Age' -Category 'Security' -Severity $severity `
                -Status 'Fail' `
                -IssueDetected "Krbtgt password is $krbtgtAge days old (threshold: $KrbtgtPasswordAgeDays days)." `
                -Explanation 'The krbtgt secret signs all Kerberos Ticket-Granting Tickets in the domain. If this hash was stolen, an attacker can forge TGTs for any identity with any lifetime (Golden Ticket). Only rotating the password invalidates all outstanding Golden Tickets. A stale password means any stolen hash remains exploitable indefinitely.' `
                -PossibleSolution 'Reset the krbtgt password twice: once to change it, wait for replication (10+ hours / one max ticket lifetime), then reset again to invalidate TGTs issued with the old hash. Use the Microsoft krbtgt reset script for safe orchestration.' `
                -Impact 'If the krbtgt hash was exfiltrated, Golden Tickets created with it remain valid until the password is rotated twice. An attacker maintains persistent, indelible access to the domain until rotation occurs.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-ADUser' `
                -Remediation 'Use Microsoft KrbtgtKeys.ps1 script (search "New-KrbtgtKeys.ps1" on GitHub). Manual: Set-ADAccountPassword -Identity krbtgt -Reset. Wait at least 10 hours or one max ticket lifetime (default 10 hours) for replication. Run Set-ADAccountPassword again. Monitor for Kerberos errors during rotation.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                -Notes "PasswordLastSet: $ageSource | Age: $krbtgtAge days"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-SEC-004' -Workload 'ActiveDirectory' -Component 'Kerberos' `
                -CheckName 'Krbtgt Account Password Age' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected "Krbtgt password is $krbtgtAge days old — within the $KrbtgtPasswordAgeDays-day threshold." `
                -DataSource 'Get-ADUser' `
                -Notes "PasswordLastSet: $ageSource"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "AD-SEC-004: Krbtgt check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-SEC-004' -Workload 'ActiveDirectory' -Component 'Kerberos' `
            -CheckName 'Krbtgt Account Password Age' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADUser' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # AD-SEC-005 — Protected Users Security Group Coverage
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "AD-SEC-005: Checking Protected Users group coverage"

        $protectedGroup = Get-ADGroup -Filter "Name -eq 'Protected Users'" -Server $domain.DNSRoot -ErrorAction SilentlyContinue

        if (-not $protectedGroup) {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-SEC-005' -Workload 'ActiveDirectory' -Component 'PrivilegedGroups' `
                -CheckName 'Protected Users Security Group Coverage' -Category 'Security' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'Protected Users group not found. Domain functional level may be below Windows Server 2012 R2.' `
                -Explanation 'The Protected Users group enforces hardened credential requirements: Kerberos-only (no NTLM), no DES/RC4, no delegation, short TGT lifetime (4 hours). This prevents pass-the-hash, NTLM relay, and credential caching attacks on privileged accounts.' `
                -PossibleSolution 'Raise the domain functional level to Windows Server 2012 R2 minimum: Set-ADDomainMode -Identity $domain.DNSRoot -Mode Windows2012R2Domain. Then add all privileged accounts to Protected Users.' `
                -Impact 'Privileged accounts remain vulnerable to NTLM relay, pass-the-hash, and credential-caching attacks.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-ADGroup' -AutoFixAvailable 'No' -RemediationPriority 'P3'))
        }
        else {
            $protectedMembers = (Get-ADGroupMember -Identity $protectedGroup -Recursive -ErrorAction SilentlyContinue) |
                Where-Object { $_.objectClass -eq 'user' } |
                Select-Object -ExpandProperty SamAccountName

            $privGroupNames = @('Domain Admins','Enterprise Admins','Schema Admins')
            $allPrivUsers   = [System.Collections.Generic.List[string]]::new()
            foreach ($g in $privGroupNames) {
                $grp = Get-ADGroup -Filter "Name -eq '$g'" -Server $domain.DNSRoot -ErrorAction SilentlyContinue
                if ($grp) {
                    Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue |
                        Where-Object { $_.objectClass -eq 'user' } |
                        ForEach-Object {
                            if ($_.SamAccountName -notin $allPrivUsers) {
                                $allPrivUsers.Add($_.SamAccountName)
                            }
                        }
                }
            }

            $notProtected = $allPrivUsers | Where-Object { $_ -notin $protectedMembers }
            $notProtectedCount = ($notProtected | Measure-Object).Count

            if ($notProtectedCount -gt 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'AD-SEC-005' -Workload 'ActiveDirectory' -Component 'PrivilegedGroups' `
                    -CheckName 'Protected Users Security Group Coverage' -Category 'Security' -Severity 'Medium' `
                    -Status 'Warning' `
                    -IssueDetected "$notProtectedCount privileged user(s) are not members of the Protected Users group." `
                    -Explanation 'Privileged accounts outside of Protected Users can have credentials cached via NTLM, are susceptible to NTLM relay, and can be abused via delegation. Protected Users prevents all of these attack vectors for the accounts it covers.' `
                    -PossibleSolution 'Add all Domain, Enterprise, and Schema Admins to Protected Users. Test in a lab environment first — Protected Users disables NTLM which may break applications or services that authenticate with these accounts.' `
                    -Impact 'Privileged accounts not in Protected Users remain vulnerable to pass-the-hash, NTLM relay, and unconstrained delegation abuse.' `
                    -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                    -DataSource 'Get-ADGroupMember' `
                    -Remediation 'Add-ADGroupMember -Identity "Protected Users" -Members @(<list>). Audit each account: Get-ADFineGrainedPasswordPolicySubject -Identity "Protected Users". Verify no services or scheduled tasks run as these accounts before adding them.' `
                    -AutoFixAvailable 'Partial' -RemediationPriority 'P3' `
                    -Notes "Not in Protected Users: $($notProtected -join '; ')"))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'AD-SEC-005' -Workload 'ActiveDirectory' -Component 'PrivilegedGroups' `
                    -CheckName 'Protected Users Security Group Coverage' -Category 'Security' -Severity 'Medium' `
                    -Status 'Pass' `
                    -IssueDetected "All $($allPrivUsers.Count) privileged user(s) are members of the Protected Users group." `
                    -DataSource 'Get-ADGroupMember'))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "AD-SEC-005: Protected Users check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-SEC-005' -Workload 'ActiveDirectory' -Component 'PrivilegedGroups' `
            -CheckName 'Protected Users Security Group Coverage' -Category 'Security' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADGroup' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # AD-CFG-001 — Default Domain Password Policy
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "AD-CFG-001: Checking default domain password policy"

        $passwordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $domain.DNSRoot
        $policyIssues   = [System.Collections.Generic.List[string]]::new()

        if ($passwordPolicy.MinPasswordLength -lt 12) {
            $policyIssues.Add("MinPasswordLength is $($passwordPolicy.MinPasswordLength) (recommend 14+)")
        }
        if (-not $passwordPolicy.ComplexityEnabled) {
            $policyIssues.Add('Password complexity is DISABLED')
        }
        if ($passwordPolicy.MaxPasswordAge.TotalDays -eq 0) {
            $policyIssues.Add('Passwords never expire (MaxPasswordAge = 0 / unlimited)')
        }
        elseif ($passwordPolicy.MaxPasswordAge.TotalDays -gt 365) {
            $policyIssues.Add("MaxPasswordAge is $([int]$passwordPolicy.MaxPasswordAge.TotalDays) days (recommend 180 or less)")
        }
        if ($passwordPolicy.PasswordHistoryCount -lt 10) {
            $policyIssues.Add("PasswordHistoryCount is $($passwordPolicy.PasswordHistoryCount) (recommend 24)")
        }
        if ($passwordPolicy.LockoutThreshold -eq 0) {
            $policyIssues.Add('Account lockout is DISABLED (LockoutThreshold = 0)')
        }
        elseif ($passwordPolicy.LockoutThreshold -gt 10) {
            $policyIssues.Add("LockoutThreshold is $($passwordPolicy.LockoutThreshold) (recommend 5 or less)")
        }
        if ($passwordPolicy.ReversibleEncryptionEnabled) {
            $policyIssues.Add('CRITICAL: Reversible encryption is ENABLED — passwords stored in plaintext-equivalent')
        }

        if ($policyIssues.Count -gt 0) {
            $severity = if ($passwordPolicy.ReversibleEncryptionEnabled -or $passwordPolicy.LockoutThreshold -eq 0) {
                'High'
            } else { 'Medium' }

            $findings.Add((New-TtcFinding `
                -FindingId 'AD-CFG-001' -Workload 'ActiveDirectory' -Component 'PasswordPolicy' `
                -CheckName 'Default Domain Password Policy' -Category 'Configuration' -Severity $severity `
                -Status 'Fail' `
                -IssueDetected "$($policyIssues.Count) password policy weakness(es) detected in the default domain policy." `
                -Explanation 'The default domain password policy governs all accounts not covered by Fine-Grained Password Policies. Weak settings enable brute force, credential stuffing, and password spray attacks at scale. Reversible encryption stores passwords in a recoverable form, equivalent to plaintext.' `
                -PossibleSolution 'Update via Group Policy: Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy. Apply stricter requirements to admin accounts using Fine-Grained Password Policies (FGPP).' `
                -Impact 'Weak password policies allow automated attacks to compromise accounts. Disabled lockout enables unlimited password spray attempts. Reversible encryption means any DC compromise exposes all user passwords.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-ADDefaultDomainPasswordPolicy' `
                -Remediation 'Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 14 -PasswordHistoryCount 24 -MaxPasswordAge "180.00:00:00" -LockoutThreshold 5 -LockoutObservationWindow "00:30:00" -LockoutDuration "00:30:00" -ComplexityEnabled $true -ReversibleEncryptionEnabled $false.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                -Notes ($policyIssues -join '; ')))
        }
        else {
            $policyNote = "MinLen=$($passwordPolicy.MinPasswordLength) | Complexity=$($passwordPolicy.ComplexityEnabled) | MaxAge=$([int]$passwordPolicy.MaxPasswordAge.TotalDays)d | History=$($passwordPolicy.PasswordHistoryCount) | Lockout=$($passwordPolicy.LockoutThreshold)"
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-CFG-001' -Workload 'ActiveDirectory' -Component 'PasswordPolicy' `
                -CheckName 'Default Domain Password Policy' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected 'Default domain password policy meets baseline security requirements.' `
                -DataSource 'Get-ADDefaultDomainPasswordPolicy' `
                -Notes $policyNote))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "AD-CFG-001: Password policy check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-CFG-001' -Workload 'ActiveDirectory' -Component 'PasswordPolicy' `
            -CheckName 'Default Domain Password Policy' -Category 'Configuration' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADDefaultDomainPasswordPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # AD-CFG-002 — Fine-Grained Password Policies
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "AD-CFG-002: Checking fine-grained password policies"

        $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -Server $domain.DNSRoot -ErrorAction SilentlyContinue
        $fgppCount = ($fgpps | Measure-Object).Count

        if ($fgppCount -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-CFG-002' -Workload 'ActiveDirectory' -Component 'PasswordPolicy' `
                -CheckName 'Fine-Grained Password Policies' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'No Fine-Grained Password Policies (FGPP) are configured.' `
                -Explanation 'Without FGPPs, privileged accounts like Domain Admins are subject to the same password policy as standard end users. A stronger policy (longer minimum length, shorter max age) should apply to admin and service accounts. FGPPs require domain functional level 2008 or higher.' `
                -PossibleSolution 'Create an FGPP targeting privileged groups. Recommended settings for admins: MinLength=20, MaxAge=90 days, History=24, Lockout=3.' `
                -Impact 'Admin account passwords may meet only end-user standards (e.g., 8-character minimum), making them significantly easier to crack.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-ADFineGrainedPasswordPolicy' `
                -Remediation 'New-ADFineGrainedPasswordPolicy -Name "AdminAccountPolicy" -Precedence 1 -MinPasswordLength 20 -PasswordHistoryCount 24 -MaxPasswordAge "90.00:00:00" -LockoutThreshold 3 -ComplexityEnabled $true -ReversibleEncryptionEnabled $false. Then: Add-ADFineGrainedPasswordPolicySubject -Identity "AdminAccountPolicy" -Subjects "Domain Admins".' `
                -AutoFixAvailable 'No' -RemediationPriority 'P3'))
        }
        else {
            $fgppDetails = ($fgpps | ForEach-Object {
                "[$($_.Name)] Precedence:$($_.Precedence) MinLen:$($_.MinPasswordLength) MaxAge:$([int]$_.MaxPasswordAge.TotalDays)d"
            }) -join '; '
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-CFG-002' -Workload 'ActiveDirectory' -Component 'PasswordPolicy' `
                -CheckName 'Fine-Grained Password Policies' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected "$fgppCount Fine-Grained Password Policy/Policies are configured." `
                -DataSource 'Get-ADFineGrainedPasswordPolicy' `
                -Notes $fgppDetails))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "AD-CFG-002: FGPP check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-CFG-002' -Workload 'ActiveDirectory' -Component 'PasswordPolicy' `
            -CheckName 'Fine-Grained Password Policies' -Category 'Configuration' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADFineGrainedPasswordPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # AD-MON-001 — Advanced Audit Policy Configuration
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "AD-MON-001: Checking audit policy via auditpol"

        $auditOutput = & auditpol /get /category:* /r 2>&1
        $auditExitCode = $LASTEXITCODE

        if ($auditExitCode -ne 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'AD-MON-001' -Workload 'ActiveDirectory' -Component 'AuditPolicy' `
                -CheckName 'Advanced Audit Policy Configuration' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'Could not retrieve audit policy via auditpol — manual review required.' `
                -Explanation 'Advanced Audit Policy configuration is critical for detecting attacks in Active Directory. Without proper auditing, Kerberos ticket anomalies, privilege escalation, LDAP enumeration, and directory changes go undetected.' `
                -PossibleSolution 'Run: auditpol /get /category:* on a domain controller and review against the CIS AD benchmark. Configure via Group Policy on the Default Domain Controllers Policy.' `
                -DataSource 'auditpol' -FrameworkMapping 'NIST-Detect' -ZeroTrustPillar 'Infrastructure' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                -Notes "auditpol exit code: $auditExitCode"))
        }
        else {
            $auditLines = $auditOutput | Where-Object { $_ -match ',' }
            $auditCsv   = $auditLines | ConvertFrom-Csv -ErrorAction SilentlyContinue

            # Key subcategories and required minimum setting
            $requiredSettings = [ordered]@{
                'Logon'                          = 'Success and Failure'
                'Logoff'                         = 'Success'
                'Account Lockout'                = 'Failure'
                'Kerberos Authentication Service' = 'Success and Failure'
                'Computer Account Management'    = 'Success and Failure'
                'Security Group Management'      = 'Success and Failure'
                'User Account Management'        = 'Success and Failure'
                'Directory Service Access'       = 'Success and Failure'
                'Directory Service Changes'      = 'Success and Failure'
                'Audit Policy Change'            = 'Success and Failure'
                'Sensitive Privilege Use'        = 'Success and Failure'
            }

            $auditIssues   = [System.Collections.Generic.List[string]]::new()
            $auditOkCount  = 0

            foreach ($reqSetting in $requiredSettings.GetEnumerator()) {
                $match = $auditCsv | Where-Object { $_.Subcategory -eq $reqSetting.Key } | Select-Object -First 1
                if (-not $match) {
                    $auditIssues.Add("$($reqSetting.Key): NOT FOUND in auditpol output")
                }
                else {
                    $current = $match.'Inclusion Setting'
                    $required = $reqSetting.Value
                    $ok = switch ($required) {
                        'Success and Failure' { $current -match 'Success' -and $current -match 'Failure' }
                        'Success'             { $current -match 'Success' }
                        'Failure'             { $current -match 'Failure' }
                        default               { $false }
                    }
                    if ($ok) { $auditOkCount++ }
                    else     { $auditIssues.Add("$($reqSetting.Key): '$current' (requires: '$required')") }
                }
            }

            if ($auditIssues.Count -gt 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'AD-MON-001' -Workload 'ActiveDirectory' -Component 'AuditPolicy' `
                    -CheckName 'Advanced Audit Policy Configuration' -Category 'Monitoring' -Severity 'Medium' `
                    -Status 'Fail' `
                    -IssueDetected "$($auditIssues.Count) audit subcategory gap(s) detected on the assessment host." `
                    -Explanation 'Gaps in the advanced audit policy leave critical AD security events unlogged. Without auditing account management, directory changes, and Kerberos activity, attacks such as DCSync, AdminSDHolder modification, and Golden Ticket usage are invisible to defenders.' `
                    -PossibleSolution 'Configure Advanced Audit Policy on all DCs via the Default Domain Controllers Policy GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration.' `
                    -Impact 'Security incidents cannot be detected or investigated. Regulatory compliance (SOC 2, ISO 27001, NIST, CIS) requirements for audit logging will not be met.' `
                    -FrameworkMapping 'NIST-Detect' -ZeroTrustPillar 'Infrastructure' `
                    -DataSource 'auditpol' `
                    -Remediation 'Apply via GPO or run on each DC: auditpol /set /subcategory:"Logon" /success:enable /failure:enable. Key subcategories: Logon, Account Logon, Account Management, Directory Service Access, Directory Service Changes, Privilege Use, Policy Change. Verify with: auditpol /get /category:*' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                    -Notes ($auditIssues -join '; ')))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'AD-MON-001' -Workload 'ActiveDirectory' -Component 'AuditPolicy' `
                    -CheckName 'Advanced Audit Policy Configuration' -Category 'Monitoring' -Severity 'Medium' `
                    -Status 'Pass' `
                    -IssueDetected "All $auditOkCount critical audit subcategories are configured correctly." `
                    -DataSource 'auditpol'))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "AD-MON-001: Audit policy check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'AD-MON-001' -Workload 'ActiveDirectory' -Component 'AuditPolicy' `
            -CheckName 'Advanced Audit Policy Configuration' -Category 'Monitoring' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'auditpol' -Notes $_.Exception.Message))
    }

    Write-TtcLog -Level Info -Message "Active Directory assessment complete — $($findings.Count) finding(s) generated"
    return $findings.ToArray()
}
