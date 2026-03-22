function Invoke-TtcEntraAssessment {
    <#
    .SYNOPSIS
        Runs the Entra ID workload assessment.
    .DESCRIPTION
        Performs a comprehensive assessment of Microsoft Entra ID (formerly Azure AD) covering
        MFA registration posture, Conditional Access coverage, Global Administrator hygiene,
        risky user status, user consent settings, external collaboration, self-service password
        reset configuration, stale guest users, and audit log accessibility.

        Requires Microsoft.Graph PowerShell SDK with the following scopes:
        - User.Read.All
        - Policy.Read.All
        - Directory.Read.All
        - IdentityRiskyUser.Read.All
        - AuditLog.Read.All
        - Organization.Read.All
        - Reports.Read.All
        - UserAuthenticationMethod.Read.All

        Connect before running:
        Connect-MgGraph -Scopes "User.Read.All","Policy.Read.All","Directory.Read.All",
            "IdentityRiskyUser.Read.All","AuditLog.Read.All","Organization.Read.All",
            "Reports.Read.All","UserAuthenticationMethod.Read.All"
    .PARAMETER StaleGuestDays
        Number of days without sign-in before a guest account is considered stale.
        Default: 90
    .PARAMETER MaxGlobalAdmins
        Maximum acceptable number of permanent Global Administrator assignments.
        Default: 5
    .EXAMPLE
        Invoke-TtcEntraAssessment
    .EXAMPLE
        Invoke-TtcEntraAssessment -StaleGuestDays 60 -MaxGlobalAdmins 4
    .OUTPUTS
        [PSCustomObject[]] Array of TakeItToCloud finding objects.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter()]
        [ValidateRange(30, 365)]
        [int]$StaleGuestDays = 90,

        [Parameter()]
        [ValidateRange(2, 20)]
        [int]$MaxGlobalAdmins = 5
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-TtcLog -Level Info -Message "Starting Entra ID assessment"

    # =========================================================================
    # Prerequisite: Verify Microsoft.Graph module and connection
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        if (-not (Get-Module -Name Microsoft.Graph.Authentication -ListAvailable) -and
            -not (Get-Module -Name Microsoft.Graph -ListAvailable)) {
            Write-TtcLog -Level Warning -Message "Microsoft.Graph module not available"
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-001' -Workload 'EntraID' -Component 'Prerequisites' `
                -CheckName 'MFA Registration Coverage' -Category 'Security' -Severity 'Critical' `
                -Status 'Error' `
                -IssueDetected 'Microsoft.Graph PowerShell SDK is not installed.' `
                -Explanation 'The Microsoft.Graph module is required to query Entra ID. Install via: Install-Module Microsoft.Graph -Scope CurrentUser.' `
                -PossibleSolution 'Install-Module Microsoft.Graph -Scope CurrentUser -Force. Then connect: Connect-MgGraph -Scopes "User.Read.All","Policy.Read.All","Directory.Read.All","IdentityRiskyUser.Read.All","AuditLog.Read.All","Organization.Read.All".' `
                -Impact 'No Entra ID assessment data can be collected.' `
                -FrameworkMapping 'NIST-Identify' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-Module' -AutoFixAvailable 'No' -RemediationPriority 'P1'))
            return $findings.ToArray()
        }

        # Verify active Graph connection
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $ctx) {
            Write-TtcLog -Level Warning -Message "No active Microsoft Graph connection"
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-001' -Workload 'EntraID' -Component 'Prerequisites' `
                -CheckName 'MFA Registration Coverage' -Category 'Security' -Severity 'Critical' `
                -Status 'Error' `
                -IssueDetected 'Not connected to Microsoft Graph. Run Connect-MgGraph before assessment.' `
                -PossibleSolution 'Connect-MgGraph -Scopes "User.Read.All","Policy.Read.All","Directory.Read.All","IdentityRiskyUser.Read.All","AuditLog.Read.All","Organization.Read.All","Reports.Read.All","UserAuthenticationMethod.Read.All"' `
                -Impact 'No Entra ID assessment data can be collected.' `
                -FrameworkMapping 'NIST-Identify' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-MgContext' -AutoFixAvailable 'No' -RemediationPriority 'P1'))
            return $findings.ToArray()
        }

        Write-TtcLog -Level Info -Message "Connected to Graph as: $($ctx.Account) | Tenant: $($ctx.TenantId)"
    }
    catch {
        Write-TtcLog -Level Error -Message "Graph prerequisite check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-SEC-001' -Workload 'EntraID' -Component 'Prerequisites' `
            -CheckName 'MFA Registration Coverage' -Category 'Security' -Severity 'Critical' `
            -Status 'Error' -IssueDetected "Graph prerequisite check failed: $($_.Exception.Message)" `
            -DataSource 'Get-MgContext' -Notes $_.Exception.Message))
        return $findings.ToArray()
    }

    # Cache organization data  -  used by multiple checks
    $org = $null
    try {
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        Write-TtcLog -Level Info -Message "Tenant: $($org.DisplayName) ($($org.Id))"
    }
    catch {
        Write-TtcLog -Level Warning -Message "Could not retrieve organization data: $_"
    }

    # =========================================================================
    # ENT-SEC-001  -  MFA Registration Coverage
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-SEC-001: Checking MFA registration coverage"

        # Get credential user registration details report (requires Reports.Read.All)
        $mfaReport = Get-MgReportAuthenticationMethodUserRegistrationDetail `
            -All -ErrorAction SilentlyContinue

        if (-not $mfaReport) {
            # Fallback: query user authentication methods directly (slower, requires UserAuthenticationMethod.Read.All)
            Write-TtcLog -Level Warning -Message "ENT-SEC-001: MFA report unavailable, attempting per-user method query"

            $allUsers = Get-MgUser -Filter "accountEnabled eq true and userType eq 'Member'" `
                -Property Id, DisplayName, UserPrincipalName, AccountEnabled `
                -All -ErrorAction Stop

            $totalUsers   = ($allUsers | Measure-Object).Count
            $mfaEnabled   = 0
            $noMfaUsers   = [System.Collections.Generic.List[string]]::new()
            $sampleSize   = [Math]::Min($totalUsers, 50)  # Sample to avoid throttling

            $sampled = $allUsers | Select-Object -First $sampleSize
            foreach ($user in $sampled) {
                try {
                    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                    $mfaMethods = $methods | Where-Object {
                        $_.AdditionalProperties.'@odata.type' -notmatch 'password'
                    }
                    if (($mfaMethods | Measure-Object).Count -gt 0) {
                        $mfaEnabled++
                    }
                    else {
                        $noMfaUsers.Add($user.UserPrincipalName)
                    }
                }
                catch {
                    Write-TtcLog -Level Warning -Message "Could not query auth methods for $($user.UserPrincipalName): $_"
                }
            }

            $mfaPercentage = if ($sampleSize -gt 0) { [int](($mfaEnabled / $sampleSize) * 100) } else { 0 }
            $notes = "Sampled $sampleSize of $totalUsers member users. MFA registered: $mfaEnabled/$sampleSize ($mfaPercentage%)"

            if ($mfaPercentage -lt 90) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'ENT-SEC-001' -Workload 'EntraID' -Component 'MFA' `
                    -CheckName 'MFA Registration Coverage' -Category 'Security' -Severity 'Critical' `
                    -Status 'Fail' `
                    -IssueDetected "Estimated MFA registration: $mfaPercentage% of sampled users (target: 90%+)." `
                    -Explanation 'MFA is the single most impactful control for preventing account compromise. Accounts without MFA registration are susceptible to password spray, phishing, and credential stuffing attacks regardless of password complexity.' `
                    -PossibleSolution 'Enable MFA registration campaign in Entra ID: Identity > Protection > Authentication Methods > Registration Campaign. Enforce MFA via Conditional Access policy requiring MFA for all users.' `
                    -Impact 'Accounts without MFA can be compromised with only a stolen or guessed password. Industry data shows MFA blocks 99.9% of automated account compromise attacks.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                    -SecureScoreMapping 'Require MFA for all users' `
                    -DataSource 'Get-MgUserAuthenticationMethod' `
                    -Remediation 'Create CA policy: All Users > All Cloud Apps > Grant: Require MFA. Enable registration campaign: Connect-MgGraph; Update-MgPolicyAuthenticationMethodPolicy. Exclude break-glass accounts and service accounts from MFA CA policy with named location or exclusion group.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                    -Notes $notes))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'ENT-SEC-001' -Workload 'EntraID' -Component 'MFA' `
                    -CheckName 'MFA Registration Coverage' -Category 'Security' -Severity 'Critical' `
                    -Status 'Pass' `
                    -IssueDetected "Estimated MFA registration: $mfaPercentage% of sampled users." `
                    -DataSource 'Get-MgUserAuthenticationMethod' -Notes $notes))
            }
        }
        else {
            $totalRegistered = ($mfaReport | Measure-Object).Count
            $mfaRegistered   = ($mfaReport | Where-Object { $_.IsMfaRegistered -eq $true } | Measure-Object).Count
            $mfaCapable      = ($mfaReport | Where-Object { $_.IsMfaCapable -eq $true } | Measure-Object).Count
            $notRegistered   = $totalRegistered - $mfaRegistered
            $pct             = if ($totalRegistered -gt 0) { [int](($mfaRegistered / $totalRegistered) * 100) } else { 0 }

            if ($pct -lt 90) {
                $severity = if ($pct -lt 60) { 'Critical' } else { 'High' }
                $findings.Add((New-TtcFinding `
                    -FindingId 'ENT-SEC-001' -Workload 'EntraID' -Component 'MFA' `
                    -CheckName 'MFA Registration Coverage' -Category 'Security' -Severity $severity `
                    -Status 'Fail' `
                    -IssueDetected "$notRegistered of $totalRegistered users ($([int](100-$pct))%) have not registered for MFA." `
                    -Explanation 'MFA is the single most effective control against account takeover. Users not registered for MFA cannot complete MFA challenges and are vulnerable to any successful password attack.' `
                    -PossibleSolution 'Enable the MFA registration campaign in Entra ID to prompt users at sign-in. Create a Conditional Access policy requiring MFA for all users targeting all cloud apps. Set a deadline for registration completion.' `
                    -Impact 'Accounts without MFA registration are fully compromisable with credentials alone. Phishing, password spray, and credential stuffing bypass all password controls without MFA.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                    -SecureScoreMapping 'Require MFA for all users' `
                    -DataSource 'Get-MgReportAuthenticationMethodUserRegistrationDetail' `
                    -Remediation 'Create CA policy: New-MgIdentityConditionalAccessPolicy targeting All Users, All Apps, Grant: Require MFA. Launch registration campaign: Identity > Protection > Authentication Methods > Registration Campaign. Use Temporary Access Pass for users who need onboarding.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                    -Notes "Total: $totalRegistered | MFA Registered: $mfaRegistered ($pct%) | MFA Capable: $mfaCapable"))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'ENT-SEC-001' -Workload 'EntraID' -Component 'MFA' `
                    -CheckName 'MFA Registration Coverage' -Category 'Security' -Severity 'Critical' `
                    -Status 'Pass' `
                    -IssueDetected "$mfaRegistered of $totalRegistered users ($pct%) have registered for MFA." `
                    -DataSource 'Get-MgReportAuthenticationMethodUserRegistrationDetail' `
                    -Notes "MFA Capable: $mfaCapable | Not Registered: $notRegistered"))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-SEC-001: MFA registration check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-SEC-001' -Workload 'EntraID' -Component 'MFA' `
            -CheckName 'MFA Registration Coverage' -Category 'Security' -Severity 'Critical' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgReportAuthenticationMethodUserRegistrationDetail' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-SEC-002  -  Legacy Authentication Blocked via Conditional Access
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-SEC-002: Checking legacy auth blocking via Conditional Access"

        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop

        # A policy blocks legacy auth if it:
        # - Targets All Users (or large groups)  -  AllUsers included
        # - Conditions: ClientAppTypes includes exchangeActiveSync or other (legacy protocols)
        # - Grant: Block

        $legacyBlockPolicies = $caPolicies | Where-Object {
            $_.State -eq 'enabled' -and
            $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -and
            $_.GrantControls.BuiltInControls -contains 'block'
        }

        # Also check for policies blocking "other" (covers legacy auth broadly)
        $broadLegacyBlock = $caPolicies | Where-Object {
            $_.State -eq 'enabled' -and
            $_.Conditions.ClientAppTypes -contains 'other' -and
            $_.GrantControls.BuiltInControls -contains 'block'
        }

        $hasLegacyBlock = ($legacyBlockPolicies | Measure-Object).Count -gt 0 -or
                          ($broadLegacyBlock | Measure-Object).Count -gt 0

        if (-not $hasLegacyBlock) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-002' -Workload 'EntraID' -Component 'ConditionalAccess' `
                -CheckName 'Legacy Authentication Blocked' -Category 'Security' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected 'No enabled Conditional Access policy found that blocks legacy authentication protocols.' `
                -Explanation 'Legacy authentication protocols (Basic Auth, SMTP AUTH, POP3, IMAP, NTLM for Exchange) do not support MFA challenges. Attackers actively target these protocols for password spray and credential stuffing because MFA policies are bypassed entirely.' `
                -PossibleSolution 'Create a CA policy: All Users > All Cloud Apps > Conditions: Client Apps = Exchange ActiveSync + Other clients > Grant: Block. Exclude break-glass and service accounts that legitimately require legacy auth using a named exclusion group.' `
                -Impact 'Users with legacy auth clients (Outlook 2010, native iOS Mail, POP/IMAP clients) can authenticate without MFA, bypassing your MFA investment entirely. Over 99% of password spray attacks target legacy auth endpoints.' `
                -FrameworkMapping 'CIS-SecureConfig' -ZeroTrustPillar 'Identity' `
                -SecureScoreMapping 'Block legacy authentication' `
                -DataSource 'Get-MgIdentityConditionalAccessPolicy' `
                -Remediation 'In Entra admin center: Protection > Conditional Access > New Policy. Name: "Block Legacy Auth". Users: All Users. Cloud apps: All cloud apps. Conditions > Client apps: Exchange ActiveSync, Other. Grant: Block access. Enable in Report-Only mode first to identify impact before enforcing.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes "Total CA policies found: $(($caPolicies | Measure-Object).Count). Enabled: $(($caPolicies | Where-Object {$_.State -eq 'enabled'} | Measure-Object).Count)"))
        }
        else {
            $policyNames = @()
            $legacyBlockPolicies | ForEach-Object { $policyNames += $_.DisplayName }
            $broadLegacyBlock    | ForEach-Object { if ($_.DisplayName -notin $policyNames) { $policyNames += $_.DisplayName } }
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-002' -Workload 'EntraID' -Component 'ConditionalAccess' `
                -CheckName 'Legacy Authentication Blocked' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected 'Conditional Access policy is in place to block legacy authentication.' `
                -DataSource 'Get-MgIdentityConditionalAccessPolicy' `
                -Notes "Blocking policies: $($policyNames -join '; ')"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-SEC-002: Legacy auth check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-SEC-002' -Workload 'EntraID' -Component 'ConditionalAccess' `
            -CheckName 'Legacy Authentication Blocked' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgIdentityConditionalAccessPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-SEC-003  -  Global Administrator Count and Hygiene
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-SEC-003: Checking Global Administrator assignments"

        $gaRole    = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction Stop
        $gaMembers = @()
        if ($gaRole) {
            $gaMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All -ErrorAction Stop
        }
        $gaCount = ($gaMembers | Measure-Object).Count
        $gaMemberNames = ($gaMembers | ForEach-Object {
            $_.AdditionalProperties['displayName']
        }) -join ', '

        if ($gaCount -lt 2) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-003' -Workload 'EntraID' -Component 'RoleAssignments' `
                -CheckName 'Global Administrator Count' -Category 'Identity' -Severity 'Critical' `
                -Status 'Fail' `
                -IssueDetected "Only $gaCount Global Administrator(s) assigned  -  minimum 2 required for break-glass redundancy." `
                -Explanation 'A single Global Admin is a single point of failure. If the account is locked, the MFA device is lost, or the account is compromised and password-reset, no one can administer the tenant. Microsoft recommends 2-4 permanent Global Admins for break-glass purposes.' `
                -PossibleSolution 'Assign at least 2 cloud-only, MFA-protected break-glass Global Admin accounts. Store credentials in a secure offline vault. Use PIM for all other admin access.' `
                -Impact 'Tenant lock-out risk if the single GA is inaccessible. No recovery path without Microsoft Support intervention (which can take days).' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                -SecureScoreMapping 'Ensure there are at most 5 global admins' `
                -DataSource 'Get-MgDirectoryRole;Get-MgDirectoryRoleMember' `
                -Remediation 'Create two cloud-only accounts (not synced from AD) as emergency break-glass GAs. Enable strong MFA (FIDO2 or certificate). Store credentials in a physical safe or offline vault. Monitor with conditional access exclusion and alerts for any sign-in activity.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes "Current GAs: $gaMemberNames"))
        }
        elseif ($gaCount -gt $MaxGlobalAdmins) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-003' -Workload 'EntraID' -Component 'RoleAssignments' `
                -CheckName 'Global Administrator Count' -Category 'Identity' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "$gaCount permanent Global Administrators found (recommended maximum: $MaxGlobalAdmins)." `
                -Explanation 'The Global Administrator role grants unrestricted control over the entire Entra ID tenant, all Microsoft 365 services, and all Azure subscriptions via Entra. Excess permanent GAs increase the blast radius of a compromised admin account and violate least-privilege principles.' `
                -PossibleSolution 'Reduce permanent GAs to 2-4 break-glass accounts. Move all other admin tasks to scoped roles (Exchange Admin, SharePoint Admin, etc.) and provision them via Entra PIM as eligible (not active) assignments.' `
                -Impact 'Each excess GA is a high-value target. A compromised GA can permanently modify security settings, create backdoor accounts, disable MFA, and exfiltrate all data.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                -SecureScoreMapping 'Ensure there are at most 5 global admins' `
                -DataSource 'Get-MgDirectoryRole;Get-MgDirectoryRoleMember' `
                -Remediation 'Review each GA: Get-MgDirectoryRoleMember -DirectoryRoleId <gaRoleId>. Remove unnecessary assignments: Remove-MgDirectoryRoleMemberByRef. Enable Entra PIM (Privileged Identity Management) to convert standing GA assignments to eligible assignments requiring activation justification and MFA.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                -Notes "Current GAs ($gaCount): $gaMemberNames"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-003' -Workload 'EntraID' -Component 'RoleAssignments' `
                -CheckName 'Global Administrator Count' -Category 'Identity' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected "$gaCount Global Administrator(s) assigned  -  within recommended range (2 to $MaxGlobalAdmins)." `
                -DataSource 'Get-MgDirectoryRole;Get-MgDirectoryRoleMember' `
                -Notes "GAs: $gaMemberNames"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-SEC-003: Global admin check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-SEC-003' -Workload 'EntraID' -Component 'RoleAssignments' `
            -CheckName 'Global Administrator Count' -Category 'Identity' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgDirectoryRole' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-SEC-004  -  Risky Users Not Remediated
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-SEC-004: Checking unresolved risky user detections"

        $riskyUsers = Get-MgRiskyUser -Filter "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'" `
            -All -ErrorAction Stop

        $atRisk      = $riskyUsers | Where-Object { $_.RiskState -eq 'atRisk' }
        $compromised = $riskyUsers | Where-Object { $_.RiskState -eq 'confirmedCompromised' }
        $atRiskCount = ($atRisk | Measure-Object).Count
        $compromisedCount = ($compromised | Measure-Object).Count
        $totalRisky = $atRiskCount + $compromisedCount

        if ($compromisedCount -gt 0) {
            $compromisedNames = ($compromised | ForEach-Object { $_.UserPrincipalName }) -join ', '
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-004' -Workload 'EntraID' -Component 'IdentityProtection' `
                -CheckName 'Risky Users Not Remediated' -Category 'Security' -Severity 'Critical' `
                -Status 'Fail' `
                -IssueDetected "$compromisedCount account(s) confirmed compromised in Entra Identity Protection  -  not yet remediated." `
                -Explanation 'Accounts marked as "Confirmed Compromised" in Identity Protection have had their compromise acknowledged. Failure to remediate means an active attacker may still have access to these accounts and all resources they can reach.' `
                -PossibleSolution 'Immediately: reset passwords, revoke all active sessions (Revoke-MgUserSignInSession), disable accounts pending investigation. Investigate sign-in and audit logs for lateral movement. Re-enable only after full forensic review.' `
                -Impact 'Active attacker access to compromised accounts and all their authorized resources. Data exfiltration, privilege escalation, and lateral movement may be ongoing.' `
                -FrameworkMapping 'NIST-Detect' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-MgRiskyUser' `
                -Remediation 'For each compromised account: Revoke-MgUserSignInSession -UserId <id>; Reset-MgUserPassword; Disable-MgUser. Investigate: Get-MgAuditLogSignIn -Filter "userId eq ''<id>''". After remediation: Invoke-MgDismissRiskyUser to clear the risk state. Enable a CA policy requiring password change for risky users.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P1' `
                -Notes "Confirmed Compromised: $compromisedNames | At Risk: $atRiskCount additional"))
        }
        elseif ($atRiskCount -gt 0) {
            $atRiskNames = ($atRisk | Select-Object -First 10 | ForEach-Object {
                "$($_.UserPrincipalName) [Risk: $($_.RiskLevel)]"
            }) -join '; '
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-004' -Workload 'EntraID' -Component 'IdentityProtection' `
                -CheckName 'Risky Users Not Remediated' -Category 'Security' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "$atRiskCount account(s) flagged as 'at risk' by Entra Identity Protection are not remediated." `
                -Explanation 'Identity Protection flags accounts based on leaked credentials, anomalous sign-in behavior, and threat intelligence. At-risk accounts may already be in the hands of attackers who have not yet acted visibly.' `
                -PossibleSolution 'Investigate each risky user''s sign-in logs. Require MFA re-registration if credentials may be compromised. Enable a CA policy that requires password change or MFA for risky users.' `
                -Impact 'At-risk accounts may be actively abused. Unresolved risk allows ongoing unauthorized access.' `
                -FrameworkMapping 'NIST-Detect' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-MgRiskyUser' `
                -Remediation 'Create a CA policy: User risk = High/Medium > Grant: Require password change. Review each user in Identity Protection > Risky Users. Use: Get-MgRiskyUser | ForEach-Object { Revoke-MgUserSignInSession -UserId $_.Id } for high-risk users. If false positive: Invoke-MgDismissRiskyUser.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                -Notes "At Risk users (first 10): $atRiskNames"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-004' -Workload 'EntraID' -Component 'IdentityProtection' `
                -CheckName 'Risky Users Not Remediated' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected 'No unresolved risky user detections found in Entra Identity Protection.' `
                -DataSource 'Get-MgRiskyUser'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-SEC-004: Risky user check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-SEC-004' -Workload 'EntraID' -Component 'IdentityProtection' `
            -CheckName 'Risky Users Not Remediated' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete (Identity Protection P2 license may be required): $($_.Exception.Message)" `
            -DataSource 'Get-MgRiskyUser' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-CFG-001  -  User Consent Policy (Application Consent)
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-CFG-001: Checking user consent policy for applications"

        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop

        # permissionGrantPoliciesAssigned: if contains 'ManagePermissionGrantsForSelf.*' users can self-consent
        $selfConsentPolicies = $authPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned |
            Where-Object { $_ -like 'ManagePermissionGrantsForSelf*' }

        $allowsUnrestrictedConsent = $selfConsentPolicies | Where-Object { $_ -eq 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy' }
        $allowsLimitedConsent      = $selfConsentPolicies | Where-Object { $_ -like '*low*' -or $_ -like '*verified*' }

        if ($allowsUnrestrictedConsent) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-CFG-001' -Workload 'EntraID' -Component 'AppConsent' `
                -CheckName 'User Application Consent Policy' -Category 'Governance' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected 'Users can consent to any application requesting permissions without admin approval (legacy unrestricted consent).' `
                -Explanation 'Unrestricted user consent enables OAuth phishing attacks. Attackers register malicious applications and trick users into granting them access to mailboxes, Teams data, and SharePoint. This is the primary vector for "consent phishing" attacks targeting Microsoft 365.' `
                -PossibleSolution 'Restrict user consent to verified publishers with low-risk permissions only, or disable user consent entirely and require admin approval for all application consent requests.' `
                -Impact 'Users can inadvertently grant malicious OAuth applications persistent access to their email, files, and calendar without any admin visibility or control.' `
                -FrameworkMapping 'ISO27001-A.9' -ZeroTrustPillar 'Applications' `
                -SecureScoreMapping 'Do not allow users to grant consent to unmanaged applications' `
                -DataSource 'Get-MgPolicyAuthorizationPolicy' `
                -Remediation 'Entra admin center: Enterprise Applications > Consent and Permissions > User consent settings: select "Allow user consent for apps from verified publishers, for selected permissions". Or: Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{PermissionGrantPoliciesAssigned = @("ManagePermissionGrantsForSelf.microsoft-user-default-low")}.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                -Notes "Consent policies assigned: $(($selfConsentPolicies -join ', '))"))
        }
        elseif ($allowsLimitedConsent) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-CFG-001' -Workload 'EntraID' -Component 'AppConsent' `
                -CheckName 'User Application Consent Policy' -Category 'Governance' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'User consent is limited to verified publishers with low-risk permissions  -  review to confirm alignment with policy.' `
                -Explanation 'Limiting consent to verified publishers and low-risk permissions reduces OAuth phishing risk. However, "low-risk" is a relative Microsoft designation and may still permit access to user profile and email read operations.' `
                -PossibleSolution 'Consider requiring admin approval for all consent requests (disable user consent entirely) if the organization handles sensitive data. Implement admin consent workflow so users can request approval.' `
                -DataSource 'Get-MgPolicyAuthorizationPolicy' -FrameworkMapping 'ISO27001-A.9' -ZeroTrustPillar 'Applications' `
                -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                -Notes "Consent policy: $($selfConsentPolicies -join ', ')"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-CFG-001' -Workload 'EntraID' -Component 'AppConsent' `
                -CheckName 'User Application Consent Policy' -Category 'Governance' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected 'User consent is disabled  -  admin approval is required for all application permissions.' `
                -DataSource 'Get-MgPolicyAuthorizationPolicy' `
                -Notes "Consent policies assigned: $(($authPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned -join ', '))"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-CFG-001: Consent policy check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-CFG-001' -Workload 'EntraID' -Component 'AppConsent' `
            -CheckName 'User Application Consent Policy' -Category 'Governance' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgPolicyAuthorizationPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-CFG-002  -  External Collaboration Settings (Guest Invitations)
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-CFG-002: Checking external collaboration / guest invitation settings"

        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop

        # allowInvitesFrom: adminsAndGuestInviters | adminsAndMembersAndGuestInviters | everyone | none
        $invitesSetting = $authPolicy.AllowInvitesFrom

        $inviteIssue = switch ($invitesSetting) {
            'everyone'                        { 'Any user in the tenant (including guests) can invite external guests.' }
            'adminsAndMembersAndGuestInviters' { 'All member users and guests with the Guest Inviter role can send invitations.' }
            default                            { '' }
        }

        if ($inviteIssue) {
            $severity = if ($invitesSetting -eq 'everyone') { 'High' } else { 'Medium' }
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-CFG-002' -Workload 'EntraID' -Component 'GuestAccess' `
                -CheckName 'External Collaboration Settings' -Category 'Governance' -Severity $severity `
                -Status 'Fail' `
                -IssueDetected $inviteIssue `
                -Explanation 'Overly permissive guest invitation settings allow uncontrolled external sharing. Any user (or even guests) can introduce new external identities into the tenant, bypassing IT governance and creating data exfiltration paths.' `
                -PossibleSolution 'Restrict guest invitations to admins and designated Guest Inviters only. Set AllowInvitesFrom to "adminsAndGuestInviters". Require admin approval for all guest access requests.' `
                -Impact 'Uncontrolled guest accounts can access SharePoint sites, Teams channels, and other shared resources. External identities introduced by non-IT users bypass access reviews and governance controls.' `
                -FrameworkMapping 'ISO27001-A.9' -ZeroTrustPillar 'Data' `
                -DataSource 'Get-MgPolicyAuthorizationPolicy' `
                -Remediation 'Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom "adminsAndGuestInviters". In Entra admin center: External Identities > External collaboration settings > Guest invite settings: "Only users assigned to specific admin roles can invite guest users".' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P3' `
                -Notes "Current AllowInvitesFrom: $invitesSetting"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-CFG-002' -Workload 'EntraID' -Component 'GuestAccess' `
                -CheckName 'External Collaboration Settings' -Category 'Governance' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected 'Guest invitation is restricted to administrators and designated Guest Inviters.' `
                -DataSource 'Get-MgPolicyAuthorizationPolicy' `
                -Notes "AllowInvitesFrom: $invitesSetting"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-CFG-002: Guest collaboration check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-CFG-002' -Workload 'EntraID' -Component 'GuestAccess' `
            -CheckName 'External Collaboration Settings' -Category 'Governance' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgPolicyAuthorizationPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-SEC-005  -  Conditional Access Baseline Coverage
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-SEC-005: Checking Conditional Access policy coverage"

        # Re-use $caPolicies if already fetched, otherwise fetch now
        if (-not (Get-Variable -Name caPolicies -Scope Local -ErrorAction SilentlyContinue)) {
            $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        }

        $enabledPolicies = $caPolicies | Where-Object { $_.State -eq 'enabled' }
        $reportOnlyPolicies = $caPolicies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }
        $enabledCount = ($enabledPolicies | Measure-Object).Count

        # Check for Security Defaults as fallback
        $secDefaults = Get-MgPolicyIdentitySecurityDefaultsEnforcementPolicy -ErrorAction SilentlyContinue
        $secDefaultsEnabled = $secDefaults -and $secDefaults.IsEnabled

        if ($enabledCount -eq 0 -and -not $secDefaultsEnabled) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-005' -Workload 'EntraID' -Component 'ConditionalAccess' `
                -CheckName 'Conditional Access Baseline Coverage' -Category 'Security' -Severity 'Critical' `
                -Status 'Fail' `
                -IssueDetected 'No Conditional Access policies are enabled and Security Defaults is disabled  -  no baseline MFA enforcement.' `
                -Explanation 'Without CA policies or Security Defaults, there is no mechanism to enforce MFA, block risky sign-ins, or apply access controls. The tenant is relying entirely on password authentication, which is highly susceptible to phishing and credential attacks.' `
                -PossibleSolution 'Immediately enable Security Defaults for basic MFA enforcement (if not using CA policies), or deploy a set of Conditional Access baseline policies: require MFA for all users, block legacy auth, require MFA for admin roles.' `
                -Impact 'All users can authenticate with only a password. No protection against phishing, password spray, or credential stuffing exists at the authentication layer.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -SecureScoreMapping 'Enable Conditional Access policies' `
                -DataSource 'Get-MgIdentityConditionalAccessPolicy;Get-MgPolicyIdentitySecurityDefaultsEnforcementPolicy' `
                -Remediation 'Option 1: Enable Security Defaults: Update-MgPolicyIdentitySecurityDefaultsEnforcementPolicy -IsEnabled $true. Option 2: Deploy CA baseline  -  Require MFA for all users, Block legacy auth, Require MFA for admins, Block risky sign-ins. Use named locations and exclusion groups for break-glass accounts.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes "CA Policies: $(($caPolicies | Measure-Object).Count) total, $enabledCount enabled, $(($reportOnlyPolicies | Measure-Object).Count) report-only. Security Defaults: Disabled"))
        }
        elseif ($enabledCount -eq 0 -and $secDefaultsEnabled) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-005' -Workload 'EntraID' -Component 'ConditionalAccess' `
                -CheckName 'Conditional Access Baseline Coverage' -Category 'Security' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'No Conditional Access policies enabled  -  Security Defaults provides basic protection but lacks granular control.' `
                -Explanation 'Security Defaults provide a basic MFA baseline but cannot accommodate exclusions, named locations, risk-based controls, or device compliance requirements. Organizations with more complex needs should migrate to Conditional Access policies.' `
                -PossibleSolution 'Migrate to Conditional Access policies to gain control over exclusions (break-glass, service accounts), named locations, device compliance, and risk-based sign-in policies. Disable Security Defaults after CA policies are in place.' `
                -Impact 'Security Defaults may enforce MFA in ways that block service accounts or legitimate automation. No risk-based or device compliance controls are available.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-MgIdentityConditionalAccessPolicy;Get-MgPolicyIdentitySecurityDefaultsEnforcementPolicy' `
                -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                -Notes 'Security Defaults: Enabled. No active CA policies.'))
        }
        else {
            $policyNames = ($enabledPolicies | Select-Object -ExpandProperty DisplayName) -join '; '
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-005' -Workload 'EntraID' -Component 'ConditionalAccess' `
                -CheckName 'Conditional Access Baseline Coverage' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected "$enabledCount Conditional Access policy/policies are enabled." `
                -DataSource 'Get-MgIdentityConditionalAccessPolicy' `
                -Notes "Enabled policies: $policyNames"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-SEC-005: CA coverage check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-SEC-005' -Workload 'EntraID' -Component 'ConditionalAccess' `
            -CheckName 'Conditional Access Baseline Coverage' -Category 'Security' -Severity 'Critical' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgIdentityConditionalAccessPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-CFG-003  -  Self-Service Password Reset Configuration
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-CFG-003: Checking SSPR configuration"

        # SSPR policy: Get-MgPolicySelfServiceSignupPolicy (for registered domain validation)
        # Actual SSPR config is in the legacy MSOnline API or beta Graph endpoint
        $sspr = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/beta/policies/passwordResetPolicies' `
            -ErrorAction SilentlyContinue

        $ssprEnabled = $sspr -and $sspr.enablementType -ne 'none'

        if (-not $ssprEnabled) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-CFG-003' -Workload 'EntraID' -Component 'SSPR' `
                -CheckName 'Self-Service Password Reset Configuration' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'Self-Service Password Reset (SSPR) may not be enabled for all users.' `
                -Explanation 'Without SSPR, users who forget their password must contact the helpdesk, creating operational overhead and potential social engineering attack surfaces. SSPR reduces helpdesk load while giving users a secure self-service option.' `
                -PossibleSolution 'Enable SSPR for all users: Entra admin center > Protection > Password reset > Properties > Self service password reset enabled: All. Require registration at next sign-in and configure at least 2 authentication methods.' `
                -Impact 'Helpdesk password reset requests create social engineering opportunities. Users may be locked out of accounts unnecessarily, impacting productivity.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -DataSource 'Graph beta: policies/passwordResetPolicies' `
                -Remediation 'Enable in Entra admin center: Protection > Password reset > Properties > Enabled: All. Set number of methods required to reset: 2. Configure authentication methods: mobile app, email, mobile phone, security questions. Set registration: require when sign-in.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P4' `
                -Notes "SSPR enablementType: $($sspr.enablementType)"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-CFG-003' -Workload 'EntraID' -Component 'SSPR' `
                -CheckName 'Self-Service Password Reset Configuration' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected 'Self-Service Password Reset is enabled.' `
                -DataSource 'Graph beta: policies/passwordResetPolicies' `
                -Notes "SSPR enablementType: $($sspr.enablementType)"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-CFG-003: SSPR check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-CFG-003' -Workload 'EntraID' -Component 'SSPR' `
            -CheckName 'Self-Service Password Reset Configuration' -Category 'Configuration' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "SSPR check could not complete (beta API or permissions): $($_.Exception.Message)" `
            -DataSource 'Graph beta: policies/passwordResetPolicies' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-IDN-001  -  Stale Guest User Accounts
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-IDN-001: Checking stale guest user accounts"

        $staleGuestThreshold = (Get-Date).AddDays(-$StaleGuestDays).ToString('yyyy-MM-ddTHH:mm:ssZ')

        $allGuests = Get-MgUser `
            -Filter "userType eq 'Guest' and accountEnabled eq true" `
            -Property Id, DisplayName, UserPrincipalName, SignInActivity, CreatedDateTime `
            -All -ErrorAction Stop

        $totalGuests = ($allGuests | Measure-Object).Count
        $staleGuests = $allGuests | Where-Object {
            $lastSignIn = $_.SignInActivity.LastSignInDateTime
            -not $lastSignIn -or $lastSignIn -lt (Get-Date).AddDays(-$StaleGuestDays)
        }
        $staleCount = ($staleGuests | Measure-Object).Count

        if ($staleCount -gt 0) {
            $staleExamples = ($staleGuests | Select-Object -First 15 | ForEach-Object {
                $last = if ($_.SignInActivity.LastSignInDateTime) {
                    $_.SignInActivity.LastSignInDateTime.ToString('yyyy-MM-dd')
                } else { 'NEVER' }
                "$($_.UserPrincipalName) [Last: $last]"
            }) -join '; '

            $severity = if ($staleCount -gt 50) { 'High' } else { 'Medium' }
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-IDN-001' -Workload 'EntraID' -Component 'GuestAccess' `
                -CheckName 'Stale Guest User Accounts' -Category 'Identity' -Severity $severity `
                -Status 'Fail' `
                -IssueDetected "$staleCount of $totalGuests guest account(s) have not signed in within $StaleGuestDays days." `
                -Explanation 'Stale guest accounts represent former contractors, project partners, or conference invitees who no longer need access. These dormant accounts remain valid and can be used if the external identity provider is compromised or the guest account is taken over.' `
                -PossibleSolution 'Implement quarterly access reviews for guest accounts using Entra ID Access Reviews. Remove guests who have not signed in within 90 days and have no active resource access. Deploy a guest lifecycle management policy.' `
                -Impact 'Former guests retain access to Teams channels, SharePoint sites, and shared resources. A compromised guest identity provider account can be used to log in as a stale guest.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-MgUser' `
                -Remediation 'Create Entra Access Reviews targeting guest users: Identity Governance > Access Reviews > New. Set recurrence quarterly. For immediate cleanup: Get-MgUser -Filter "userType eq ''Guest''" | Where-Object {$_.SignInActivity.LastSignInDateTime -lt (Get-Date).AddDays(-90)} | ForEach-Object { Remove-MgUser -UserId $_.Id }. Verify no active resource assignments first.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P3' `
                -Notes "Stale (first 15): $staleExamples"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-IDN-001' -Workload 'EntraID' -Component 'GuestAccess' `
                -CheckName 'Stale Guest User Accounts' -Category 'Identity' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected "All $totalGuests active guest account(s) have signed in within $StaleGuestDays days." `
                -DataSource 'Get-MgUser'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-IDN-001: Stale guest check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-IDN-001' -Workload 'EntraID' -Component 'GuestAccess' `
            -CheckName 'Stale Guest User Accounts' -Category 'Identity' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete (SignInActivity requires AuditLog.Read.All): $($_.Exception.Message)" `
            -DataSource 'Get-MgUser' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-MON-001  -  Audit and Sign-in Log Accessibility
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-MON-001: Checking audit log accessibility"

        # Try to pull the most recent audit log entry to confirm logs are flowing
        $recentAuditLogs = Get-MgAuditLogDirectoryAudit -Top 1 -ErrorAction Stop
        $recentSignIns   = Get-MgAuditLogSignIn -Top 1 -ErrorAction SilentlyContinue

        if ($recentAuditLogs) {
            $lastAuditDate  = $recentAuditLogs.ActivityDateTime
            $lastSignInDate = if ($recentSignIns) { $recentSignIns.CreatedDateTime } else { 'N/A' }

            # Check if latest audit is suspiciously old (>24 hours could indicate log export issue)
            $auditAge = if ($lastAuditDate) { [int]((Get-Date) - $lastAuditDate).TotalHours } else { 999 }

            if ($auditAge -gt 48) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'ENT-MON-001' -Workload 'EntraID' -Component 'AuditLogs' `
                    -CheckName 'Entra ID Audit and Sign-in Log Accessibility' -Category 'Monitoring' -Severity 'Medium' `
                    -Status 'Warning' `
                    -IssueDetected "Most recent audit log entry is $auditAge hours old  -  verify log pipeline is functioning." `
                    -Explanation 'Entra ID audit logs are retained for 30 days (P1) or 90 days (P2). If logs appear stale, the log export pipeline (Log Analytics, Sentinel, or SIEM) may be broken. Real-time alerting depends on live log ingestion.' `
                    -PossibleSolution 'Verify Diagnostic Settings: Entra admin center > Monitoring > Diagnostic Settings. Confirm logs are flowing to Log Analytics or SIEM. Check for export quota issues or Service Principal permission changes.' `
                    -DataSource 'Get-MgAuditLogDirectoryAudit' -FrameworkMapping 'CIS-ContinuousMonitoring' -ZeroTrustPillar 'Infrastructure' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                    -Notes "Last audit entry: $lastAuditDate ($auditAge hours ago) | Last sign-in entry: $lastSignInDate"))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'ENT-MON-001' -Workload 'EntraID' -Component 'AuditLogs' `
                    -CheckName 'Entra ID Audit and Sign-in Log Accessibility' -Category 'Monitoring' -Severity 'Medium' `
                    -Status 'Pass' `
                    -IssueDetected 'Entra ID audit logs are accessible and current.' `
                    -DataSource 'Get-MgAuditLogDirectoryAudit' `
                    -Notes "Last audit entry: $lastAuditDate | Last sign-in entry: $lastSignInDate"))
            }
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-MON-001' -Workload 'EntraID' -Component 'AuditLogs' `
                -CheckName 'Entra ID Audit and Sign-in Log Accessibility' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'No audit log entries returned  -  logs may be empty or permissions insufficient.' `
                -Explanation 'Entra audit logs should always contain recent events. If no entries are returned, the account running the assessment may lack AuditLog.Read.All permission, or logs may not be configured.' `
                -PossibleSolution 'Ensure the assessment account has AuditLog.Read.All permission. Verify Diagnostic Settings in the Entra portal. A Purview license or P1 is required for audit log retention beyond 30 days.' `
                -DataSource 'Get-MgAuditLogDirectoryAudit' -FrameworkMapping 'CIS-ContinuousMonitoring' -ZeroTrustPillar 'Infrastructure' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-MON-001: Audit log check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-MON-001' -Workload 'EntraID' -Component 'AuditLogs' `
            -CheckName 'Entra ID Audit and Sign-in Log Accessibility' -Category 'Monitoring' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete (requires AuditLog.Read.All): $($_.Exception.Message)" `
            -DataSource 'Get-MgAuditLogDirectoryAudit' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-SEC-006  -  Workload Identity Credential Expiry
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-SEC-006: Checking workload identity credential expiry"

        $apps = Invoke-TtcMgGraphRequest -Uri '/v1.0/applications?$select=id,displayName,passwordCredentials,keyCredentials&$top=999' -ErrorAction Stop
        $appList = if ($apps.value) { $apps.value } else { @() }

        $nowUtc    = [DateTime]::UtcNow
        $warnDays  = 30
        $expiredApps  = [System.Collections.Generic.List[string]]::new()
        $expiringApps = [System.Collections.Generic.List[string]]::new()

        foreach ($app in $appList) {
            $allCreds = @()
            if ($app.passwordCredentials) { $allCreds += $app.passwordCredentials }
            if ($app.keyCredentials)      { $allCreds += $app.keyCredentials }

            foreach ($cred in $allCreds) {
                $expiry = [DateTime]$cred.endDateTime
                if ($expiry -lt $nowUtc) {
                    $expiredApps.Add("$($app.displayName) [expired: $($expiry.ToString('yyyy-MM-dd'))]")
                }
                elseif ($expiry -lt $nowUtc.AddDays($warnDays)) {
                    $expiringApps.Add("$($app.displayName) [expires: $($expiry.ToString('yyyy-MM-dd'))]")
                }
            }
        }

        if ($expiredApps.Count -gt 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-006' -Workload 'EntraID' -Component 'AppRegistrations' `
                -CheckName 'Workload Identity Credential Expiry' -Category 'Security' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "$($expiredApps.Count) application registration(s) have expired credentials. $($expiringApps.Count) expire within $warnDays days." `
                -Explanation 'Expired app credentials cause authentication failures and may force emergency changes. Applications using expired credentials may fall back to weaker authentication or fail entirely. Rotation gaps create windows where old credentials remain valid if not revoked.' `
                -PossibleSolution 'Rotate expired credentials immediately. Implement automated credential rotation using managed identities where possible. Configure alerts 60 days before expiry via Azure Monitor or Entra workload identity insights.' `
                -Impact 'Service outages, broken integrations, and emergency credential rotation under pressure - increasing risk of misconfiguration.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Applications' `
                -MitreAttack 'T1528' `
                -DataSource 'Graph: /v1.0/applications' `
                -Remediation 'For each expired app: Get-MgApplication -ApplicationId <id>; Remove-MgApplicationPassword; Add-MgApplicationPassword. Prefer managed identities (no credential management) for Azure workloads. Use federated identity credentials for GitHub Actions and other CI/CD.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                -Notes "Expired: $($expiredApps -join ' | ') -- Expiring soon: $($expiringApps -join ' | ')"))
        }
        elseif ($expiringApps.Count -gt 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-006' -Workload 'EntraID' -Component 'AppRegistrations' `
                -CheckName 'Workload Identity Credential Expiry' -Category 'Security' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected "$($expiringApps.Count) application credential(s) expire within $warnDays days." `
                -PossibleSolution 'Rotate credentials before expiry. Consider migrating to managed identities to eliminate credential management overhead.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Applications' `
                -MitreAttack 'T1528' `
                -DataSource 'Graph: /v1.0/applications' -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                -Notes "Expiring soon: $($expiringApps -join ' | ')"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-006' -Workload 'EntraID' -Component 'AppRegistrations' `
                -CheckName 'Workload Identity Credential Expiry' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected "No expired or near-expiry application credentials found across $($appList.Count) app registration(s)." `
                -DataSource 'Graph: /v1.0/applications'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-SEC-006: App credential expiry check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-SEC-006' -Workload 'EntraID' -Component 'AppRegistrations' `
            -CheckName 'Workload Identity Credential Expiry' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/applications' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-SEC-007  -  Over-Privileged Enterprise Applications
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-SEC-007: Checking enterprise app permissions"

        # Dangerous application (not delegated) permissions that allow broad data access
        $dangerousPermissions = @(
            'RoleManagement.ReadWrite.Directory',  # Can grant admin roles
            'Directory.ReadWrite.All',             # Full directory write
            'AppRoleAssignment.ReadWrite.All',     # Can assign any app role
            'Group.ReadWrite.All',                 # All groups write
            'Mail.ReadWrite',                      # Read/write all mailboxes
            'Mail.Read',                           # Read all mailboxes (app permission)
            'User.ReadWrite.All'                   # Full user management
        )

        $spns = Invoke-TtcMgGraphRequest -Uri '/v1.0/servicePrincipals?$select=id,displayName,appId&$top=999' -ErrorAction Stop
        $spnList = if ($spns.value) { $spns.value } else { @() }

        $riskySpns = [System.Collections.Generic.List[string]]::new()

        foreach ($spn in $spnList) {
            try {
                $grants = Invoke-TtcMgGraphRequest -Uri "/v1.0/servicePrincipals/$($spn.id)/appRoleAssignments" -ErrorAction SilentlyContinue
                $grantList = if ($grants.value) { $grants.value } else { @() }

                foreach ($grant in $grantList) {
                    # appRoleAssignment has roleId - we need to check resource service principal's appRoles
                    # For Microsoft Graph (00000003-0000-0000-c000-000000000000), check permission value
                    if ($grant.resourceDisplayName -eq 'Microsoft Graph') {
                        $resourceSpn = Invoke-TtcMgGraphRequest -Uri "/v1.0/servicePrincipals/$($grant.resourceId)?`$select=appRoles" -ErrorAction SilentlyContinue
                        if ($resourceSpn.appRoles) {
                            $matchingRole = $resourceSpn.appRoles | Where-Object { $_.id -eq $grant.appRoleId }
                            if ($matchingRole -and $matchingRole.value -in $dangerousPermissions) {
                                $riskySpns.Add("$($spn.displayName): $($matchingRole.value)")
                            }
                        }
                    }
                }
            }
            catch { } # Skip individual SPNs that fail
        }

        if ($riskySpns.Count -gt 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-007' -Workload 'EntraID' -Component 'AppPermissions' `
                -CheckName 'Over-Privileged Enterprise Applications' -Category 'Security' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "$($riskySpns.Count) enterprise application(s) have high-privilege Microsoft Graph application permissions." `
                -Explanation 'Application permissions (not delegated) allow background services to access tenant data without a signed-in user. High-privilege app permissions like Mail.Read or Directory.ReadWrite.All can be abused by a compromised service principal to exfiltrate all mailboxes or manipulate directory objects.' `
                -PossibleSolution 'Review each application and verify the permission is genuinely required. Remove unused permissions. Prefer delegated permissions where a human sign-in is involved. Implement Conditional Access for workload identities (requires Entra ID P2).' `
                -Impact 'A compromised service principal with Mail.Read.All can silently read every mailbox in the tenant. Directory.ReadWrite.All allows creating backdoor accounts.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Applications' `
                -MitreAttack 'T1098.002' `
                -DataSource 'Graph: /v1.0/servicePrincipals' `
                -Remediation 'For each risky app: Entra admin center > Enterprise Applications > [App] > Permissions > Review. Remove: Remove-MgServicePrincipalAppRoleAssignment. Implement app permission review quarterly. Use Microsoft Entra Permissions Management for continuous monitoring.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                -Notes "Risky apps: $($riskySpns -join ' | ')"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-007' -Workload 'EntraID' -Component 'AppPermissions' `
                -CheckName 'Over-Privileged Enterprise Applications' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected "No enterprise applications found with high-privilege Graph application permissions." `
                -DataSource 'Graph: /v1.0/servicePrincipals' `
                -Notes "Checked $($spnList.Count) service principal(s)"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-SEC-007: App permissions check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-SEC-007' -Workload 'EntraID' -Component 'AppPermissions' `
            -CheckName 'Over-Privileged Enterprise Applications' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/servicePrincipals' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-SEC-008  -  Privileged Identity Management (PIM) Adoption
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-SEC-008: Checking PIM adoption for privileged roles"

        $eligibleSchedules = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/roleManagement/directory/roleEligibilitySchedules?$select=id,principalId,roleDefinitionId' `
            -ErrorAction SilentlyContinue

        $eligibleCount = 0
        if ($eligibleSchedules -and $eligibleSchedules.value) {
            $eligibleCount = ($eligibleSchedules.value | Measure-Object).Count
        }

        # Also check active role assignments (standing access)
        $activeAssignments = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId' `
            -ErrorAction SilentlyContinue
        $activeCount = 0
        if ($activeAssignments -and $activeAssignments.value) {
            $activeCount = ($activeAssignments.value | Measure-Object).Count
        }

        if ($eligibleCount -eq 0 -and $activeCount -gt 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-008' -Workload 'EntraID' -Component 'PIM' `
                -CheckName 'Privileged Identity Management Adoption' -Category 'Identity' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "No PIM eligible role assignments found. All $activeCount role assignment(s) are standing (always-on) privileged access." `
                -Explanation 'Without PIM, all role assignments are permanent (standing access). Users with admin roles are high-value targets 24/7. PIM enforces just-in-time access with approval workflows, MFA step-up, and time-limited activation - dramatically reducing the attack surface for privileged accounts.' `
                -PossibleSolution 'Enable Entra ID PIM (requires P2 license). Convert standing role assignments to PIM eligible assignments. Configure activation policies: require MFA, justification, and optionally approval. Start with Global Administrator and Privileged Role Administrator roles.' `
                -Impact 'Admin accounts with permanent standing access are prime targets. A compromised admin account immediately provides full privileges with no time limit.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                -SecureScoreMapping 'Use limited and just-in-time admin roles' `
                -MitreAttack 'T1078.004' `
                -DataSource 'Graph: /v1.0/roleManagement/directory/roleEligibilitySchedules' `
                -Remediation 'Enable PIM: Entra admin center > Identity Governance > Privileged Identity Management. For each admin role: PIM > Azure AD Roles > Roles > [Role] > Assignments > Add Assignments > Assignment type: Eligible. Set activation duration (e.g., 4 hours). Require MFA and justification at activation.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                -Notes "Standing assignments: $activeCount | PIM eligible assignments: 0"))
        }
        elseif ($eligibleCount -gt 0) {
            $pimRatio = if (($eligibleCount + $activeCount) -gt 0) {
                [int](($eligibleCount / ($eligibleCount + $activeCount)) * 100)
            } else { 0 }

            $status = if ($pimRatio -ge 70) { 'Pass' } else { 'Warning' }
            $severity = if ($pimRatio -lt 50) { 'Medium' } else { 'Low' }
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-008' -Workload 'EntraID' -Component 'PIM' `
                -CheckName 'Privileged Identity Management Adoption' -Category 'Identity' -Severity $severity `
                -Status $status `
                -IssueDetected "PIM is in use: $eligibleCount eligible vs $activeCount standing role assignment(s) ($pimRatio% PIM-managed)." `
                -DataSource 'Graph: /v1.0/roleManagement/directory/roleEligibilitySchedules' `
                -Notes "Eligible (PIM): $eligibleCount | Standing (permanent): $activeCount | PIM adoption: $pimRatio%"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-008' -Workload 'EntraID' -Component 'PIM' `
                -CheckName 'Privileged Identity Management Adoption' -Category 'Identity' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'PIM eligibility data could not be retrieved - P2 license or RoleManagement.Read.All permission may be required.' `
                -DataSource 'Graph: /v1.0/roleManagement/directory/roleEligibilitySchedules' `
                -AutoFixAvailable 'No' -RemediationPriority 'P3'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-SEC-008: PIM check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-SEC-008' -Workload 'EntraID' -Component 'PIM' `
            -CheckName 'Privileged Identity Management Adoption' -Category 'Identity' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete (requires Entra ID P2 + RoleManagement.Read.All): $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/roleManagement/directory/roleEligibilitySchedules' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-SEC-009  -  FIDO2 / Passwordless Authentication Enablement
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-SEC-009: Checking FIDO2/passwordless authentication method policy"

        $authMethodsPolicy = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/policies/authenticationMethodsPolicy' -ErrorAction Stop

        $fido2Policy = $null
        $msAuthenticatorPolicy = $null
        if ($authMethodsPolicy.authenticationMethodConfigurations) {
            $fido2Policy = $authMethodsPolicy.authenticationMethodConfigurations |
                Where-Object { $_.id -eq 'Fido2' }
            $msAuthenticatorPolicy = $authMethodsPolicy.authenticationMethodConfigurations |
                Where-Object { $_.id -eq 'MicrosoftAuthenticator' }
        }

        $fido2Enabled      = $fido2Policy -and $fido2Policy.state -eq 'enabled'
        $authenticatorEnabled = $msAuthenticatorPolicy -and $msAuthenticatorPolicy.state -eq 'enabled'

        $passwordlessEnabled = $fido2Enabled -or $authenticatorEnabled

        if (-not $passwordlessEnabled) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-009' -Workload 'EntraID' -Component 'AuthenticationMethods' `
                -CheckName 'FIDO2/Passwordless Authentication Enablement' -Category 'Security' -Severity 'Medium' `
                -Status 'Fail' `
                -IssueDetected 'Neither FIDO2 security keys nor Microsoft Authenticator passwordless phone sign-in are enabled.' `
                -Explanation 'Passwordless authentication eliminates the password as an attack vector entirely. FIDO2 security keys are phishing-resistant - even a perfect phishing site cannot capture a FIDO2 credential. Password-based MFA still exposes users to real-time phishing (AiTM attacks) that proxy MFA codes.' `
                -PossibleSolution 'Enable FIDO2 authentication: Entra admin center > Protection > Authentication Methods > FIDO2 Security Key > Enable. Enable Microsoft Authenticator passwordless: Authentication Methods > Microsoft Authenticator > Enable and configure. Create a pilot group and gradually expand adoption.' `
                -Impact 'Password-based authentication (even with MFA) is vulnerable to adversary-in-the-middle phishing kits (Evilginx, Modlishka) that relay credentials and session tokens in real-time. FIDO2 is immune to this attack class.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -SecureScoreMapping 'Enable passwordless authentication methods' `
                -DataSource 'Graph: /v1.0/policies/authenticationMethodsPolicy' `
                -Remediation 'FIDO2: Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId Fido2 -State enabled. Authenticator passwordless: Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId MicrosoftAuthenticator -State enabled. Deploy to admins first as highest-value targets.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                -Notes "FIDO2: $($fido2Policy.state) | Microsoft Authenticator: $($msAuthenticatorPolicy.state)"))
        }
        else {
            $enabledMethods = @()
            if ($fido2Enabled)        { $enabledMethods += 'FIDO2' }
            if ($authenticatorEnabled) { $enabledMethods += 'Microsoft Authenticator Passwordless' }
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-009' -Workload 'EntraID' -Component 'AuthenticationMethods' `
                -CheckName 'FIDO2/Passwordless Authentication Enablement' -Category 'Security' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected "Passwordless authentication method(s) enabled: $($enabledMethods -join ', ')." `
                -DataSource 'Graph: /v1.0/policies/authenticationMethodsPolicy'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-SEC-009: FIDO2/passwordless check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-SEC-009' -Workload 'EntraID' -Component 'AuthenticationMethods' `
            -CheckName 'FIDO2/Passwordless Authentication Enablement' -Category 'Security' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/policies/authenticationMethodsPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-CFG-004  -  Cross-Tenant Access Settings
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-CFG-004: Checking cross-tenant access settings"

        $crossTenantDefault = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/policies/crossTenantAccessPolicy/default' -ErrorAction Stop

        $inboundAllowAll  = $crossTenantDefault.inboundTrust -and
                            $crossTenantDefault.b2bCollaborationInbound.usersAndGroups.accessType -eq 'allowed' -and
                            $crossTenantDefault.b2bCollaborationInbound.usersAndGroups.targets.type -eq 'all'

        $outboundAllowAll = $crossTenantDefault.b2bCollaborationOutbound.usersAndGroups.accessType -eq 'allowed' -and
                            $crossTenantDefault.b2bCollaborationOutbound.usersAndGroups.targets.type -eq 'all'

        $partners = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/policies/crossTenantAccessPolicy/partners' -ErrorAction SilentlyContinue
        $partnerCount = if ($partners -and $partners.value) { ($partners.value | Measure-Object).Count } else { 0 }

        if ($inboundAllowAll) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-CFG-004' -Workload 'EntraID' -Component 'CrossTenantAccess' `
                -CheckName 'Cross-Tenant Access Settings' -Category 'Governance' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'Cross-tenant access default policy allows inbound collaboration from all external tenants without restriction.' `
                -Explanation 'Unrestricted inbound B2B collaboration allows guest users from any Microsoft 365 tenant to be invited and access resources. Organizations should explicitly allowlist trusted tenants and block all others to prevent data exfiltration paths.' `
                -PossibleSolution 'Configure cross-tenant access policies to block inbound collaboration by default. Add explicit allow entries for trusted partner tenants. Entra admin center: External Identities > Cross-tenant access settings > Default settings.' `
                -Impact 'External users from any tenant can be invited as guests, potentially providing unauthorized access to internal resources if invitation controls are lax.' `
                -FrameworkMapping 'ISO27001-A.15' -ZeroTrustPillar 'Data' `
                -DataSource 'Graph: /v1.0/policies/crossTenantAccessPolicy/default' `
                -Remediation 'Set default inbound to block: In Entra admin center > External Identities > Cross-tenant access settings > Default settings > B2B collaboration Inbound: Block. Add partner entries for trusted tenants. Configure tenant restrictions to prevent users from signing into external tenants on corporate devices.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                -Notes "Partner-specific policies: $partnerCount | Inbound default: Allow All | Outbound default: $(if ($outboundAllowAll) { 'Allow All' } else { 'Restricted' })"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-CFG-004' -Workload 'EntraID' -Component 'CrossTenantAccess' `
                -CheckName 'Cross-Tenant Access Settings' -Category 'Governance' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected 'Cross-tenant access default policy is configured with restrictions on inbound collaboration.' `
                -DataSource 'Graph: /v1.0/policies/crossTenantAccessPolicy/default' `
                -Notes "Partner-specific policies: $partnerCount | Outbound: $(if ($outboundAllowAll) { 'Allow All' } else { 'Restricted' })"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-CFG-004: Cross-tenant access check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-CFG-004' -Workload 'EntraID' -Component 'CrossTenantAccess' `
            -CheckName 'Cross-Tenant Access Settings' -Category 'Governance' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/policies/crossTenantAccessPolicy/default' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # ENT-SEC-010  -  Emergency Access (Break-Glass) Account Validation
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-SEC-010: Checking emergency access (break-glass) account hygiene"

        # Heuristic: find cloud-only GA accounts that appear to be break-glass
        # Indicators: no MFA registered via normal methods, no last sign-in, name contains 'break', 'emergency', 'bg', 'glass'
        $gaRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction Stop
        $gaMembers = @()
        if ($gaRole) {
            $gaMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All -ErrorAction Stop
        }

        $breakGlassPatterns = @('*break*', '*glass*', '*emergency*', '*emerg*', '*bg-*', '*-bg*', '*bg_*', '*_bg*')
        $breakGlassAccounts = $gaMembers | Where-Object {
            $upn = $_.AdditionalProperties['userPrincipalName']
            $displayName = $_.AdditionalProperties['displayName']
            $breakGlassPatterns | Where-Object { $upn -like $_ -or $displayName -like $_ }
        }

        $breakGlassCount = ($breakGlassAccounts | Measure-Object).Count

        # Also check for GAs with no onPremisesSyncEnabled (cloud-only = good for BG accounts)
        $cloudOnlyGAs = [System.Collections.Generic.List[string]]::new()
        foreach ($ga in $gaMembers) {
            $userId = $ga.Id
            try {
                $userDetail = Get-MgUser -UserId $userId `
                    -Property DisplayName, UserPrincipalName, OnPremisesSyncEnabled, SignInActivity `
                    -ErrorAction SilentlyContinue
                if ($userDetail -and -not $userDetail.OnPremisesSyncEnabled) {
                    $cloudOnlyGAs.Add($userDetail.UserPrincipalName)
                }
            }
            catch { }
        }

        if ($breakGlassCount -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-010' -Workload 'EntraID' -Component 'BreakGlass' `
                -CheckName 'Emergency Access Account Validation' -Category 'Resilience' -Severity 'High' `
                -Status 'Warning' `
                -IssueDetected 'No Global Administrator accounts matching break-glass naming conventions were identified.' `
                -Explanation 'Break-glass (emergency access) accounts are cloud-only GA accounts held offline for use when normal admin access fails (MFA device lost, federated identity provider outage, CA policy misconfiguration lockout). Without dedicated break-glass accounts, an admin lockout may require days of Microsoft Support intervention.' `
                -PossibleSolution 'Create 2 cloud-only Global Administrator accounts with names indicating emergency use (e.g., breakglass1@domain.com). Use a FIDO2 key or very long random password stored in a physical safe. Exclude from all CA policies. Set up alert rules to notify on any sign-in.' `
                -Impact 'Without break-glass accounts, a CA policy misconfiguration, MFA device failure, or federated IdP outage can lock all admins out of the tenant permanently.' `
                -FrameworkMapping 'NIST-Recover' -ZeroTrustPillar 'Identity' `
                -SecureScoreMapping 'Designate more than one global admin' `
                -DataSource 'Get-MgDirectoryRole;Get-MgDirectoryRoleMember' `
                -Remediation 'Create 2 accounts: New-MgUser with cloud-only UPN (e.g., bg1@tenant.onmicrosoft.com). Assign GA role. Store credentials in physical safe or HSM. Configure Log Analytics alert: any sign-in from these accounts triggers immediate notification. Test access semi-annually.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                -Notes "Cloud-only GAs detected (potential BG candidates): $($cloudOnlyGAs -join ', ')"))
        }
        else {
            $bgNames = ($breakGlassAccounts | ForEach-Object { $_.AdditionalProperties['userPrincipalName'] }) -join ', '
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-010' -Workload 'EntraID' -Component 'BreakGlass' `
                -CheckName 'Emergency Access Account Validation' -Category 'Resilience' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected "$breakGlassCount break-glass Global Administrator account(s) identified by naming convention." `
                -DataSource 'Get-MgDirectoryRole;Get-MgDirectoryRoleMember' `
                -Notes "Break-glass accounts: $bgNames | Cloud-only GAs: $($cloudOnlyGAs -join ', ')"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "ENT-SEC-010: Break-glass check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'ENT-SEC-010' -Workload 'EntraID' -Component 'BreakGlass' `
            -CheckName 'Emergency Access Account Validation' -Category 'Resilience' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgDirectoryRole;Get-MgDirectoryRoleMember' -Notes $_.Exception.Message))
    }

    Write-TtcLog -Level Info -Message "Entra ID assessment complete  -  $($findings.Count) finding(s) generated"
    return $findings.ToArray()
}
