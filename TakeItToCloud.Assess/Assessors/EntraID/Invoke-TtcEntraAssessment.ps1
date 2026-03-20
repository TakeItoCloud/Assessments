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

    # Cache organization data — used by multiple checks
    $org = $null
    try {
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        Write-TtcLog -Level Info -Message "Tenant: $($org.DisplayName) ($($org.Id))"
    }
    catch {
        Write-TtcLog -Level Warning -Message "Could not retrieve organization data: $_"
    }

    # =========================================================================
    # ENT-SEC-001 — MFA Registration Coverage
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
    # ENT-SEC-002 — Legacy Authentication Blocked via Conditional Access
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "ENT-SEC-002: Checking legacy auth blocking via Conditional Access"

        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop

        # A policy blocks legacy auth if it:
        # - Targets All Users (or large groups) — AllUsers included
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
    # ENT-SEC-003 — Global Administrator Count and Hygiene
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
                -IssueDetected "Only $gaCount Global Administrator(s) assigned — minimum 2 required for break-glass redundancy." `
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
                -IssueDetected "$gaCount Global Administrator(s) assigned — within recommended range (2 to $MaxGlobalAdmins)." `
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
    # ENT-SEC-004 — Risky Users Not Remediated
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
                -IssueDetected "$compromisedCount account(s) confirmed compromised in Entra Identity Protection — not yet remediated." `
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
    # ENT-CFG-001 — User Consent Policy (Application Consent)
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
                -IssueDetected 'User consent is limited to verified publishers with low-risk permissions — review to confirm alignment with policy.' `
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
                -IssueDetected 'User consent is disabled — admin approval is required for all application permissions.' `
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
    # ENT-CFG-002 — External Collaboration Settings (Guest Invitations)
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
    # ENT-SEC-005 — Conditional Access Baseline Coverage
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
                -IssueDetected 'No Conditional Access policies are enabled and Security Defaults is disabled — no baseline MFA enforcement.' `
                -Explanation 'Without CA policies or Security Defaults, there is no mechanism to enforce MFA, block risky sign-ins, or apply access controls. The tenant is relying entirely on password authentication, which is highly susceptible to phishing and credential attacks.' `
                -PossibleSolution 'Immediately enable Security Defaults for basic MFA enforcement (if not using CA policies), or deploy a set of Conditional Access baseline policies: require MFA for all users, block legacy auth, require MFA for admin roles.' `
                -Impact 'All users can authenticate with only a password. No protection against phishing, password spray, or credential stuffing exists at the authentication layer.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                -SecureScoreMapping 'Enable Conditional Access policies' `
                -DataSource 'Get-MgIdentityConditionalAccessPolicy;Get-MgPolicyIdentitySecurityDefaultsEnforcementPolicy' `
                -Remediation 'Option 1: Enable Security Defaults: Update-MgPolicyIdentitySecurityDefaultsEnforcementPolicy -IsEnabled $true. Option 2: Deploy CA baseline — Require MFA for all users, Block legacy auth, Require MFA for admins, Block risky sign-ins. Use named locations and exclusion groups for break-glass accounts.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes "CA Policies: $(($caPolicies | Measure-Object).Count) total, $enabledCount enabled, $(($reportOnlyPolicies | Measure-Object).Count) report-only. Security Defaults: Disabled"))
        }
        elseif ($enabledCount -eq 0 -and $secDefaultsEnabled) {
            $findings.Add((New-TtcFinding `
                -FindingId 'ENT-SEC-005' -Workload 'EntraID' -Component 'ConditionalAccess' `
                -CheckName 'Conditional Access Baseline Coverage' -Category 'Security' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'No Conditional Access policies enabled — Security Defaults provides basic protection but lacks granular control.' `
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
    # ENT-CFG-003 — Self-Service Password Reset Configuration
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
    # ENT-IDN-001 — Stale Guest User Accounts
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
    # ENT-MON-001 — Audit and Sign-in Log Accessibility
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
                    -IssueDetected "Most recent audit log entry is $auditAge hours old — verify log pipeline is functioning." `
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
                -IssueDetected 'No audit log entries returned — logs may be empty or permissions insufficient.' `
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

    Write-TtcLog -Level Info -Message "Entra ID assessment complete — $($findings.Count) finding(s) generated"
    return $findings.ToArray()
}
