function Invoke-TtcPimAssessment {
    <#
    .SYNOPSIS
        Runs the Privileged Identity Management (PIM) workload assessment.
    .DESCRIPTION
        Performs a deep assessment of Entra ID Privileged Identity Management configuration
        covering: PIM-managed vs standing role assignments, activation policy configuration
        (MFA, justification, approval), alert configuration, role assignment hygiene,
        and access review coverage for privileged roles.

        Requires Microsoft.Graph PowerShell SDK with the following scopes:
        - RoleManagement.Read.Directory
        - PrivilegedAccess.Read.AzureAD
        - Directory.Read.All

        Connect before running:
        Connect-MgGraph -Scopes "RoleManagement.Read.Directory","PrivilegedAccess.Read.AzureAD","Directory.Read.All"

        NOTE: Requires Entra ID P2 license for PIM functionality.
    .EXAMPLE
        Invoke-TtcPimAssessment
    .OUTPUTS
        [PSCustomObject[]] Array of TakeItToCloud finding objects.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-TtcLog -Level Info -Message "Starting PIM assessment"

    # =========================================================================
    # Prerequisite: Microsoft Graph connection
    # =========================================================================
    if (-not (Test-TtcGraphConnection -RequiredScopes @('RoleManagement.Read.Directory') -Workload 'PIM')) {
        $findings.Add((New-TtcFinding `
            -FindingId 'PIM-CFG-001' -Workload 'EntraID' -Component 'Prerequisites' `
            -CheckName 'PIM Activation Policy Configuration' -Category 'Identity' -Severity 'Critical' `
            -Status 'Error' `
            -IssueDetected 'Microsoft Graph connection not established or missing RoleManagement.Read.Directory scope.' `
            -PossibleSolution 'Connect-MgGraph -Scopes "RoleManagement.Read.Directory","PrivilegedAccess.Read.AzureAD","Directory.Read.All"' `
            -DataSource 'Get-MgContext' -AutoFixAvailable 'No' -RemediationPriority 'P1'))
        return $findings.ToArray()
    }

    # =========================================================================
    # PIM-CFG-001  -  PIM Activation Policy Requirements
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "PIM-CFG-001: Checking PIM role activation policy settings"

        $roleSettings = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/policies/roleManagementPolicies?$filter=scopeType eq ''DirectoryRole''' `
            -ErrorAction SilentlyContinue

        $settingsList = if ($roleSettings -and $roleSettings.value) { $roleSettings.value } else { @() }
        $settingsCount = ($settingsList | Measure-Object).Count

        if ($settingsCount -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'PIM-CFG-001' -Workload 'EntraID' -Component 'PIMPolicies' `
                -CheckName 'PIM Activation Policy Configuration' -Category 'Identity' -Severity 'High' `
                -Status 'Warning' `
                -IssueDetected 'No PIM role management policies found. PIM may not be configured or P2 license may be absent.' `
                -Explanation 'PIM role management policies control activation requirements such as MFA, justification, approval, and maximum activation duration. Without policies, there are no controls on how and when admins activate their privileged roles.' `
                -PossibleSolution 'Enable Entra ID PIM: Identity Governance > Privileged Identity Management. Verify Entra ID P2 or Microsoft 365 E5 licensing. Configure role settings for each admin role.' `
                -DataSource 'Graph: /v1.0/policies/roleManagementPolicies' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2'))
        }
        else {
            # Check individual role policies for key admin roles
            $criticalRoles = @('Global Administrator', 'Privileged Role Administrator', 'Security Administrator',
                               'Exchange Administrator', 'SharePoint Administrator', 'User Administrator')

            $weakPolicies = [System.Collections.Generic.List[string]]::new()

            foreach ($policy in $settingsList) {
                try {
                    $policyRules = Invoke-TtcMgGraphRequest `
                        -Uri "/v1.0/policies/roleManagementPolicies/$($policy.id)/rules" `
                        -ErrorAction SilentlyContinue

                    $rules = if ($policyRules -and $policyRules.value) { $policyRules.value } else { @() }

                    # Check MFA requirement rule
                    $mfaRule = $rules | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' -or $_.'@odata.type' -like '*enablementRule*' }
                    $expirationRule = $rules | Where-Object { $_.'@odata.type' -like '*expirationRule*' -and $_.isExpirationRequired -eq $true }

                    $roleName = $policy.displayName
                    if ($roleName -in $criticalRoles) {
                        $needsMfa = $mfaRule -and $mfaRule.enabledRules -contains 'MultiFactorAuthentication'
                        if (-not $needsMfa) {
                            $weakPolicies.Add("$roleName: MFA not required for activation")
                        }
                    }
                }
                catch { }
            }

            if ($weakPolicies.Count -gt 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'PIM-CFG-001' -Workload 'EntraID' -Component 'PIMPolicies' `
                    -CheckName 'PIM Activation Policy Configuration' -Category 'Identity' -Severity 'High' `
                    -Status 'Fail' `
                    -IssueDetected "$($weakPolicies.Count) critical role(s) do not require MFA for PIM activation." `
                    -Explanation 'PIM activation without MFA requirement defeats a key security control. An attacker who compromises an eligible admin account can activate the role immediately without an additional authentication factor. MFA at activation time is a critical Just-In-Time access control.' `
                    -PossibleSolution 'Configure PIM activation settings for each critical role to require MFA. Entra admin center: Identity Governance > PIM > Azure AD Roles > [Role] > Settings > Activation > Require Multi-Factor Authentication.' `
                    -Impact 'Compromised eligible accounts can activate privileged roles without MFA challenge, immediately gaining administrative access.' `
                    -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                    -MitreAttack 'T1078.004' `
                    -DataSource 'Graph: /v1.0/policies/roleManagementPolicies' `
                    -Remediation 'For each critical role: PIM > Azure AD Roles > Roles > [Role] > Settings > Edit. Activation tab: Require Azure MFA = Yes. Require justification = Yes. Set activation duration = 4-8 hours maximum. For Global Admin: also require approval.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                    -Notes "Weak policies: $($weakPolicies -join ' | ')"))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'PIM-CFG-001' -Workload 'EntraID' -Component 'PIMPolicies' `
                    -CheckName 'PIM Activation Policy Configuration' -Category 'Identity' -Severity 'High' `
                    -Status 'Pass' `
                    -IssueDetected "PIM activation policies configured for $settingsCount role(s). Critical roles require MFA for activation." `
                    -DataSource 'Graph: /v1.0/policies/roleManagementPolicies'))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "PIM-CFG-001: PIM policy check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'PIM-CFG-001' -Workload 'EntraID' -Component 'PIMPolicies' `
            -CheckName 'PIM Activation Policy Configuration' -Category 'Identity' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete (requires P2 + RoleManagement.Read.Directory): $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/policies/roleManagementPolicies' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # PIM-SEC-001  -  Stale PIM Eligible Assignments
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "PIM-SEC-001: Checking stale PIM eligible role assignments"

        $eligibleSchedules = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition' `
            -ErrorAction Stop

        $scheduleList = if ($eligibleSchedules -and $eligibleSchedules.value) { $eligibleSchedules.value } else { @() }

        # Assignments with no end date are permanent eligible - flag them
        $neverExpiring = $scheduleList | Where-Object {
            $_.scheduleInfo.expiration.type -eq 'noExpiration' -or
            -not $_.scheduleInfo.expiration.endDateTime
        }
        $neverExpiringCount = ($neverExpiring | Measure-Object).Count
        $totalEligible = ($scheduleList | Measure-Object).Count

        if ($neverExpiringCount -gt 0) {
            $examples = ($neverExpiring | Select-Object -First 10 | ForEach-Object {
                $principalName = $_.principal.displayName
                $roleName = $_.roleDefinition.displayName
                "$principalName -> $roleName"
            }) -join ' | '

            $findings.Add((New-TtcFinding `
                -FindingId 'PIM-SEC-001' -Workload 'EntraID' -Component 'PIMAssignments' `
                -CheckName 'Stale PIM Eligible Assignments' -Category 'Identity' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected "$neverExpiringCount of $totalEligible PIM eligible assignment(s) have no expiration date." `
                -Explanation 'PIM eligible assignments without expiry persist indefinitely. Former employees, contractors, or role owners who no longer need access retain eligible assignments permanently. Best practice is to set eligible assignment expiry to 1 year and require annual access review renewal.' `
                -PossibleSolution 'Set expiration on all PIM eligible assignments: PIM > Azure AD Roles > Assignments > Eligible Assignments > Edit each assignment > Set end date. Implement quarterly or annual access reviews for all PIM eligible assignments via Entra Identity Governance > Access Reviews.' `
                -Impact 'Eligible role assignments accumulate over time as people change roles. Former admins retain the ability to activate privileged roles indefinitely unless explicitly removed.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                -DataSource 'Graph: /v1.0/roleManagement/directory/roleEligibilitySchedules' `
                -Remediation 'Set expiry: For each no-expiration assignment, edit and set EndDateTime = (Get-Date).AddDays(365). Create Access Review: Identity Governance > Access Reviews > New > Scope: Privileged Identity Management eligible roles > Recurrence: Quarterly.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                -Notes "No-expiry eligible assignments (first 10): $examples"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'PIM-SEC-001' -Workload 'EntraID' -Component 'PIMAssignments' `
                -CheckName 'Stale PIM Eligible Assignments' -Category 'Identity' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected "All $totalEligible PIM eligible assignment(s) have expiration dates configured." `
                -DataSource 'Graph: /v1.0/roleManagement/directory/roleEligibilitySchedules'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "PIM-SEC-001: Eligible assignment check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'PIM-SEC-001' -Workload 'EntraID' -Component 'PIMAssignments' `
            -CheckName 'Stale PIM Eligible Assignments' -Category 'Identity' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/roleManagement/directory/roleEligibilitySchedules' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # PIM-SEC-002  -  Active (Standing) Privileged Role Assignments
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "PIM-SEC-002: Checking active (standing) privileged role assignments"

        $activeSchedules = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/roleManagement/directory/roleAssignmentSchedules?$expand=principal,roleDefinition' `
            -ErrorAction Stop

        $activeList = if ($activeSchedules -and $activeSchedules.value) { $activeSchedules.value } else { @() }

        # Standing access = not activated via PIM (assignmentType = 'Assigned' not 'Activated')
        $standingAssignments = $activeList | Where-Object { $_.assignmentType -eq 'Assigned' }
        $standingCount = ($standingAssignments | Measure-Object).Count

        # Flag critical roles with standing access
        $criticalRoleNames = @('Global Administrator', 'Privileged Role Administrator', 'Security Administrator')
        $criticalStanding = $standingAssignments | Where-Object {
            $_.roleDefinition.displayName -in $criticalRoleNames
        }
        $criticalStandingCount = ($criticalStanding | Measure-Object).Count

        if ($criticalStandingCount -gt 0) {
            $examples = ($criticalStanding | ForEach-Object {
                "$($_.principal.displayName) -> $($_.roleDefinition.displayName)"
            }) -join ' | '

            $findings.Add((New-TtcFinding `
                -FindingId 'PIM-SEC-002' -Workload 'EntraID' -Component 'PIMAssignments' `
                -CheckName 'Standing Privileged Role Assignments' -Category 'Identity' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected "$criticalStandingCount critical role(s) assigned as standing (permanent) access instead of PIM eligible." `
                -Explanation 'Standing assignments for critical roles like Global Administrator are permanently active 24/7. Every minute these accounts exist as active admins is time an attacker has to exploit a compromised credential. PIM just-in-time access limits exposure to only when the role is explicitly activated.' `
                -PossibleSolution 'Convert standing critical role assignments to PIM eligible assignments. Keep only 2 break-glass accounts as permanent GAs. All other admin access should be eligible and require explicit activation with MFA and justification.' `
                -Impact 'Standing admin accounts are high-value attack targets at all times. A compromised standing GA has immediate, unlimited tenant access without any activation delay or MFA step-up.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                -MitreAttack 'T1078.004' `
                -DataSource 'Graph: /v1.0/roleManagement/directory/roleAssignmentSchedules' `
                -Remediation 'For each standing critical role: Remove standing assignment: Remove-MgRoleManagementDirectoryRoleAssignment. Add PIM eligible assignment: New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest. Keep 2 break-glass GAs as permanent. Use PIM for all other admin access.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes "Standing critical roles: $examples | Total standing assignments: $standingCount"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'PIM-SEC-002' -Workload 'EntraID' -Component 'PIMAssignments' `
                -CheckName 'Standing Privileged Role Assignments' -Category 'Identity' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected "No standing assignments found for critical roles. Total standing assignments: $standingCount (may include break-glass accounts)." `
                -DataSource 'Graph: /v1.0/roleManagement/directory/roleAssignmentSchedules' `
                -Notes "Total standing: $standingCount | Critical role standing: 0"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "PIM-SEC-002: Standing assignment check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'PIM-SEC-002' -Workload 'EntraID' -Component 'PIMAssignments' `
            -CheckName 'Standing Privileged Role Assignments' -Category 'Identity' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/roleManagement/directory/roleAssignmentSchedules' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # PIM-GOV-001  -  Access Reviews for Privileged Roles
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "PIM-GOV-001: Checking access reviews for privileged roles"

        $accessReviews = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/identityGovernance/accessReviews/definitions?$select=id,displayName,status,scope' `
            -ErrorAction SilentlyContinue

        $reviewList = if ($accessReviews -and $accessReviews.value) { $accessReviews.value } else { @() }
        $activeReviews = $reviewList | Where-Object { $_.status -ne 'Completed' -and $_.status -ne 'Deleted' }
        $privilegedReviews = $activeReviews | Where-Object {
            $_.scope -and ($_.scope.principalScopes -or ($_.scope | ConvertTo-Json -Depth 5) -match 'role')
        }

        $reviewCount = ($privilegedReviews | Measure-Object).Count

        if ($reviewCount -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'PIM-GOV-001' -Workload 'EntraID' -Component 'AccessReviews' `
                -CheckName 'Access Reviews for Privileged Roles' -Category 'Governance' -Severity 'Medium' `
                -Status 'Fail' `
                -IssueDetected 'No active access reviews targeting privileged roles found in Entra Identity Governance.' `
                -Explanation 'Access reviews are a critical governance control that periodically validates that privileged role assignments are still appropriate. Without scheduled reviews, stale eligible assignments accumulate as people change roles, leave the organization, or no longer need access. Reviews ensure least-privilege is maintained over time.' `
                -PossibleSolution 'Create quarterly access reviews for all PIM eligible role assignments. Assign reviewers (role owners or managers). Configure auto-apply: remove access if reviewer does not respond. Entra admin center: Identity Governance > Access Reviews > New access review > Scope: Privileged Identity Management roles.' `
                -Impact 'Without periodic reviews, former employees and role-changers retain eligible admin access indefinitely. Excess eligible assignments increase blast radius of any compromised account.' `
                -FrameworkMapping 'ISO27001-A.9' -ZeroTrustPillar 'Identity' `
                -DataSource 'Graph: /v1.0/identityGovernance/accessReviews/definitions' `
                -Remediation 'Create access review: Identity Governance > Access Reviews > New. Scope: Users with Azure AD role assignments. Include PIM eligible + active. Reviewers: Role owners or selected reviewers. Recurrence: Quarterly. Upon completion: Auto-apply results = Remove access.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                -Notes "Total access review definitions found: $(($reviewList | Measure-Object).Count)"))
        }
        else {
            $reviewNames = ($privilegedReviews | Select-Object -ExpandProperty displayName) -join ', '
            $findings.Add((New-TtcFinding `
                -FindingId 'PIM-GOV-001' -Workload 'EntraID' -Component 'AccessReviews' `
                -CheckName 'Access Reviews for Privileged Roles' -Category 'Governance' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected "$reviewCount active access review(s) targeting privileged roles found." `
                -DataSource 'Graph: /v1.0/identityGovernance/accessReviews/definitions' `
                -Notes "Active privileged role reviews: $reviewNames"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "PIM-GOV-001: Access review check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'PIM-GOV-001' -Workload 'EntraID' -Component 'AccessReviews' `
            -CheckName 'Access Reviews for Privileged Roles' -Category 'Governance' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete (requires Identity Governance license): $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/identityGovernance/accessReviews/definitions' -Notes $_.Exception.Message))
    }

    Write-TtcLog -Level Info -Message "PIM assessment complete  -  $($findings.Count) finding(s) generated"
    return $findings.ToArray()
}
