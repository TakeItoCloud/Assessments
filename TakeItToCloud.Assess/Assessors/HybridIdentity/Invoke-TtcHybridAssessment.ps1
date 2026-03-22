function Invoke-TtcHybridAssessment {
    <#
    .SYNOPSIS
        Runs the Hybrid Identity workload assessment.
    .DESCRIPTION
        Performs a comprehensive assessment of the hybrid identity configuration connecting
        on-premises Active Directory to Microsoft Entra ID via Entra Connect (formerly Azure AD Connect).

        Checks include: directory sync status and currency, password hash sync configuration,
        authentication mode assessment (managed vs. PTA vs. federated), break-glass account hygiene,
        on-premises privileged accounts synced to cloud, and sync error objects.

        Requires:
        - Microsoft.Graph PowerShell SDK (connected via Connect-MgGraph)
        - ActiveDirectory RSAT module (for on-premises checks)

        Required Graph scopes:
        - Organization.Read.All
        - Directory.Read.All
        - User.Read.All
        - OnPremDirectorySynchronization.Read.All (beta)
    .PARAMETER MaxSyncAgeMins
        Maximum acceptable number of minutes since the last Entra Connect sync.
        Default: 60 (Microsoft recommends alerting if >30 minutes, but 60 accounts for latency)
    .PARAMETER MaxPasswordSyncAgeMins
        Maximum acceptable number of minutes since the last password hash sync.
        Default: 120
    .EXAMPLE
        Invoke-TtcHybridAssessment
    .EXAMPLE
        Invoke-TtcHybridAssessment -MaxSyncAgeMins 30
    .OUTPUTS
        [PSCustomObject[]] Array of TakeItToCloud finding objects.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter()]
        [ValidateRange(10, 1440)]
        [int]$MaxSyncAgeMins = 60,

        [Parameter()]
        [ValidateRange(10, 1440)]
        [int]$MaxPasswordSyncAgeMins = 120
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-TtcLog -Level Info -Message "Starting Hybrid Identity assessment"

    # =========================================================================
    # Prerequisite checks
    # =========================================================================
    $graphAvailable = $false
    $adAvailable    = $false

    try {
        $ErrorActionPreference = 'Stop'
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        if ($ctx) {
            $graphAvailable = $true
            Write-TtcLog -Level Info -Message "Graph connected as: $($ctx.Account)"
        }
        else {
            Write-TtcLog -Level Warning -Message "Microsoft Graph not connected  -  cloud-side hybrid checks will be skipped"
        }
    }
    catch {
        Write-TtcLog -Level Warning -Message "Graph context check failed: $_"
    }

    try {
        $ErrorActionPreference = 'Stop'
        if (Get-Module -Name ActiveDirectory -ListAvailable) {
            Import-Module -Name ActiveDirectory -ErrorAction Stop
            $adAvailable = $true
            Write-TtcLog -Level Info -Message "ActiveDirectory module loaded"
        }
        else {
            Write-TtcLog -Level Warning -Message "ActiveDirectory module not available  -  on-premises hybrid checks will be skipped"
        }
    }
    catch {
        Write-TtcLog -Level Warning -Message "ActiveDirectory module import failed: $_"
    }

    if (-not $graphAvailable -and -not $adAvailable) {
        $findings.Add((New-TtcFinding `
            -FindingId 'HYB-HLT-001' -Workload 'HybridIdentity' -Component 'Prerequisites' `
            -CheckName 'Directory Sync Status' -Category 'Health' -Severity 'Critical' `
            -Status 'Error' `
            -IssueDetected 'Neither Microsoft Graph nor ActiveDirectory module are available  -  hybrid assessment cannot proceed.' `
            -PossibleSolution 'Install Microsoft.Graph module: Install-Module Microsoft.Graph. Connect: Connect-MgGraph. Install RSAT: Add-WindowsCapability -Online -Name RSAT.ActiveDirectory*.' `
            -Impact 'No hybrid identity assessment data can be collected.' `
            -DataSource 'Get-MgContext;Get-Module' -AutoFixAvailable 'No' -RemediationPriority 'P1'))
        return $findings.ToArray()
    }

    # Cache org data
    $org = $null
    if ($graphAvailable) {
        try {
            $org = Get-MgOrganization -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        catch {
            Write-TtcLog -Level Warning -Message "Could not retrieve organization data: $_"
        }
    }

    # =========================================================================
    # HYB-HLT-001  -  Directory Sync Status (Last Sync Time)
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "HYB-HLT-001: Checking Entra Connect sync status"

        if (-not $graphAvailable -or -not $org) {
            $findings.Add((New-TtcFinding `
                -FindingId 'HYB-HLT-001' -Workload 'HybridIdentity' -Component 'EntraConnect' `
                -CheckName 'Directory Sync Status' -Category 'Health' -Severity 'High' `
                -Status 'Error' -IssueDetected 'Graph not connected  -  directory sync status cannot be assessed.' `
                -DataSource 'Get-MgOrganization' -Notes 'Connect-MgGraph required'))
        }
        elseif (-not $org.OnPremisesSyncEnabled) {
            $findings.Add((New-TtcFinding `
                -FindingId 'HYB-HLT-001' -Workload 'HybridIdentity' -Component 'EntraConnect' `
                -CheckName 'Directory Sync Status' -Category 'Health' -Severity 'Informational' `
                -Status 'NotAssessed' `
                -IssueDetected 'Directory synchronization is not enabled for this tenant  -  cloud-only environment.' `
                -Explanation 'This tenant does not have Entra Connect configured. All users are cloud-native. Hybrid Identity checks are not applicable.' `
                -DataSource 'Get-MgOrganization' -Notes 'OnPremisesSyncEnabled: false'))
        }
        else {
            $lastSync = $org.OnPremisesLastSyncDateTime
            if ($lastSync) {
                $syncAge = [int]((Get-Date) - $lastSync.ToUniversalTime()).TotalMinutes

                if ($syncAge -gt $MaxSyncAgeMins) {
                    $severity = if ($syncAge -gt 240) { 'Critical' } elseif ($syncAge -gt 120) { 'High' } else { 'Medium' }
                    $findings.Add((New-TtcFinding `
                        -FindingId 'HYB-HLT-001' -Workload 'HybridIdentity' -Component 'EntraConnect' `
                        -CheckName 'Directory Sync Status' -Category 'Health' -Severity $severity `
                        -Status 'Fail' `
                        -IssueDetected "Last Entra Connect directory sync was $syncAge minutes ago (threshold: $MaxSyncAgeMins minutes)." `
                        -Explanation 'Entra Connect is expected to synchronize every 30 minutes by default. A prolonged sync gap means on-premises changes (new accounts, group membership updates, password changes, account disablements) are not reflected in Entra ID, creating security and operational gaps.' `
                        -PossibleSolution 'Check the Entra Connect server: (1) Verify ADSync service is running, (2) Run Start-ADSyncSyncCycle -PolicyType Delta, (3) Review Synchronization Service Manager for errors, (4) Check event logs on the Entra Connect server.' `
                        -Impact 'On-premises account disablements may not propagate, leaving terminated employee accounts active in the cloud. New users or group membership changes are delayed. Password changes on-prem may not sync.' `
                        -FrameworkMapping 'NIST-Identify' -ZeroTrustPillar 'Identity' `
                        -DataSource 'Get-MgOrganization' `
                        -Remediation 'On the Entra Connect server: Start-ADSyncSyncCycle -PolicyType Delta. Check Synchronization Service Manager for errors. Verify ADSync Windows service is running: Get-Service ADSync. Review event log: Get-EventLog -LogName Application -Source "Directory Synchronization" -Newest 20. If Entra Connect server is unreachable, verify network connectivity and health.' `
                        -AutoFixAvailable 'Partial' -RemediationPriority 'P1' `
                        -Notes "Last sync: $lastSync (UTC) | Age: $syncAge minutes | Tenant: $($org.DisplayName)"))
                }
                else {
                    $findings.Add((New-TtcFinding `
                        -FindingId 'HYB-HLT-001' -Workload 'HybridIdentity' -Component 'EntraConnect' `
                        -CheckName 'Directory Sync Status' -Category 'Health' -Severity 'High' `
                        -Status 'Pass' `
                        -IssueDetected "Last directory sync was $syncAge minutes ago  -  within the $MaxSyncAgeMins-minute threshold." `
                        -DataSource 'Get-MgOrganization' `
                        -Notes "Last sync: $lastSync (UTC)"))
                }
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-HLT-001' -Workload 'HybridIdentity' -Component 'EntraConnect' `
                    -CheckName 'Directory Sync Status' -Category 'Health' -Severity 'Critical' `
                    -Status 'Fail' `
                    -IssueDetected 'Directory sync is enabled but no sync timestamp is recorded  -  sync may have never completed successfully.' `
                    -Explanation 'Entra Connect reports no last sync timestamp despite being configured. This indicates the synchronization process has never completed successfully, or the Entra Connect installation is corrupted.' `
                    -PossibleSolution 'Reinstall or repair Entra Connect. Check the Synchronization Service Manager for persistent errors. Verify network access from the Entra Connect server to Microsoft endpoints.' `
                    -Impact 'On-premises directory is not syncing to Entra ID. Hybrid authentication, conditional access based on on-prem groups, and seamless SSO may be non-functional.' `
                    -FrameworkMapping 'NIST-Identify' -ZeroTrustPillar 'Identity' `
                    -DataSource 'Get-MgOrganization' -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                    -Notes 'OnPremisesLastSyncDateTime is null despite OnPremisesSyncEnabled = true'))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "HYB-HLT-001: Sync status check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'HYB-HLT-001' -Workload 'HybridIdentity' -Component 'EntraConnect' `
            -CheckName 'Directory Sync Status' -Category 'Health' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgOrganization' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # HYB-HLT-002  -  Password Hash Sync Currency
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "HYB-HLT-002: Checking password hash sync currency"

        if ($graphAvailable -and $org -and $org.OnPremisesSyncEnabled) {
            $lastPwdSync = $org.OnPremisesLastPasswordSyncDateTime

            if (-not $lastPwdSync) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-HLT-002' -Workload 'HybridIdentity' -Component 'PasswordSync' `
                    -CheckName 'Password Hash Sync Currency' -Category 'Health' -Severity 'Medium' `
                    -Status 'Warning' `
                    -IssueDetected 'No password hash sync timestamp recorded  -  PHS may not be configured or has never completed.' `
                    -Explanation 'Password Hash Synchronization (PHS) is recommended as an authentication resilience feature even when PTA or Federation is the primary method. No PHS timestamp may indicate PHS is disabled or misconfigured.' `
                    -PossibleSolution 'Enable PHS as a backup authentication method: In Entra Connect wizard, configure Password Hash Synchronization. Even with PTA/ADFS primary auth, PHS provides leaked credential detection and fallback authentication.' `
                    -Impact 'Without PHS, the tenant cannot leverage leaked credential detection in Entra Identity Protection. No authentication fallback if the PTA agent or ADFS goes offline.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                    -DataSource 'Get-MgOrganization' -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                    -Notes 'OnPremisesLastPasswordSyncDateTime is null'))
            }
            else {
                $pwdSyncAge = [int]((Get-Date) - $lastPwdSync.ToUniversalTime()).TotalMinutes

                if ($pwdSyncAge -gt $MaxPasswordSyncAgeMins) {
                    $severity = if ($pwdSyncAge -gt 720) { 'High' } else { 'Medium' }
                    $findings.Add((New-TtcFinding `
                        -FindingId 'HYB-HLT-002' -Workload 'HybridIdentity' -Component 'PasswordSync' `
                        -CheckName 'Password Hash Sync Currency' -Category 'Health' -Severity $severity `
                        -Status 'Fail' `
                        -IssueDetected "Last password hash sync was $pwdSyncAge minutes ago (threshold: $MaxPasswordSyncAgeMins minutes)." `
                        -Explanation 'Password Hash Sync should run approximately every 2 minutes for accounts with changed passwords. A large gap may indicate PHS agent issues, connectivity problems to Microsoft endpoints, or on-premises AD performance issues.' `
                        -PossibleSolution 'Check the Entra Connect server ADSync service. Verify network connectivity to Microsoft 365 sync endpoints. Review event logs for ADSync. Force a password sync: Set-MsolDirSyncFeature -Feature PasswordSync or run a full sync.' `
                        -Impact 'Password changes on-premises are not reflected in Entra ID, breaking cloud authentication for users who changed their password. Leaked credential detection may be stale.' `
                        -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                        -DataSource 'Get-MgOrganization' `
                        -Remediation 'On Entra Connect server: Invoke-ADSyncRunProfile -ConnectorName "<OnPrem Connector>" -RunProfileName "Full Import". Or restart ADSync service: Restart-Service ADSync. Review: Get-ADSyncScheduler to confirm scheduler is enabled and not suspended.' `
                        -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                        -Notes "Last PHS: $lastPwdSync (UTC) | Age: $pwdSyncAge minutes"))
                }
                else {
                    $findings.Add((New-TtcFinding `
                        -FindingId 'HYB-HLT-002' -Workload 'HybridIdentity' -Component 'PasswordSync' `
                        -CheckName 'Password Hash Sync Currency' -Category 'Health' -Severity 'Medium' `
                        -Status 'Pass' `
                        -IssueDetected "Password hash sync is current  -  last sync was $pwdSyncAge minutes ago." `
                        -DataSource 'Get-MgOrganization' `
                        -Notes "Last PHS: $lastPwdSync (UTC)"))
                }
            }
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'HYB-HLT-002' -Workload 'HybridIdentity' -Component 'PasswordSync' `
                -CheckName 'Password Hash Sync Currency' -Category 'Health' -Severity 'Medium' `
                -Status 'NotAssessed' -IssueDetected 'Graph not connected or sync not enabled  -  PHS check skipped.' `
                -DataSource 'Get-MgOrganization'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "HYB-HLT-002: PHS currency check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'HYB-HLT-002' -Workload 'HybridIdentity' -Component 'PasswordSync' `
            -CheckName 'Password Hash Sync Currency' -Category 'Health' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgOrganization' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # HYB-CFG-001  -  Password Hash Sync Enabled
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "HYB-CFG-001: Checking if Password Hash Sync is configured"

        if ($graphAvailable -and $org -and $org.OnPremisesSyncEnabled) {
            # Try the beta endpoint for detailed sync config
            $syncConfig = $null
            try {
                $syncConfig = Invoke-MgGraphRequest -Method GET `
                    -Uri 'https://graph.microsoft.com/beta/directory/onPremisesPublishing' `
                    -ErrorAction SilentlyContinue
            }
            catch {
                Write-TtcLog -Level Debug -Message "Could not query onPremisesPublishing endpoint: $_"
            }

            # Fall back to checking if PHS timestamp exists as a proxy for PHS being enabled
            $phsEnabled = $null -ne $org.OnPremisesLastPasswordSyncDateTime

            if ($phsEnabled) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-CFG-001' -Workload 'HybridIdentity' -Component 'PasswordSync' `
                    -CheckName 'Password Hash Sync Configuration' -Category 'Configuration' -Severity 'High' `
                    -Status 'Pass' `
                    -IssueDetected 'Password Hash Synchronization appears to be enabled (last PHS timestamp present).' `
                    -Explanation 'PHS provides authentication resilience, leaked credential detection in Identity Protection, and is a prerequisite for Seamless SSO. Microsoft recommends enabling PHS even in PTA/Federated environments as a fallback.' `
                    -DataSource 'Get-MgOrganization' `
                    -Notes "Last PHS timestamp: $($org.OnPremisesLastPasswordSyncDateTime)"))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-CFG-001' -Workload 'HybridIdentity' -Component 'PasswordSync' `
                    -CheckName 'Password Hash Sync Configuration' -Category 'Configuration' -Severity 'High' `
                    -Status 'Warning' `
                    -IssueDetected 'Password Hash Synchronization does not appear to be enabled (no PHS timestamp in tenant).' `
                    -Explanation 'PHS is recommended even in environments using Pass-Through Authentication or Federation as the primary auth method. It provides: (1) leaked credential detection via Identity Protection, (2) authentication fallback if PTA agents or ADFS fail, (3) Seamless SSO capability.' `
                    -PossibleSolution 'Enable PHS in Entra Connect: run the Entra Connect wizard and select "Password hash synchronization" as an optional feature, or change the sign-on method to include PHS. Enabling PHS does not automatically change the primary authentication method.' `
                    -Impact 'Without PHS: no leaked credential detection, no auth fallback if on-premises auth infrastructure fails, potential complete authentication outage if ADFS or PTA agents go offline.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                    -DataSource 'Get-MgOrganization' `
                    -Remediation 'Run Entra Connect configuration wizard. On "Optional features" page, enable "Password hash synchronization". This can coexist with PTA or Federation as a fallback. After enabling, verify with: (Get-MgOrganization).OnPremisesLastPasswordSyncDateTime  -  should populate within minutes.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                    -Notes 'No OnPremisesLastPasswordSyncDateTime in tenant record'))
            }
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'HYB-CFG-001' -Workload 'HybridIdentity' -Component 'PasswordSync' `
                -CheckName 'Password Hash Sync Configuration' -Category 'Configuration' -Severity 'High' `
                -Status 'NotAssessed' -IssueDetected 'Graph not connected or sync not enabled.' `
                -DataSource 'Get-MgOrganization'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "HYB-CFG-001: PHS config check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'HYB-CFG-001' -Workload 'HybridIdentity' -Component 'PasswordSync' `
            -CheckName 'Password Hash Sync Configuration' -Category 'Configuration' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgOrganization' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # HYB-CFG-002  -  Authentication Mode Assessment
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "HYB-CFG-002: Assessing authentication mode"

        if ($graphAvailable -and $org -and $org.OnPremisesSyncEnabled) {
            # Determine auth method by inspecting domain federation state
            $verifiedDomains = $org.VerifiedDomains
            $federatedDomains = $verifiedDomains | Where-Object { $_.Type -eq 'Federated' }
            $managedDomains   = $verifiedDomains | Where-Object { $_.Type -eq 'Managed' }
            $federatedCount   = ($federatedDomains | Measure-Object).Count
            $managedCount     = ($managedDomains | Measure-Object).Count

            # Check for PTA agents
            $ptaAgents = $null
            try {
                $ptaAgents = Invoke-MgGraphRequest -Method GET `
                    -Uri 'https://graph.microsoft.com/beta/onPremisesPublishingProfiles/provisioning/agents' `
                    -ErrorAction SilentlyContinue
            }
            catch {
                Write-TtcLog -Level Debug -Message "Could not query PTA agents endpoint: $_"
            }

            $authMode = if ($federatedCount -gt 0) { 'Federation (ADFS/Third-Party)' }
                        elseif ($ptaAgents -and $ptaAgents.value -and $ptaAgents.value.Count -gt 0) { 'Pass-Through Authentication (PTA)' }
                        else { 'Password Hash Sync (Managed Authentication)' }

            $notes = "Auth mode: $authMode | Federated domains: $federatedCount | Managed domains: $managedCount"

            if ($authMode -like '*Federation*') {
                $fedDomainNames = ($federatedDomains | Select-Object -ExpandProperty Name) -join ', '
                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-CFG-002' -Workload 'HybridIdentity' -Component 'AuthMethod' `
                    -CheckName 'Authentication Mode Assessment' -Category 'Configuration' -Severity 'Medium' `
                    -Status 'Warning' `
                    -IssueDetected "Federation is configured for $federatedCount domain(s). ADFS/third-party dependency introduces additional risk and infrastructure to maintain." `
                    -Explanation 'Federated authentication routes all sign-ins through on-premises ADFS servers. ADFS requires high availability infrastructure, regular certificate management, and has historically been a target for sophisticated attacks (SolarWinds, Golden SAML). Microsoft recommends migrating away from ADFS.' `
                    -PossibleSolution 'Consider migrating from ADFS to PHS or PTA (managed authentication). Use the Entra Connect migration wizard. Enable staged rollout to test managed auth for a subset of users before full cutover.' `
                    -Impact 'ADFS infrastructure downtime causes complete authentication failure for federated users. Certificate expiry on ADFS token-signing cert locks out all federated users. ADFS is a high-value target for nation-state attackers.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                    -DataSource 'Get-MgOrganization' `
                    -Remediation 'Stage ADFS to PHS migration: Enable PHS in Entra Connect first. Use staged rollout: Entra admin center > Hybrid Management > Entra Connect > Enable staged rollout. Move pilot group to managed auth. Verify then migrate remaining users. Decommission ADFS after successful cutover.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                    -Notes "$notes | Federated: $fedDomainNames"))
            }
            elseif ($authMode -like '*PTA*') {
                $ptaAgentCount = if ($ptaAgents -and $ptaAgents.value) { $ptaAgents.value.Count } else { 'unknown' }
                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-CFG-002' -Workload 'HybridIdentity' -Component 'AuthMethod' `
                    -CheckName 'Authentication Mode Assessment' -Category 'Configuration' -Severity 'Low' `
                    -Status 'Pass' `
                    -IssueDetected "Pass-Through Authentication (PTA) is configured with $ptaAgentCount PTA agent(s)." `
                    -Explanation 'PTA is a supported managed authentication method. Ensure PHS is also enabled as a fallback. Verify PTA agent redundancy (minimum 3 agents recommended for HA).' `
                    -DataSource 'Get-MgOrganization;Graph beta agents' `
                    -Notes "$notes | PTA agents: $ptaAgentCount"))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-CFG-002' -Workload 'HybridIdentity' -Component 'AuthMethod' `
                    -CheckName 'Authentication Mode Assessment' -Category 'Configuration' -Severity 'Low' `
                    -Status 'Pass' `
                    -IssueDetected 'Password Hash Sync (managed authentication) is configured  -  the recommended authentication method.' `
                    -Explanation 'PHS managed authentication is Microsoft''s recommended approach. It provides the best resilience (no on-premises dependency), Seamless SSO, and leaked credential detection without ADFS or PTA agent infrastructure.' `
                    -DataSource 'Get-MgOrganization' `
                    -Notes $notes))
            }
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'HYB-CFG-002' -Workload 'HybridIdentity' -Component 'AuthMethod' `
                -CheckName 'Authentication Mode Assessment' -Category 'Configuration' -Severity 'Medium' `
                -Status 'NotAssessed' -IssueDetected 'Graph not connected or sync not enabled.' `
                -DataSource 'Get-MgOrganization'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "HYB-CFG-002: Auth mode check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'HYB-CFG-002' -Workload 'HybridIdentity' -Component 'AuthMethod' `
            -CheckName 'Authentication Mode Assessment' -Category 'Configuration' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgOrganization' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # HYB-HLT-003  -  Sync Error Objects
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "HYB-HLT-003: Checking for directory synchronization errors"

        if ($graphAvailable -and $org -and $org.OnPremisesSyncEnabled) {
            # Objects with sync errors visible from Entra side
            $syncErrorUsers = Get-MgUser `
                -Filter "onPremisesSyncEnabled eq true and onPremisesProvisioningErrors ne null" `
                -Property Id, DisplayName, UserPrincipalName, OnPremisesProvisioningErrors `
                -All -ErrorAction SilentlyContinue

            $errorCount = ($syncErrorUsers | Measure-Object).Count

            # Also check for groups with sync errors
            $syncErrorGroups = Get-MgGroup `
                -Filter "onPremisesSyncEnabled eq true" `
                -Property Id, DisplayName, OnPremisesProvisioningErrors `
                -All -ErrorAction SilentlyContinue |
                Where-Object { $_.OnPremisesProvisioningErrors -and $_.OnPremisesProvisioningErrors.Count -gt 0 }

            $groupErrorCount = ($syncErrorGroups | Measure-Object).Count
            $totalErrors      = $errorCount + $groupErrorCount

            if ($totalErrors -gt 0) {
                $userErrorDetails = ($syncErrorUsers | Select-Object -First 10 | ForEach-Object {
                    $errType = if ($_.OnPremisesProvisioningErrors) {
                        ($_.OnPremisesProvisioningErrors | Select-Object -First 1).Category
                    } else { 'Unknown' }
                    "User: $($_.UserPrincipalName) [$errType]"
                }) -join '; '

                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-HLT-003' -Workload 'HybridIdentity' -Component 'SyncErrors' `
                    -CheckName 'Directory Synchronization Errors' -Category 'Health' -Severity 'Medium' `
                    -Status 'Fail' `
                    -IssueDetected "$totalErrors object(s) have sync errors ($errorCount users, $groupErrorCount groups)." `
                    -Explanation 'Sync errors prevent on-premises objects from properly synchronizing to Entra ID. Common causes include UPN conflicts, duplicate proxy addresses, and attribute validation failures. Objects with errors may have incomplete or incorrect cloud representations.' `
                    -PossibleSolution 'Review sync errors in the Entra admin center: Entra Connect > Troubleshoot > Diagnose synchronization errors. Or use: Get-MgUser -Filter "onPremisesSyncEnabled eq true" and check OnPremisesProvisioningErrors. Fix attribute conflicts in on-premises AD.' `
                    -Impact 'Users with sync errors may not authenticate correctly, may have missing attributes (email, group memberships), or may appear as orphaned objects. Licensing and resource access may be affected.' `
                    -FrameworkMapping 'NIST-Identify' -ZeroTrustPillar 'Identity' `
                    -DataSource 'Get-MgUser;Get-MgGroup' `
                    -Remediation 'For duplicate UPN/proxy conflicts: deduplicate in on-prem AD. For attribute validation errors: use IdFix tool (Microsoft) to scan and fix AD attributes before sync. Run IdFix: download from Microsoft Download Center. After fixing: Start-ADSyncSyncCycle -PolicyType Delta. Validate in Entra portal sync errors.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                    -Notes "First 10 user errors: $userErrorDetails"))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-HLT-003' -Workload 'HybridIdentity' -Component 'SyncErrors' `
                    -CheckName 'Directory Synchronization Errors' -Category 'Health' -Severity 'Medium' `
                    -Status 'Pass' `
                    -IssueDetected 'No directory synchronization errors detected for synced users or groups.' `
                    -DataSource 'Get-MgUser;Get-MgGroup'))
            }
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'HYB-HLT-003' -Workload 'HybridIdentity' -Component 'SyncErrors' `
                -CheckName 'Directory Synchronization Errors' -Category 'Health' -Severity 'Medium' `
                -Status 'NotAssessed' -IssueDetected 'Graph not connected or sync not enabled.' `
                -DataSource 'Get-MgUser'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "HYB-HLT-003: Sync error check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'HYB-HLT-003' -Workload 'HybridIdentity' -Component 'SyncErrors' `
            -CheckName 'Directory Synchronization Errors' -Category 'Health' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgUser' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # HYB-SEC-001  -  On-Premises Privileged Accounts Synced to Cloud
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "HYB-SEC-001: Checking if on-prem admin accounts are synced to Entra ID"

        if ($graphAvailable -and $adAvailable -and $org -and $org.OnPremisesSyncEnabled) {
            # Get on-prem privileged group members
            $domainInfo = Get-ADDomain -ErrorAction Stop
            $privGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
            $onPremAdminSAMs = [System.Collections.Generic.List[string]]::new()

            foreach ($groupName in $privGroups) {
                try {
                    $grp = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
                    if ($grp) {
                        Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue |
                            Where-Object { $_.objectClass -eq 'user' } |
                            ForEach-Object {
                                if ($_.SamAccountName -notin $onPremAdminSAMs) {
                                    $onPremAdminSAMs.Add($_.SamAccountName)
                                }
                            }
                    }
                }
                catch {
                    Write-TtcLog -Level Warning -Message "Could not enumerate group '$groupName': $_"
                }
            }

            # Check which of these are synced to Entra ID (have cloud representation)
            $syncedPrivAccounts = [System.Collections.Generic.List[string]]::new()
            foreach ($sam in $onPremAdminSAMs) {
                try {
                    $upnSuffixes = @($domainInfo.DNSRoot) + @($org.VerifiedDomains.Name)
                    foreach ($suffix in $upnSuffixes) {
                        $cloudUser = Get-MgUser -Filter "onPremisesSamAccountName eq '$sam' and onPremisesSyncEnabled eq true" `
                            -Property Id, DisplayName, UserPrincipalName, OnPremisesSyncEnabled `
                            -ErrorAction SilentlyContinue |
                            Select-Object -First 1
                        if ($cloudUser) {
                            $syncedPrivAccounts.Add("$sam ($($cloudUser.UserPrincipalName))")
                            break
                        }
                    }
                }
                catch {
                    Write-TtcLog -Level Debug -Message "Could not check cloud sync for $sam`: $_"
                }
            }

            $syncedCount = $syncedPrivAccounts.Count

            if ($syncedCount -gt 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-SEC-001' -Workload 'HybridIdentity' -Component 'PrivilegedAccounts' `
                    -CheckName 'On-Premises Admin Accounts Synced to Cloud' -Category 'Security' -Severity 'High' `
                    -Status 'Fail' `
                    -IssueDetected "$syncedCount on-premises privileged account(s) are synchronized to Entra ID." `
                    -Explanation 'Synchronizing on-premises Domain Admin accounts to Entra ID violates the principle of tier separation. If the cloud account is compromised, it can be used to attack on-premises systems. If the on-premises AD is compromised, the attacker inherits cloud privileges. Microsoft recommends separate, cloud-only accounts for cloud administration.' `
                    -PossibleSolution 'Create separate, dedicated cloud-only accounts for Entra/Microsoft 365 administration. Remove cloud admin roles from synced privileged accounts. Configure Entra Connect sync scope rules to exclude privileged AD accounts from synchronization.' `
                    -Impact 'A single compromise path exists between on-premises and cloud environments in both directions. Compromising either environment gives the attacker a foothold in the other.' `
                    -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                    -SecureScoreMapping 'Ensure admin accounts are cloud-only' `
                    -DataSource 'Get-ADGroupMember;Get-MgUser' `
                    -Remediation 'For each synced admin account: (1) Create a separate cloud-only admin account (e.g., admin-cloud@tenant.onmicrosoft.com), (2) Transfer admin role assignments to the new account, (3) Remove cloud admin roles from the synced account. Configure Entra Connect filtering to exclude Domain Admin accounts: Add-ADSyncAttributeFlowMapping or use OU/group filtering to exclude the Tier 0 OU.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                    -Notes "Synced privileged accounts: $($syncedPrivAccounts -join '; ')"))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-SEC-001' -Workload 'HybridIdentity' -Component 'PrivilegedAccounts' `
                    -CheckName 'On-Premises Admin Accounts Synced to Cloud' -Category 'Security' -Severity 'High' `
                    -Status 'Pass' `
                    -IssueDetected "No on-premises privileged accounts ($($onPremAdminSAMs.Count) checked) appear to be synchronized to Entra ID." `
                    -DataSource 'Get-ADGroupMember;Get-MgUser' `
                    -Notes "On-prem admins checked: $($onPremAdminSAMs.Count)"))
            }
        }
        else {
            $reason = if (-not $graphAvailable) { 'Graph not connected' }
                      elseif (-not $adAvailable) { 'ActiveDirectory module unavailable' }
                      elseif (-not $org.OnPremisesSyncEnabled) { 'Sync not enabled (cloud-only tenant)' }
                      else { 'Unknown' }

            $findings.Add((New-TtcFinding `
                -FindingId 'HYB-SEC-001' -Workload 'HybridIdentity' -Component 'PrivilegedAccounts' `
                -CheckName 'On-Premises Admin Accounts Synced to Cloud' -Category 'Security' -Severity 'High' `
                -Status 'NotAssessed' -IssueDetected "Check skipped: $reason." `
                -DataSource 'Get-ADGroupMember;Get-MgUser'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "HYB-SEC-001: On-prem admins sync check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'HYB-SEC-001' -Workload 'HybridIdentity' -Component 'PrivilegedAccounts' `
            -CheckName 'On-Premises Admin Accounts Synced to Cloud' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADGroupMember;Get-MgUser' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # HYB-SEC-002  -  Break-Glass Accounts Are Cloud-Only (Not Synced)
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "HYB-SEC-002: Checking Global Admin accounts are cloud-only"

        if ($graphAvailable) {
            $gaRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction SilentlyContinue
            if ($gaRole) {
                $gaMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All -ErrorAction Stop
                $syncedGAs = [System.Collections.Generic.List[string]]::new()

                foreach ($member in $gaMembers) {
                    $upn = $member.AdditionalProperties['userPrincipalName']
                    $syncEnabled = $member.AdditionalProperties['onPremisesSyncEnabled']
                    if ($syncEnabled -eq $true) {
                        $displayName = $member.AdditionalProperties['displayName']
                        $syncedGAs.Add("$displayName ($upn)")
                    }
                }

                $syncedGACount = $syncedGAs.Count

                if ($syncedGACount -gt 0) {
                    $findings.Add((New-TtcFinding `
                        -FindingId 'HYB-SEC-002' -Workload 'HybridIdentity' -Component 'BreakGlass' `
                        -CheckName 'Break-Glass Accounts Are Cloud-Only' -Category 'Security' -Severity 'High' `
                        -Status 'Fail' `
                        -IssueDetected "$syncedGACount Global Administrator(s) are synced from on-premises AD  -  break-glass accounts must be cloud-only." `
                        -Explanation 'Break-glass (emergency access) Global Administrators must be cloud-only accounts, not synchronized from on-premises AD. If on-premises AD is compromised (e.g., ransomware), synced accounts could be modified or deleted, removing cloud admin access at the worst possible time.' `
                        -PossibleSolution 'Create separate cloud-only Global Admin accounts with @tenant.onmicrosoft.com UPN. Remove GA roles from synced accounts. Store break-glass credentials in an offline vault. Enable alerting for any sign-in activity from these accounts.' `
                        -Impact 'If on-premises AD is compromised and GA accounts are synced, the attacker can delete or modify cloud admin accounts, locking legitimate admins out of the tenant at the moment they need access most.' `
                        -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                        -DataSource 'Get-MgDirectoryRole;Get-MgDirectoryRoleMember' `
                        -Remediation 'Create cloud-only GAs: New-MgUser with @<tenant>.onmicrosoft.com UPN. Add to Global Administrator role. Remove GA assignment from synced accounts: Remove-MgDirectoryRoleWithReferenceMember. Store credentials in physical safe or HSM-backed vault. Configure Identity Protection alert for break-glass sign-in activity.' `
                        -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                        -Notes "Synced GAs: $($syncedGAs -join '; ')"))
                }
                else {
                    $gaCount = ($gaMembers | Measure-Object).Count
                    $findings.Add((New-TtcFinding `
                        -FindingId 'HYB-SEC-002' -Workload 'HybridIdentity' -Component 'BreakGlass' `
                        -CheckName 'Break-Glass Accounts Are Cloud-Only' -Category 'Security' -Severity 'High' `
                        -Status 'Pass' `
                        -IssueDetected "All $gaCount Global Administrator(s) are cloud-only accounts (not synced from on-premises AD)." `
                        -DataSource 'Get-MgDirectoryRole;Get-MgDirectoryRoleMember'))
                }
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-SEC-002' -Workload 'HybridIdentity' -Component 'BreakGlass' `
                    -CheckName 'Break-Glass Accounts Are Cloud-Only' -Category 'Security' -Severity 'High' `
                    -Status 'Error' -IssueDetected 'Global Administrator role not found in directory.' `
                    -DataSource 'Get-MgDirectoryRole'))
            }
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'HYB-SEC-002' -Workload 'HybridIdentity' -Component 'BreakGlass' `
                -CheckName 'Break-Glass Accounts Are Cloud-Only' -Category 'Security' -Severity 'High' `
                -Status 'NotAssessed' -IssueDetected 'Graph not connected  -  break-glass account check skipped.' `
                -DataSource 'Get-MgDirectoryRole'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "HYB-SEC-002: Break-glass cloud-only check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'HYB-SEC-002' -Workload 'HybridIdentity' -Component 'BreakGlass' `
            -CheckName 'Break-Glass Accounts Are Cloud-Only' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgDirectoryRole' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # HYB-CFG-003  -  Entra Connect Service Account Detection
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "HYB-CFG-003: Checking Entra Connect service account configuration"

        if ($adAvailable) {
            # MSOL_ service accounts are created by Entra Connect and have extensive AD read permissions
            $msolAccounts = Get-ADUser -Filter "SamAccountName -like 'MSOL_*'" `
                -Properties SamAccountName, Description, PasswordLastSet, Enabled, MemberOf `
                -ErrorAction SilentlyContinue

            $msolCount = ($msolAccounts | Measure-Object).Count

            if ($msolCount -gt 0) {
                $msolDetails = ($msolAccounts | ForEach-Object {
                    "[$($_.SamAccountName)] Enabled:$($_.Enabled) PwdLastSet:$($_.PasswordLastSet)"
                }) -join '; '

                # Check if MSOL accounts are in any admin groups (they should not be)
                $msolInAdminGroups = [System.Collections.Generic.List[string]]::new()
                foreach ($msol in $msolAccounts) {
                    $memberOf = $msol.MemberOf | Where-Object { $_ -match 'Domain Admins|Enterprise Admins|Schema Admins|Administrators' }
                    if ($memberOf) {
                        $msolInAdminGroups.Add("$($msol.SamAccountName) is in elevated group(s)")
                    }
                }

                if ($msolInAdminGroups.Count -gt 0) {
                    $findings.Add((New-TtcFinding `
                        -FindingId 'HYB-CFG-003' -Workload 'HybridIdentity' -Component 'ServiceAccounts' `
                        -CheckName 'Entra Connect Service Account Privileges' -Category 'Security' -Severity 'Critical' `
                        -Status 'Fail' `
                        -IssueDetected "Entra Connect MSOL_ service account(s) found in privileged AD groups  -  excessive permissions." `
                        -Explanation 'The MSOL_ service account is used by Entra Connect to read and write directory data. This account does not need Domain Admin privileges. If it is in Domain Admins or Administrators, it represents an unnecessary privilege escalation path. If the Entra Connect server is compromised, the attacker gains Domain Admin.' `
                        -PossibleSolution 'Remove MSOL_ accounts from all privileged AD groups immediately. The account requires only: Replicate Directory Changes (and Replicate Directory Changes All for PHS) permissions on the domain, which are granted automatically during Entra Connect installation.' `
                        -Impact 'Compromise of the Entra Connect server (which is network-accessible to Microsoft cloud) provides an instant Domain Admin credential.' `
                        -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                        -DataSource 'Get-ADUser' `
                        -Remediation 'Remove from admin groups: Remove-ADGroupMember -Identity "Domain Admins" -Members MSOL_*. Verify required permissions using the Entra Connect wizard permission grants. Ensure the Entra Connect server is classified as Tier 0 infrastructure with equivalent security to Domain Controllers.' `
                        -AutoFixAvailable 'Partial' -RemediationPriority 'P1' `
                        -Notes "Violations: $($msolInAdminGroups -join '; ')"))
                }
                else {
                    $findings.Add((New-TtcFinding `
                        -FindingId 'HYB-CFG-003' -Workload 'HybridIdentity' -Component 'ServiceAccounts' `
                        -CheckName 'Entra Connect Service Account Privileges' -Category 'Configuration' -Severity 'Medium' `
                        -Status 'Pass' `
                        -IssueDetected "$msolCount Entra Connect MSOL_ service account(s) found  -  not in privileged AD groups." `
                        -DataSource 'Get-ADUser' `
                        -Notes $msolDetails))
                }
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'HYB-CFG-003' -Workload 'HybridIdentity' -Component 'ServiceAccounts' `
                    -CheckName 'Entra Connect Service Account Privileges' -Category 'Configuration' -Severity 'Medium' `
                    -Status 'Warning' `
                    -IssueDetected 'No MSOL_ service accounts found in AD  -  Entra Connect may not be installed on a domain-joined server, or uses a different naming convention.' `
                    -Explanation 'Entra Connect creates MSOL_ service accounts during installation. If none are found, either Entra Connect is not installed in this domain, uses a custom service account name, or this is a cloud-only deployment.' `
                    -DataSource 'Get-ADUser' `
                    -Notes 'Query: Get-ADUser -Filter "SamAccountName -like ''MSOL_*''" returned 0 results'))
            }
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'HYB-CFG-003' -Workload 'HybridIdentity' -Component 'ServiceAccounts' `
                -CheckName 'Entra Connect Service Account Privileges' -Category 'Configuration' -Severity 'Medium' `
                -Status 'NotAssessed' -IssueDetected 'ActiveDirectory module unavailable  -  service account check skipped.' `
                -DataSource 'Get-ADUser'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "HYB-CFG-003: Service account check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'HYB-CFG-003' -Workload 'HybridIdentity' -Component 'ServiceAccounts' `
            -CheckName 'Entra Connect Service Account Privileges' -Category 'Configuration' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-ADUser' -Notes $_.Exception.Message))
    }

    Write-TtcLog -Level Info -Message "Hybrid Identity assessment complete  -  $($findings.Count) finding(s) generated"
    return $findings.ToArray()
}
