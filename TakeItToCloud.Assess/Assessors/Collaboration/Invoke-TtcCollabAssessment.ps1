function Invoke-TtcCollabAssessment {
    <#
    .SYNOPSIS
        Runs the Collaboration workload assessment for SharePoint Online, OneDrive for Business,
        Microsoft Teams, and data governance.
    .DESCRIPTION
        Performs a comprehensive assessment of collaboration security and governance settings,
        covering: external sharing capability, anonymous link expiration, guest link expiration,
        default sharing link scope, M365 Groups guest policy, sensitivity label deployment,
        retention policy coverage, and Teams external/guest access configuration.

        Data sources are attempted in this order of preference:
        1. Microsoft Graph API (Connect-MgGraph) — primary for SPO settings and identity/governance checks
        2. SharePoint Online Management Shell (Connect-SPOService) — fallback for SPO checks
        3. MicrosoftTeams module (Connect-MicrosoftTeams) — required for COL-GOV-004
        4. Security & Compliance PowerShell (Connect-IPPSSession) — required for COL-GOV-003

        Required Graph scopes (for full coverage):
        - SharePointTenantSettings.Read.All  (SPO admin settings — COL-SEC-001 through COL-SEC-004)
        - Directory.Read.All                 (Group settings — COL-GOV-001)
        - InformationProtectionPolicy.Read   (Sensitivity labels — COL-GOV-002)

        Optional modules (checks return NotAssessed if unavailable):
        - Microsoft.Online.SharePoint.PowerShell  (SPO fallback)
        - MicrosoftTeams                          (COL-GOV-004)
        - ExchangeOnlineManagement v3+ or IPPS    (COL-GOV-003)
    .PARAMETER AnonymousLinkMaxExpirationDays
        Maximum acceptable expiration in days for anonymous (Anyone) sharing links.
        Links configured to expire in more than this number of days are flagged as a Warning.
        Default: 30
    .PARAMETER GuestLinkMaxExpirationDays
        Maximum acceptable expiration in days for external guest sharing links.
        Links configured to expire in more than this number of days are flagged as a Warning.
        Default: 90
    .EXAMPLE
        Invoke-TtcCollabAssessment
    .EXAMPLE
        Invoke-TtcCollabAssessment -AnonymousLinkMaxExpirationDays 14 -GuestLinkMaxExpirationDays 60
    .OUTPUTS
        [PSCustomObject[]] Array of TakeItToCloud finding objects.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$AnonymousLinkMaxExpirationDays = 30,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$GuestLinkMaxExpirationDays = 90
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-TtcLog -Level Info -Message "Starting Collaboration assessment"

    # =========================================================================
    # Prerequisite probes — detect available data sources
    # =========================================================================
    $graphAvailable   = $false
    $spoSettings      = $null   # Graph admin/sharepoint/settings response
    $spoTenant        = $null   # Get-SPOTenant response (fallback)
    $spoDataAvailable = $false

    # Graph connectivity
    try {
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        if ($ctx) {
            $graphAvailable = $true
            Write-TtcLog -Level Info -Message "Graph connected as: $($ctx.Account)"
        }
        else {
            Write-TtcLog -Level Warning -Message "Microsoft Graph not connected — some collaboration checks will be limited"
        }
    }
    catch {
        Write-TtcLog -Level Warning -Message "Graph context probe failed: $($_.Exception.Message)"
    }

    # Graph SPO admin settings (requires SharePointTenantSettings.Read.All)
    if ($graphAvailable) {
        try {
            $spoSettings = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' `
                -ErrorAction Stop
            $spoDataAvailable = $true
            Write-TtcLog -Level Info -Message "Graph SPO admin settings retrieved"
        }
        catch {
            Write-TtcLog -Level Warning -Message "Graph SPO admin settings unavailable (needs SharePointTenantSettings.Read.All) — trying SPO Management Shell: $($_.Exception.Message)"
        }
    }

    # SPO Management Shell fallback
    if (-not $spoDataAvailable) {
        try {
            $ErrorActionPreference = 'Stop'
            $spoTenant = Get-SPOTenant -ErrorAction Stop
            $spoDataAvailable = $true
            Write-TtcLog -Level Info -Message "SharePoint Online Management Shell data retrieved"
        }
        catch {
            Write-TtcLog -Level Debug -Message "Get-SPOTenant not available: $($_.Exception.Message)"
        }
    }

    if (-not $spoDataAvailable -and -not $graphAvailable) {
        $findings.Add((New-TtcFinding `
            -FindingId 'COL-SEC-001' -Workload 'Collaboration' -Component 'Prerequisites' `
            -CheckName 'SharePoint and OneDrive External Sharing Level' -Category 'Security' -Severity 'High' `
            -Status 'Error' `
            -IssueDetected 'Neither Microsoft Graph nor SharePoint Online Management Shell are available — Collaboration assessment cannot proceed.' `
            -Explanation 'The Collaboration assessor requires either a Graph connection (Connect-MgGraph with SharePointTenantSettings.Read.All) or SharePoint Online Management Shell (Connect-SPOService). Neither is available.' `
            -PossibleSolution 'Option 1: Connect-MgGraph -Scopes "SharePointTenantSettings.Read.All","Directory.Read.All","InformationProtectionPolicy.Read". Option 2: Install-Module Microsoft.Online.SharePoint.PowerShell; Connect-SPOService -Url https://<tenant>-admin.sharepoint.com.' `
            -Impact 'No SharePoint Online or OneDrive sharing configuration assessment data can be collected.' `
            -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' -AutoFixAvailable 'No' -RemediationPriority 'P1'))
        return $findings.ToArray()
    }

    # Helper: retrieve a setting from Graph response or SPO tenant fallback
    # Graph field names use camelCase; SPO uses PascalCase
    function Get-SpoValue {
        param([string]$GraphField, [string]$SpoField)
        if ($spoSettings -and $null -ne $spoSettings[$GraphField]) { return $spoSettings[$GraphField] }
        if ($spoTenant -and $null -ne $spoTenant.$SpoField)        { return $spoTenant.$SpoField }
        return $null
    }

    # =========================================================================
    # COL-SEC-001 — SharePoint and OneDrive External Sharing Level
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "COL-SEC-001: Checking external sharing level"

        # Graph: sharingCapability values: disabled, existingExternalUserSharingOnly,
        #        externalUserSharingOnly, externalUserAndGuestSharing
        # SPO:   SharingCapability: Disabled(0), ExistingExternalUserSharingOnly(1),
        #        ExternalUserAndGuestSharing(2), ExternalUserSharingOnly(3)
        $sharingCap = Get-SpoValue -GraphField 'sharingCapability' -SpoField 'SharingCapability'

        if ($null -eq $sharingCap) {
            $findings.Add((New-TtcFinding `
                -FindingId 'COL-SEC-001' -Workload 'Collaboration' -Component 'ExternalSharing' `
                -CheckName 'SharePoint and OneDrive External Sharing Level' -Category 'Security' -Severity 'High' `
                -Status 'Error' -IssueDetected 'Could not retrieve SharePoint sharing capability setting.' `
                -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant'))
        }
        else {
            # Normalize Graph string and SPO enum to a string for comparison
            $capString = "$sharingCap".ToLower()

            if ($capString -in @('externaluserandguestsharing', '2')) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-001' -Workload 'Collaboration' -Component 'ExternalSharing' `
                    -CheckName 'SharePoint and OneDrive External Sharing Level' -Category 'Security' -Severity 'High' `
                    -Status 'Fail' `
                    -IssueDetected "External sharing is set to 'Anyone' (ExternalUserAndGuestSharing) — unauthenticated anonymous sharing is permitted at the tenant level." `
                    -Explanation 'The most permissive sharing level allows any user to create shareable links that anyone on the internet can open without authentication. This exposes shared files to anyone who obtains the link, including via email forwarding, search engine indexing, or unintended link disclosure.' `
                    -PossibleSolution 'Reduce sharing to ExternalUserSharingOnly (authenticated guests only) or ExistingExternalUserSharingOnly (only previously added guests). In SharePoint admin center: Sharing > External sharing > change both SPO and ODB sliders. Or: Set-SPOTenant -SharingCapability ExternalUserSharingOnly.' `
                    -Impact 'Files shared with Anyone links are accessible to the entire internet without any authentication. A leaked or forwarded link provides permanent, anonymous access to potentially sensitive business documents.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Review SharePoint Online external sharing settings' `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Remediation 'SharePoint admin center: admin.microsoft.com > SharePoint > Policies > Sharing > External sharing. Set both SharePoint and OneDrive sliders to "New and existing guests" or "Existing guests only". Or PowerShell: Set-SPOTenant -SharingCapability ExternalUserSharingOnly. Also review site-level sharing overrides: Get-SPOSite -Filter "SharingCapability -ne 2" or via SharePoint admin center > Sites > Active sites.' `
                    -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                    -Notes "SharingCapability: $sharingCap"))
            }
            elseif ($capString -in @('externalusersharingonly', '3')) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-001' -Workload 'Collaboration' -Component 'ExternalSharing' `
                    -CheckName 'SharePoint and OneDrive External Sharing Level' -Category 'Security' -Severity 'High' `
                    -Status 'Warning' `
                    -IssueDetected "External sharing allows new guest invitations (ExternalUserSharingOnly) — new external users can be added as guests." `
                    -Explanation 'This level allows sharing with new external users who must authenticate with a Microsoft account or one-time passcode. No anonymous access is permitted. This is an acceptable baseline for many organizations but consider restricting to existing guests only if the guest roster is stable.' `
                    -PossibleSolution 'Consider restricting to ExistingExternalUserSharingOnly if you want to prevent new guest invitations without explicit admin approval. Monitor guest additions via Entra ID Guest Access Reviews.' `
                    -Impact 'Any user can invite new external guests to access SharePoint content without IT approval. Uncontrolled guest invitations can accumulate over time, increasing the external access footprint.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Review SharePoint Online external sharing settings' `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Remediation 'To require admin approval for new guests: Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly. Implement Entra ID Access Reviews for guest accounts: Entra admin center > Identity Governance > Access Reviews. Establish a guest lifecycle management process.' `
                    -AutoFixAvailable 'Partial' -RemediationPriority 'P3' `
                    -Notes "SharingCapability: $sharingCap"))
            }
            elseif ($capString -in @('existingexternalusersharingonly', '1')) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-001' -Workload 'Collaboration' -Component 'ExternalSharing' `
                    -CheckName 'SharePoint and OneDrive External Sharing Level' -Category 'Security' -Severity 'High' `
                    -Status 'Pass' `
                    -IssueDetected "External sharing is restricted to existing guests only (ExistingExternalUserSharingOnly) — no new guest invitations or anonymous links." `
                    -Explanation 'This is the recommended setting for most organizations. Only already-provisioned guests can be shared content with, preventing uncontrolled expansion of the external user population.' `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Notes "SharingCapability: $sharingCap"))
            }
            else {
                # Disabled or unknown
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-001' -Workload 'Collaboration' -Component 'ExternalSharing' `
                    -CheckName 'SharePoint and OneDrive External Sharing Level' -Category 'Security' -Severity 'High' `
                    -Status 'Pass' `
                    -IssueDetected "External sharing is disabled or fully restricted (SharingCapability: $sharingCap)." `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Notes "SharingCapability: $sharingCap"))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "COL-SEC-001: External sharing level check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'COL-SEC-001' -Workload 'Collaboration' -Component 'ExternalSharing' `
            -CheckName 'SharePoint and OneDrive External Sharing Level' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # COL-SEC-002 — Anonymous Link Expiration Policy
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "COL-SEC-002: Checking anonymous link expiration policy"

        # requireAnonymousLinksExpireInDays: -1 or 0 = no expiry, positive = days
        $anonExpireDays = Get-SpoValue -GraphField 'requireAnonymousLinksExpireInDays' -SpoField 'RequireAnonymousLinksExpireInDays'
        $sharingCap     = Get-SpoValue -GraphField 'sharingCapability' -SpoField 'SharingCapability'
        $capString      = "$sharingCap".ToLower()

        # Only relevant if anonymous sharing is enabled
        if ($capString -notin @('externaluserandguestsharing', '2')) {
            $findings.Add((New-TtcFinding `
                -FindingId 'COL-SEC-002' -Workload 'Collaboration' -Component 'AnonymousLinks' `
                -CheckName 'Anonymous Link Expiration Policy' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected 'Anonymous (Anyone) sharing links are not permitted at the tenant level — anonymous link expiration is not applicable.' `
                -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                -Notes "SharingCapability: $sharingCap — anonymous links disabled"))
        }
        elseif ($null -eq $anonExpireDays) {
            $findings.Add((New-TtcFinding `
                -FindingId 'COL-SEC-002' -Workload 'Collaboration' -Component 'AnonymousLinks' `
                -CheckName 'Anonymous Link Expiration Policy' -Category 'Security' -Severity 'High' `
                -Status 'Error' -IssueDetected 'Could not retrieve anonymous link expiration setting.' `
                -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant'))
        }
        else {
            $expireDaysInt = [int]$anonExpireDays

            if ($expireDaysInt -le 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-002' -Workload 'Collaboration' -Component 'AnonymousLinks' `
                    -CheckName 'Anonymous Link Expiration Policy' -Category 'Security' -Severity 'High' `
                    -Status 'Fail' `
                    -IssueDetected 'Anonymous (Anyone) sharing links have NO expiration — they remain valid indefinitely after creation.' `
                    -Explanation 'Anonymous links allow any internet user to access shared files without authentication. When these links have no expiration date, they persist forever even if the sharing was intended to be temporary. Leaked or forwarded links provide permanent access.' `
                    -PossibleSolution "Set a maximum expiration: Set-SPOTenant -RequireAnonymousLinksExpireInDays $AnonymousLinkMaxExpirationDays. Or in SharePoint admin center: Sharing > Advanced settings for anonymous links > set expiration." `
                    -Impact 'Anonymous links created by users remain active indefinitely, providing permanent access even after a collaboration ends, a project closes, or a file contains outdated (but sensitive) information.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Set expiration date for Anyone links' `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Remediation "Set-SPOTenant -RequireAnonymousLinksExpireInDays $AnonymousLinkMaxExpirationDays. This forces all new Anyone links to expire within the specified days. Existing links without expiration are not retroactively expired — review and update high-sensitivity site sharing via SharePoint admin center. Or via Graph: PATCH /v1.0/admin/sharepoint/settings {requireAnonymousLinksExpireInDays: $AnonymousLinkMaxExpirationDays}." `
                    -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                    -Notes "RequireAnonymousLinksExpireInDays: $anonExpireDays (0 or -1 = no expiry)"))
            }
            elseif ($expireDaysInt -gt $AnonymousLinkMaxExpirationDays) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-002' -Workload 'Collaboration' -Component 'AnonymousLinks' `
                    -CheckName 'Anonymous Link Expiration Policy' -Category 'Security' -Severity 'High' `
                    -Status 'Warning' `
                    -IssueDetected "Anonymous links expire after $expireDaysInt days — exceeds the recommended maximum of $AnonymousLinkMaxExpirationDays days." `
                    -Explanation 'While expiration is configured, the current value is longer than recommended. Anonymous links should expire within a short timeframe to limit the window of exposure if a link is leaked or forwarded to unintended recipients.' `
                    -PossibleSolution "Reduce expiration: Set-SPOTenant -RequireAnonymousLinksExpireInDays $AnonymousLinkMaxExpirationDays." `
                    -Impact 'Anonymous links created today will remain valid for an extended period. If a link is disclosed unintentionally, it provides access for up to the full expiration duration.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Set expiration date for Anyone links' `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Remediation "Set-SPOTenant -RequireAnonymousLinksExpireInDays $AnonymousLinkMaxExpirationDays." `
                    -AutoFixAvailable 'Partial' -RemediationPriority 'P3' `
                    -Notes "RequireAnonymousLinksExpireInDays: $anonExpireDays | Threshold: $AnonymousLinkMaxExpirationDays"))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-002' -Workload 'Collaboration' -Component 'AnonymousLinks' `
                    -CheckName 'Anonymous Link Expiration Policy' -Category 'Security' -Severity 'High' `
                    -Status 'Pass' `
                    -IssueDetected "Anonymous links expire after $expireDaysInt days — within the $AnonymousLinkMaxExpirationDays-day threshold." `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Notes "RequireAnonymousLinksExpireInDays: $anonExpireDays"))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "COL-SEC-002: Anonymous link expiration check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'COL-SEC-002' -Workload 'Collaboration' -Component 'AnonymousLinks' `
            -CheckName 'Anonymous Link Expiration Policy' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # COL-SEC-003 — External Guest Link Expiration Policy
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "COL-SEC-003: Checking external guest link expiration policy"

        $guestExpiryRequired = Get-SpoValue -GraphField 'externalUserExpirationRequired' -SpoField 'ExternalUserExpirationRequired'
        $guestExpireDays     = Get-SpoValue -GraphField 'externalUserExpireInDays'        -SpoField 'ExternalUserExpireInDays'

        if ($null -eq $guestExpiryRequired) {
            $findings.Add((New-TtcFinding `
                -FindingId 'COL-SEC-003' -Workload 'Collaboration' -Component 'GuestLinks' `
                -CheckName 'External Guest Link Expiration Policy' -Category 'Security' -Severity 'Medium' `
                -Status 'Error' -IssueDetected 'Could not retrieve external guest link expiration setting.' `
                -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant'))
        }
        elseif ($guestExpiryRequired -eq $true -or $guestExpiryRequired -eq 'true') {
            $expireDaysInt  = if ($guestExpireDays) { [int]$guestExpireDays } else { 0 }
            $expireDesc     = if ($expireDaysInt -gt 0) { "$expireDaysInt days" } else { 'configured' }

            if ($expireDaysInt -gt $GuestLinkMaxExpirationDays) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-003' -Workload 'Collaboration' -Component 'GuestLinks' `
                    -CheckName 'External Guest Link Expiration Policy' -Category 'Security' -Severity 'Medium' `
                    -Status 'Warning' `
                    -IssueDetected "Guest sharing link expiration is enabled but set to $expireDaysInt days — exceeds the recommended $GuestLinkMaxExpirationDays days." `
                    -Explanation 'Guest link expiration is configured but the duration is longer than recommended. External users retain access for the full duration after a sharing event, even if the business need has ended.' `
                    -PossibleSolution "Consider reducing to $GuestLinkMaxExpirationDays days: Set-SPOTenant -ExternalUserExpirationRequired $true -ExternalUserExpireInDays $GuestLinkMaxExpirationDays." `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Remediation "Set-SPOTenant -ExternalUserExpirationRequired $true -ExternalUserExpireInDays $GuestLinkMaxExpirationDays." `
                    -AutoFixAvailable 'Partial' -RemediationPriority 'P4' `
                    -Notes "ExternalUserExpirationRequired: $guestExpiryRequired | ExternalUserExpireInDays: $guestExpireDays"))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-003' -Workload 'Collaboration' -Component 'GuestLinks' `
                    -CheckName 'External Guest Link Expiration Policy' -Category 'Security' -Severity 'Medium' `
                    -Status 'Pass' `
                    -IssueDetected "External guest link expiration is enabled at $expireDesc — within the $GuestLinkMaxExpirationDays-day threshold." `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Notes "ExternalUserExpirationRequired: $guestExpiryRequired | ExternalUserExpireInDays: $guestExpireDays"))
            }
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'COL-SEC-003' -Workload 'Collaboration' -Component 'GuestLinks' `
                -CheckName 'External Guest Link Expiration Policy' -Category 'Security' -Severity 'Medium' `
                -Status 'Fail' `
                -IssueDetected 'External guest sharing links do NOT expire — former collaborators and external guests retain indefinite access to shared content.' `
                -Explanation 'When guest sharing links have no expiration, external users who were shared content continue to have access indefinitely even after the collaboration has ended, the project has closed, or employment at the partner organization has terminated. This creates an expanding, unmanaged external access footprint.' `
                -PossibleSolution "Enable expiration: Set-SPOTenant -ExternalUserExpirationRequired $true -ExternalUserExpireInDays $GuestLinkMaxExpirationDays. In SharePoint admin center: Sharing > Additional settings > Guest access link expiration." `
                -Impact 'External users accumulate persistent access to SharePoint content. Former employees of partner organizations, contractors, or auditors retain access indefinitely. Access is not revoked when the business relationship ends unless manually reviewed.' `
                -FrameworkMapping 'CIS-AccessControl' -ZeroTrustPillar 'Identity' `
                -SecureScoreMapping 'Set expiration date for external sharing links' `
                -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                -Remediation "Enable and set: Set-SPOTenant -ExternalUserExpirationRequired $true -ExternalUserExpireInDays $GuestLinkMaxExpirationDays. Perform a one-time audit of current guest access: Get-SPOExternalUser -SiteUrl <url> for each site collection. Run Access Reviews in Entra ID for guest accounts: Entra admin center > Identity Governance > Access Reviews." `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P3' `
                -Notes "ExternalUserExpirationRequired: $guestExpiryRequired | ExternalUserExpireInDays: $guestExpireDays"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "COL-SEC-003: Guest link expiration check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'COL-SEC-003' -Workload 'Collaboration' -Component 'GuestLinks' `
            -CheckName 'External Guest Link Expiration Policy' -Category 'Security' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # COL-SEC-004 — Default Sharing Link Scope
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "COL-SEC-004: Checking default sharing link scope"

        # Graph: defaultSharingLinkType: none, direct, internal, anonymous
        # SPO:   DefaultSharingLinkType: None(0), Direct(1), Internal(2), AnonymousAccess(3)
        $defaultLink = Get-SpoValue -GraphField 'defaultSharingLinkType' -SpoField 'DefaultSharingLinkType'

        if ($null -eq $defaultLink) {
            $findings.Add((New-TtcFinding `
                -FindingId 'COL-SEC-004' -Workload 'Collaboration' -Component 'SharingLinks' `
                -CheckName 'Default Sharing Link Scope' -Category 'Security' -Severity 'Medium' `
                -Status 'Error' -IssueDetected 'Could not retrieve default sharing link type setting.' `
                -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant'))
        }
        else {
            $linkString = "$defaultLink".ToLower()

            if ($linkString -in @('anonymous', 'anonymousaccess', '3')) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-004' -Workload 'Collaboration' -Component 'SharingLinks' `
                    -CheckName 'Default Sharing Link Scope' -Category 'Security' -Severity 'Medium' `
                    -Status 'Fail' `
                    -IssueDetected "Default sharing link type is 'Anyone' (anonymous) — users are nudged toward anonymous sharing by default." `
                    -Explanation 'The default sharing link type is the option pre-selected when a user clicks "Share" in SharePoint or OneDrive. When set to Anonymous, users are most likely to create anonymous links by default, even when authenticated sharing would be sufficient. Most users accept the default without changing it.' `
                    -PossibleSolution "Change to specific people (most secure): Set-SPOTenant -DefaultSharingLinkType Direct. Or organization-wide: Set-SPOTenant -DefaultSharingLinkType Internal." `
                    -Impact 'Users creating shares with the default option produce anonymous links. This makes anonymous sharing the path of least resistance, increasing the volume of anonymous links in the environment and the associated data exposure risk.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Set default sharing link scope to specific people' `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Remediation 'Set-SPOTenant -DefaultSharingLinkType Direct (specific people — recommended). Or Internal (all org members). Direct requires the sharing recipient to authenticate. Changing this does not affect existing links — only new shares created after the change. Communicate the change to users to set expectations.' `
                    -AutoFixAvailable 'Partial' -RemediationPriority 'P3' `
                    -Notes "DefaultSharingLinkType: $defaultLink"))
            }
            elseif ($linkString -in @('internal', '2')) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-004' -Workload 'Collaboration' -Component 'SharingLinks' `
                    -CheckName 'Default Sharing Link Scope' -Category 'Security' -Severity 'Medium' `
                    -Status 'Warning' `
                    -IssueDetected "Default sharing link type is 'People in your organization' (internal) — sharing defaults to org-wide access rather than specific recipients." `
                    -Explanation 'When the default link type is Internal (org-wide), users who share files with specific individuals create links accessible by the entire organization by default. Users often accept the default without adjusting scope, resulting in unintentionally broad internal access.' `
                    -PossibleSolution "Change to specific people for least-privilege sharing: Set-SPOTenant -DefaultSharingLinkType Direct." `
                    -Impact 'Files shared internally default to organization-wide access rather than being scoped to the intended recipient. Confidential documents shared with specific colleagues may be accessible to the entire tenant.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Set default sharing link scope to specific people' `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Remediation 'Set-SPOTenant -DefaultSharingLinkType Direct. This sets the pre-selected link type to "Specific people" in all SharePoint and OneDrive share dialogs, prompting users to enter explicit recipients.' `
                    -AutoFixAvailable 'Partial' -RemediationPriority 'P4' `
                    -Notes "DefaultSharingLinkType: $defaultLink"))
            }
            elseif ($linkString -in @('direct', '1')) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-004' -Workload 'Collaboration' -Component 'SharingLinks' `
                    -CheckName 'Default Sharing Link Scope' -Category 'Security' -Severity 'Medium' `
                    -Status 'Pass' `
                    -IssueDetected "Default sharing link type is 'Specific people' (direct) — the least-privilege default is configured." `
                    -Explanation 'Specific people links require the sharing user to explicitly name recipients, enforcing deliberate access decisions and preventing accidental broad sharing.' `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Notes "DefaultSharingLinkType: $defaultLink"))
            }
            else {
                # None = prompts user to choose — acceptable
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-SEC-004' -Workload 'Collaboration' -Component 'SharingLinks' `
                    -CheckName 'Default Sharing Link Scope' -Category 'Security' -Severity 'Medium' `
                    -Status 'Pass' `
                    -IssueDetected "Default sharing link type is 'None' (prompts user to choose) or direct — no insecure default is pre-selected." `
                    -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' `
                    -Notes "DefaultSharingLinkType: $defaultLink"))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "COL-SEC-004: Default sharing link check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'COL-SEC-004' -Workload 'Collaboration' -Component 'SharingLinks' `
            -CheckName 'Default Sharing Link Scope' -Category 'Security' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Invoke-MgGraphRequest;Get-SPOTenant' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # COL-GOV-001 — Microsoft 365 Groups Guest Access Policy
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "COL-GOV-001: Checking M365 Groups guest access directory settings"

        if (-not $graphAvailable) {
            $findings.Add((New-TtcFinding `
                -FindingId 'COL-GOV-001' -Workload 'Collaboration' -Component 'GroupsGuest' `
                -CheckName 'Microsoft 365 Groups Guest Access Policy' -Category 'Governance' -Severity 'Medium' `
                -Status 'NotAssessed' -IssueDetected 'Graph not connected — M365 Groups guest settings check skipped.' `
                -DataSource 'Get-MgDirectorySetting'))
        }
        else {
            $dirSettings = Get-MgDirectorySetting -ErrorAction Stop
            $groupUnified = $dirSettings | Where-Object { $_.DisplayName -eq 'Group.Unified' } | Select-Object -First 1

            if (-not $groupUnified) {
                # No Group.Unified setting = defaults apply (guests allowed by default)
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-GOV-001' -Workload 'Collaboration' -Component 'GroupsGuest' `
                    -CheckName 'Microsoft 365 Groups Guest Access Policy' -Category 'Governance' -Severity 'Medium' `
                    -Status 'Warning' `
                    -IssueDetected 'No custom Group.Unified directory settings found — M365 Groups are operating with defaults (guests allowed in all groups).' `
                    -Explanation 'Without a custom Group.Unified directory setting, Microsoft 365 Groups allow guest access by default. This means any member can add guests to any group (and the associated Teams, SharePoint site, and Planner) without restriction.' `
                    -PossibleSolution 'Create a Group.Unified policy: $template = Get-MgDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified" }; $setting = New-MgDirectorySetting -TemplateId $template.Id -Values $template.Values. Then configure AllowGuestsToAccessGroups and AllowToAddGuests as appropriate.' `
                    -Impact 'Without explicit policy, guest access to all groups is permitted by default. There is no centralized control over which groups allow guests — each group owner controls this independently.' `
                    -FrameworkMapping 'ISO27001-A.9' -ZeroTrustPillar 'Identity' `
                    -DataSource 'Get-MgDirectorySetting' `
                    -Remediation 'Create Group.Unified policy with controlled guest access: $t = Get-MgDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified" }; $setting = New-MgDirectorySetting -TemplateId $t.Id -Values $t.Values; then use Update-MgDirectorySetting to set AllowGuestsToAccessGroups and AllowToAddGuests to $false to block guest access, or leave as $true with other controls.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                    -Notes 'Group.Unified directory setting not found — Microsoft defaults apply'))
            }
            else {
                $values = $groupUnified.Values
                $allowGuestsAccess = ($values | Where-Object { $_.Name -eq 'AllowGuestsToAccessGroups' }).Value
                $allowAddGuests    = ($values | Where-Object { $_.Name -eq 'AllowToAddGuests' }).Value
                $notes = "AllowGuestsToAccessGroups: $allowGuestsAccess | AllowToAddGuests: $allowAddGuests"

                if ($allowGuestsAccess -eq 'false' -and $allowAddGuests -eq 'false') {
                    $findings.Add((New-TtcFinding `
                        -FindingId 'COL-GOV-001' -Workload 'Collaboration' -Component 'GroupsGuest' `
                        -CheckName 'Microsoft 365 Groups Guest Access Policy' -Category 'Governance' -Severity 'Medium' `
                        -Status 'Pass' `
                        -IssueDetected 'Guest access to Microsoft 365 Groups is disabled — guests cannot access or be added to groups.' `
                        -DataSource 'Get-MgDirectorySetting' `
                        -Notes $notes))
                }
                elseif ($allowAddGuests -eq 'true' -and $allowGuestsAccess -eq 'true') {
                    $findings.Add((New-TtcFinding `
                        -FindingId 'COL-GOV-001' -Workload 'Collaboration' -Component 'GroupsGuest' `
                        -CheckName 'Microsoft 365 Groups Guest Access Policy' -Category 'Governance' -Severity 'Medium' `
                        -Status 'Warning' `
                        -IssueDetected 'Guest users can be added to any M365 Group and can access group content — review whether this is intentional.' `
                        -Explanation 'With AllowToAddGuests = true, group owners can add external users to any Microsoft 365 Group, giving them access to the group mailbox, SharePoint site, Teams workspace, and Planner. Ensure this is governed by a guest lifecycle management process.' `
                        -PossibleSolution 'If stricter control is needed: restrict guest additions to specific groups using Entra ID sensitivity labels on groups. Or set AllowToAddGuests = false at tenant level and enable per-group as needed.' `
                        -Impact 'All group owners can independently add guests to their groups without IT approval. Combined with SharePoint content in those groups, this can expose sensitive data broadly to external parties.' `
                        -FrameworkMapping 'ISO27001-A.9' -ZeroTrustPillar 'Identity' `
                        -DataSource 'Get-MgDirectorySetting' `
                        -Remediation 'Implement guest lifecycle management: run quarterly Entra ID Access Reviews for groups with guests. Consider using Entra ID sensitivity labels on groups to restrict which groups can have guests. Set GuestUsageGuidelinesUrl in Group.Unified settings to direct users to your guest policy.' `
                        -AutoFixAvailable 'No' -RemediationPriority 'P4' `
                        -Notes $notes))
                }
                else {
                    $findings.Add((New-TtcFinding `
                        -FindingId 'COL-GOV-001' -Workload 'Collaboration' -Component 'GroupsGuest' `
                        -CheckName 'Microsoft 365 Groups Guest Access Policy' -Category 'Governance' -Severity 'Medium' `
                        -Status 'Pass' `
                        -IssueDetected "M365 Groups guest policy is configured with partial restrictions." `
                        -DataSource 'Get-MgDirectorySetting' `
                        -Notes $notes))
                }
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "COL-GOV-001: Groups guest policy check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'COL-GOV-001' -Workload 'Collaboration' -Component 'GroupsGuest' `
            -CheckName 'Microsoft 365 Groups Guest Access Policy' -Category 'Governance' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-MgDirectorySetting' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # COL-GOV-002 — Sensitivity Labels Published to Users
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "COL-GOV-002: Checking sensitivity label deployment"

        if (-not $graphAvailable) {
            $findings.Add((New-TtcFinding `
                -FindingId 'COL-GOV-002' -Workload 'Collaboration' -Component 'SensitivityLabels' `
                -CheckName 'Sensitivity Labels Published to Users' -Category 'Governance' -Severity 'Medium' `
                -Status 'NotAssessed' -IssueDetected 'Graph not connected — sensitivity label check skipped.' `
                -DataSource 'Invoke-MgGraphRequest (beta informationProtection)'))
        }
        else {
            $labelsResponse = $null
            try {
                $labelsResponse = Invoke-MgGraphRequest -Method GET `
                    -Uri 'https://graph.microsoft.com/beta/informationProtection/policy/labels' `
                    -ErrorAction Stop
            }
            catch {
                Write-TtcLog -Level Warning -Message "Sensitivity labels endpoint unavailable (needs InformationProtectionPolicy.Read): $($_.Exception.Message)"
            }

            if ($labelsResponse -and $labelsResponse.value) {
                $labelCount = ($labelsResponse.value | Measure-Object).Count
                $labelNames = ($labelsResponse.value | Select-Object -First 10 | ForEach-Object { $_.name }) -join '; '

                if ($labelCount -gt 0) {
                    $findings.Add((New-TtcFinding `
                        -FindingId 'COL-GOV-002' -Workload 'Collaboration' -Component 'SensitivityLabels' `
                        -CheckName 'Sensitivity Labels Published to Users' -Category 'Governance' -Severity 'Medium' `
                        -Status 'Pass' `
                        -IssueDetected "$labelCount sensitivity label(s) found — Microsoft Purview data classification is deployed." `
                        -Explanation 'Sensitivity labels allow users and administrators to classify documents and emails, applying protection (encryption, access restrictions, visual markings) based on data sensitivity. Published labels enable a data classification culture across the organization.' `
                        -DataSource 'Invoke-MgGraphRequest (beta informationProtection)' `
                        -Notes "Labels ($labelCount): $labelNames"))
                }
                else {
                    $findings.Add((New-TtcFinding `
                        -FindingId 'COL-GOV-002' -Workload 'Collaboration' -Component 'SensitivityLabels' `
                        -CheckName 'Sensitivity Labels Published to Users' -Category 'Governance' -Severity 'Medium' `
                        -Status 'Fail' `
                        -IssueDetected 'No sensitivity labels are published — Microsoft Purview data classification is not deployed.' `
                        -Explanation 'Sensitivity labels enable data classification and protection for files, emails, and Teams. Without labels, users have no standardized way to classify sensitive data, and automated protection policies (encryption, DLP, Conditional Access) cannot be scoped to data sensitivity levels.' `
                        -PossibleSolution 'Create and publish sensitivity labels in the Microsoft Purview compliance portal: compliance.microsoft.com > Information protection > Labels. Start with a basic taxonomy (Public, Internal, Confidential, Highly Confidential) and publish to all users.' `
                        -Impact 'No data classification framework is in place. Sensitive documents (customer data, financial records, IP) are handled without protection policies. DLP and Conditional Access cannot target sensitive data by classification.' `
                        -FrameworkMapping 'ISO27001-A.18' -ZeroTrustPillar 'Data' `
                        -SecureScoreMapping 'Enable Microsoft Purview sensitivity labels' `
                        -DataSource 'Invoke-MgGraphRequest (beta informationProtection)' `
                        -Remediation 'Create labels: compliance.microsoft.com > Information protection > Labels > + Create a label. Define a hierarchy (e.g., Public > Internal > Confidential > Highly Confidential). Publish via label policy: Information protection > Label policies > + Publish labels. Target all users. Enable mandatory labeling for documents. Consider auto-labeling for sensitive content types (credit card, SSN, health data).' `
                        -AutoFixAvailable 'No' -RemediationPriority 'P3'))
                }
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-GOV-002' -Workload 'Collaboration' -Component 'SensitivityLabels' `
                    -CheckName 'Sensitivity Labels Published to Users' -Category 'Governance' -Severity 'Medium' `
                    -Status 'NotAssessed' `
                    -IssueDetected 'Sensitivity labels endpoint not accessible — Graph scope InformationProtectionPolicy.Read may not be granted.' `
                    -PossibleSolution 'Re-connect with scope: Connect-MgGraph -Scopes "InformationProtectionPolicy.Read".' `
                    -DataSource 'Invoke-MgGraphRequest (beta informationProtection)'))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "COL-GOV-002: Sensitivity labels check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'COL-GOV-002' -Workload 'Collaboration' -Component 'SensitivityLabels' `
            -CheckName 'Sensitivity Labels Published to Users' -Category 'Governance' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Invoke-MgGraphRequest (beta informationProtection)' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # COL-GOV-003 — Microsoft Purview Retention Policy Coverage
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "COL-GOV-003: Checking Microsoft Purview retention policy coverage"

        # Retention policies require Security & Compliance PowerShell (Get-RetentionCompliancePolicy)
        $retentionCmdletAvailable = [bool](Get-Command -Name 'Get-RetentionCompliancePolicy' -ErrorAction SilentlyContinue)

        if (-not $retentionCmdletAvailable) {
            $findings.Add((New-TtcFinding `
                -FindingId 'COL-GOV-003' -Workload 'Collaboration' -Component 'Retention' `
                -CheckName 'Microsoft Purview Retention Policy Coverage' -Category 'Governance' -Severity 'Medium' `
                -Status 'NotAssessed' `
                -IssueDetected 'Get-RetentionCompliancePolicy cmdlet not available — Security and Compliance PowerShell session required.' `
                -Explanation 'Retention policy data requires a connection to the Microsoft Purview Security and Compliance center. This is separate from the Exchange Online session.' `
                -PossibleSolution 'Connect to Security & Compliance PowerShell: Connect-IPPSSession. This is part of the ExchangeOnlineManagement module v2+. After connecting, re-run the Collaboration assessment or check retention policies directly: Get-RetentionCompliancePolicy.' `
                -Impact 'Retention policy coverage cannot be assessed without an IPPS session. Retention policies ensure data is preserved for the required period and deleted when no longer needed, supporting compliance and e-discovery.' `
                -FrameworkMapping 'ISO27001-A.18' -ZeroTrustPillar 'Data' `
                -DataSource 'Get-RetentionCompliancePolicy' -AutoFixAvailable 'No' -RemediationPriority 'P4'))
        }
        else {
            $retentionPolicies = Get-RetentionCompliancePolicy -ErrorAction Stop
            $policyCount       = ($retentionPolicies | Measure-Object).Count
            $enabledPolicies   = $retentionPolicies | Where-Object { $_.Enabled -eq $true }
            $enabledCount      = ($enabledPolicies | Measure-Object).Count

            # Check for workload coverage: Exchange, SharePoint, Teams, OneDrive
            $workloadsCovered  = [System.Collections.Generic.List[string]]::new()
            $workloadsMissing  = [System.Collections.Generic.List[string]]::new()

            $workloadChecks = @{
                'Exchange Online'   = 'ExchangeLocation'
                'SharePoint Online' = 'SharePointLocation'
                'OneDrive'          = 'OneDriveLocation'
                'Teams'             = 'TeamsLocation'
            }

            foreach ($wlName in $workloadChecks.Keys) {
                $locationProp = $workloadChecks[$wlName]
                $covered = $enabledPolicies | Where-Object {
                    $loc = $_.$locationProp
                    $loc -and ($loc.Count -gt 0 -or $loc -eq 'All')
                }
                if (($covered | Measure-Object).Count -gt 0) {
                    $workloadsCovered.Add($wlName)
                }
                else {
                    $workloadsMissing.Add($wlName)
                }
            }

            $notes = "Total policies: $policyCount | Enabled: $enabledCount | Covered: $($workloadsCovered -join ', ') | Missing: $($workloadsMissing -join ', ')"

            if ($policyCount -eq 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-GOV-003' -Workload 'Collaboration' -Component 'Retention' `
                    -CheckName 'Microsoft Purview Retention Policy Coverage' -Category 'Governance' -Severity 'Medium' `
                    -Status 'Fail' `
                    -IssueDetected 'No Microsoft Purview retention policies found — data lifecycle is unmanaged.' `
                    -Explanation 'Retention policies define how long data is kept and when it is automatically deleted. Without them, data accumulates indefinitely (creating storage, e-discovery, and privacy risk) or is deleted without an auditable process (creating compliance gaps for regulated data).' `
                    -PossibleSolution 'Create retention policies in the Microsoft Purview compliance portal: compliance.microsoft.com > Data lifecycle management > Retention policies. Create policies for: Exchange email (e.g., 7 years), SharePoint/OneDrive documents, Teams messages.' `
                    -Impact 'No data governance for retention or deletion. Regulatory data (financial records, health data, HR records) may not be retained for required periods. Personal data may be retained longer than necessary (GDPR risk). E-discovery scope is unlimited.' `
                    -FrameworkMapping 'ISO27001-A.18' -ZeroTrustPillar 'Data' `
                    -DataSource 'Get-RetentionCompliancePolicy' `
                    -Remediation 'Create in compliance.microsoft.com > Data lifecycle management > Retention policies > + New retention policy. Scope to Exchange, SharePoint, OneDrive, and Teams. Set retention period based on regulatory requirements (e.g., financial records = 7 years, HR records = varies by jurisdiction). Consider default delete policy for unclassified data after N years to control storage and privacy obligations.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P3'))
            }
            elseif ($workloadsMissing.Count -gt 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-GOV-003' -Workload 'Collaboration' -Component 'Retention' `
                    -CheckName 'Microsoft Purview Retention Policy Coverage' -Category 'Governance' -Severity 'Medium' `
                    -Status 'Warning' `
                    -IssueDetected "$($workloadsMissing.Count) workload(s) have no retention policy coverage: $($workloadsMissing -join ', ')." `
                    -Explanation 'Retention policies exist for some workloads but not all. Data in uncovered workloads is not subject to retention or deletion rules, creating compliance gaps for regulated industries and inconsistent data lifecycle management.' `
                    -PossibleSolution 'Create additional retention policies for uncovered workloads in compliance.microsoft.com > Data lifecycle management > Retention policies. Ensure Teams messages and OneDrive data are included if not already covered.' `
                    -Impact 'Data in uncovered services is either retained indefinitely (storage and privacy risk) or deleted without policy (compliance risk). Inconsistent coverage weakens e-discovery and audit defensibility.' `
                    -FrameworkMapping 'ISO27001-A.18' -ZeroTrustPillar 'Data' `
                    -DataSource 'Get-RetentionCompliancePolicy' `
                    -Remediation 'For each uncovered workload, create a dedicated retention policy or update an existing policy to include the missing location. Teams requires a separate Teams retention policy (not a standard retention policy). OneDrive can be included in SharePoint policies or dedicated ODB policies.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                    -Notes $notes))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-GOV-003' -Workload 'Collaboration' -Component 'Retention' `
                    -CheckName 'Microsoft Purview Retention Policy Coverage' -Category 'Governance' -Severity 'Medium' `
                    -Status 'Pass' `
                    -IssueDetected "$enabledCount enabled retention policy/policies covering Exchange, SharePoint, OneDrive, and Teams." `
                    -DataSource 'Get-RetentionCompliancePolicy' `
                    -Notes $notes))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "COL-GOV-003: Retention policy check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'COL-GOV-003' -Workload 'Collaboration' -Component 'Retention' `
            -CheckName 'Microsoft Purview Retention Policy Coverage' -Category 'Governance' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-RetentionCompliancePolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # COL-GOV-004 — Teams External and Guest Access Configuration
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "COL-GOV-004: Checking Teams external and guest access configuration"

        # Probe for MicrosoftTeams module
        $teamsAvailable = $false
        try {
            if (Get-Module -Name MicrosoftTeams -ListAvailable -ErrorAction SilentlyContinue) {
                Import-Module MicrosoftTeams -ErrorAction Stop
                # Validate connection by running a cmdlet
                Get-CsTenantFederationConfiguration -ErrorAction Stop | Out-Null
                $teamsAvailable = $true
                Write-TtcLog -Level Info -Message "MicrosoftTeams module available and connected"
            }
        }
        catch {
            Write-TtcLog -Level Warning -Message "MicrosoftTeams module unavailable or not connected: $($_.Exception.Message)"
        }

        if (-not $teamsAvailable) {
            $findings.Add((New-TtcFinding `
                -FindingId 'COL-GOV-004' -Workload 'Collaboration' -Component 'TeamsAccess' `
                -CheckName 'Teams External and Guest Access Configuration' -Category 'Governance' -Severity 'Medium' `
                -Status 'NotAssessed' `
                -IssueDetected 'MicrosoftTeams PowerShell module not available or Connect-MicrosoftTeams not established — Teams access configuration check skipped.' `
                -Explanation 'Teams external access (federation) and guest access configuration requires the MicrosoftTeams PowerShell module. Without it, the assessment cannot evaluate whether Teams communication with external organizations and guests is appropriately controlled.' `
                -PossibleSolution 'Install: Install-Module MicrosoftTeams. Connect: Connect-MicrosoftTeams. Then re-run the Collaboration assessment.' `
                -Impact 'Teams external and guest access configuration is unassessed. Unrestricted external federation allows users to communicate with Teams users from any external organization, and unrestricted guest access allows guests to access Teams channels, files, and meetings.' `
                -DataSource 'Get-CsTenantFederationConfiguration;Get-CsTeamsMeetingPolicy' -AutoFixAvailable 'No' -RemediationPriority 'P4'))
        }
        else {
            $federationConfig = Get-CsTenantFederationConfiguration -ErrorAction Stop
            $guestConfig      = $null
            try {
                $guestConfig = Get-CsTeamsGuestMeetingConfiguration -ErrorAction SilentlyContinue
            }
            catch {
                Write-TtcLog -Level Debug -Message "Get-CsTeamsGuestMeetingConfiguration failed: $_"
            }

            $issues = [System.Collections.Generic.List[string]]::new()

            # External access (federation)
            $allowFederated = $federationConfig.AllowFederatedUsers
            $allowPublic    = $federationConfig.AllowPublicUsers  # Skype/consumer
            $blockedDomains = $federationConfig.BlockedDomains
            $allowedDomains = $federationConfig.AllowedDomains

            # AllowFederatedUsers = $true with no domain restrictions = open federation
            if ($allowFederated -eq $true -and
                ($null -eq $allowedDomains -or ($allowedDomains | Measure-Object).Count -eq 0) -and
                ($null -eq $blockedDomains -or ($blockedDomains | Measure-Object).Count -eq 0)) {
                $issues.Add('Open external federation — users can communicate with Teams users from ANY external organization')
            }

            if ($allowPublic -eq $true) {
                $issues.Add('Consumer accounts (Skype/personal Microsoft accounts) can communicate with Teams users')
            }

            $notes = "AllowFederatedUsers: $allowFederated | AllowPublicUsers: $allowPublic | AllowedDomains: $(($allowedDomains|Measure-Object).Count) | BlockedDomains: $(($blockedDomains|Measure-Object).Count)"

            if ($issues.Count -gt 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-GOV-004' -Workload 'Collaboration' -Component 'TeamsAccess' `
                    -CheckName 'Teams External and Guest Access Configuration' -Category 'Governance' -Severity 'Medium' `
                    -Status 'Warning' `
                    -IssueDetected "$($issues.Count) Teams external access concern(s): $($issues -join '; ')." `
                    -Explanation 'Open Teams federation allows users to initiate chats, calls, and meetings with Teams users at any external organization without restriction. While this enables business collaboration, it also creates a social engineering attack surface — external actors can directly message internal users via Teams.' `
                    -PossibleSolution 'Restrict federation to approved partner domains: Teams admin center > External access > configure allowed/blocked domain list. Disable consumer account access if not needed: Teams admin center > External access > toggle off "Skype users". Document approved external organizations.' `
                    -Impact 'Open federation enables phishing, social engineering, and malicious file sharing directly via Teams from any external organization. Users may receive convincing impersonation messages from external actors who appear as legitimate Teams users.' `
                    -FrameworkMapping 'ISO27001-A.9' -ZeroTrustPillar 'Identity' `
                    -DataSource 'Get-CsTenantFederationConfiguration' `
                    -Remediation 'Teams admin center (admin.teams.microsoft.com) > External access. Switch from "open" to "allow specific domains" or "block specific domains". Add approved partner domains to the allow list. Disable Skype consumer interop: Set-CsTenantFederationConfiguration -AllowPublicUsers $false. Review regularly with business stakeholders to maintain the approved domain list.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                    -Notes $notes))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'COL-GOV-004' -Workload 'Collaboration' -Component 'TeamsAccess' `
                    -CheckName 'Teams External and Guest Access Configuration' -Category 'Governance' -Severity 'Medium' `
                    -Status 'Pass' `
                    -IssueDetected 'Teams external federation is configured with domain restrictions and consumer account access is controlled.' `
                    -DataSource 'Get-CsTenantFederationConfiguration' `
                    -Notes $notes))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "COL-GOV-004: Teams access check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'COL-GOV-004' -Workload 'Collaboration' -Component 'TeamsAccess' `
            -CheckName 'Teams External and Guest Access Configuration' -Category 'Governance' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-CsTenantFederationConfiguration' -Notes $_.Exception.Message))
    }

    Write-TtcLog -Level Info -Message "Collaboration assessment complete — $($findings.Count) finding(s) generated"
    return $findings.ToArray()
}
