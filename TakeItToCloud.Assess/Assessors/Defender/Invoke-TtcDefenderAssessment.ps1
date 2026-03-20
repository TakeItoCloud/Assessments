function Invoke-TtcDefenderAssessment {
    <#
    .SYNOPSIS
        Runs the Microsoft Defender for Office 365 workload assessment.
    .DESCRIPTION
        Performs a comprehensive assessment of Microsoft Defender for Office 365 configuration,
        covering: Safe Links policy coverage, Safe Attachments policy coverage, anti-phishing
        policy configuration, preset security policy adoption, Zero-Hour Auto Purge (ZAP),
        SharePoint/Teams/OneDrive protection, high-severity alert notifications, and compromised
        account alert policy enablement.

        Requires:
        - ExchangeOnlineManagement module v2+ connected via Connect-ExchangeOnline
        - Microsoft Defender for Office 365 Plan 1 or Plan 2 license for DEF-SEC-001, DEF-SEC-002,
          DEF-CFG-001, and DEF-CFG-003 checks. These checks will return NotAssessed if cmdlets
          are unavailable (indicating the license is absent).

        Recommended permissions:
        - Security Reader, OR
        - View-Only Organization Management + Security Administrator (read)
    .EXAMPLE
        Invoke-TtcDefenderAssessment
    .OUTPUTS
        [PSCustomObject[]] Array of TakeItToCloud finding objects.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-TtcLog -Level Info -Message "Starting Defender for Office 365 assessment"

    # =========================================================================
    # Prerequisite: verify Exchange Online connection (Defender cmdlets require EXO session)
    # =========================================================================
    $exoConnected      = $false
    $defenderP1OrAbove = $false

    try {
        $ErrorActionPreference = 'Stop'
        Get-OrganizationConfig -ErrorAction Stop | Out-Null
        $exoConnected = $true
        Write-TtcLog -Level Info -Message "Exchange Online connection verified for Defender assessment"
    }
    catch {
        Write-TtcLog -Level Warning -Message "Exchange Online not connected — Defender assessment cannot proceed: $($_.Exception.Message)"
    }

    if (-not $exoConnected) {
        $findings.Add((New-TtcFinding `
            -FindingId 'DEF-SEC-001' -Workload 'Defender' -Component 'Prerequisites' `
            -CheckName 'Safe Links Policy Coverage' -Category 'Security' -Severity 'High' `
            -Status 'Error' `
            -IssueDetected 'Exchange Online is not connected — Defender for Office 365 assessment cannot proceed.' `
            -Explanation 'Defender for Office 365 cmdlets require an active ExchangeOnlineManagement session. All checks in this workload are skipped.' `
            -PossibleSolution 'Run: Connect-ExchangeOnline. Requires Security Administrator or Global Administrator credentials.' `
            -Impact 'No Defender for Office 365 assessment data can be collected.' `
            -DataSource 'Get-OrganizationConfig' -AutoFixAvailable 'No' -RemediationPriority 'P1'))
        return $findings.ToArray()
    }

    # Probe for Defender P1+ availability by checking if Safe Links cmdlets are accessible
    try {
        $ErrorActionPreference = 'Stop'
        $null = Get-SafeLinksPolicy -ErrorAction Stop
        $defenderP1OrAbove = $true
        Write-TtcLog -Level Info -Message "Defender for Office 365 Plan 1+ confirmed (Safe Links cmdlets available)"
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        Write-TtcLog -Level Warning -Message "Get-SafeLinksPolicy cmdlet not found — tenant may not have Defender for Office 365 license"
    }
    catch {
        Write-TtcLog -Level Warning -Message "Safe Links cmdlet check returned error: $($_.Exception.Message)"
    }

    # =========================================================================
    # DEF-SEC-001 — Safe Links Policy Coverage
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "DEF-SEC-001: Checking Safe Links policy coverage"

        if (-not $defenderP1OrAbove) {
            $findings.Add((New-TtcFinding `
                -FindingId 'DEF-SEC-001' -Workload 'Defender' -Component 'SafeLinks' `
                -CheckName 'Safe Links Policy Coverage' -Category 'Security' -Severity 'High' `
                -Status 'NotAssessed' `
                -IssueDetected 'Safe Links cmdlets are not available — tenant does not appear to have Defender for Office 365 Plan 1 or higher.' `
                -Explanation 'Safe Links requires Microsoft Defender for Office 365 Plan 1 (included in Microsoft 365 Business Premium, E3+Defender, E5). Without it, URL rewriting and time-of-click protection against malicious links is not available.' `
                -PossibleSolution 'License users for Microsoft Defender for Office 365 Plan 1 or Plan 2 (included in M365 E5, M365 Business Premium, or as an add-on). After licensing, configure Safe Links policies in the Security portal.' `
                -Impact 'Users clicking malicious links in email or Office documents are not protected by time-of-click URL inspection. Phishing and malware delivery via URL is undetected at the click event.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                -SecureScoreMapping 'Enable Safe Links policies' `
                -DataSource 'Get-SafeLinksPolicy' -AutoFixAvailable 'No' -RemediationPriority 'P2'))
        }
        else {
            $safeLinksRules    = Get-SafeLinksRule -ErrorAction Stop
            $safeLinksEnabled  = $safeLinksRules | Where-Object { $_.State -eq 'Enabled' }
            $enabledRuleCount  = ($safeLinksEnabled | Measure-Object).Count

            # Check if built-in protection is active (Microsoft's default baseline for all users)
            $builtInProtection = $null
            try {
                $builtInProtection = Get-ATPBuiltInProtectionRule -ErrorAction SilentlyContinue
            }
            catch {
                Write-TtcLog -Level Debug -Message "Get-ATPBuiltInProtectionRule not available: $_"
            }
            $builtInActive = $builtInProtection -and $builtInProtection.State -eq 'Enabled'

            if ($enabledRuleCount -gt 0 -or $builtInActive) {
                $coverage = if ($builtInActive) { 'Built-in protection active (all users covered)' }
                            else { "$enabledRuleCount enabled Safe Links rule(s) — verify recipient scope covers all users" }

                $findings.Add((New-TtcFinding `
                    -FindingId 'DEF-SEC-001' -Workload 'Defender' -Component 'SafeLinks' `
                    -CheckName 'Safe Links Policy Coverage' -Category 'Security' -Severity 'High' `
                    -Status 'Pass' `
                    -IssueDetected "Safe Links policies are active. $coverage" `
                    -Explanation 'Safe Links rewrites URLs in email and Office documents and performs time-of-click inspection to block access to malicious or newly discovered phishing sites after delivery.' `
                    -DataSource 'Get-SafeLinksRule;Get-ATPBuiltInProtectionRule' `
                    -Notes "EnabledRules: $enabledRuleCount | BuiltInProtection: $builtInActive"))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'DEF-SEC-001' -Workload 'Defender' -Component 'SafeLinks' `
                    -CheckName 'Safe Links Policy Coverage' -Category 'Security' -Severity 'High' `
                    -Status 'Fail' `
                    -IssueDetected 'No enabled Safe Links rules found and built-in protection is not active — users are not protected by Safe Links.' `
                    -Explanation 'Defender for Office 365 Plan 1+ is licensed but no Safe Links policies are enabled for users. URL rewriting and time-of-click protection against malicious links is not active, leaving users vulnerable to phishing and malware delivery via URL even when the license is present.' `
                    -PossibleSolution 'Enable built-in protection: In the Security portal, go to Email & Collaboration > Policies & Rules > Threat policies > Preset security policies and enable Standard or Strict protection. Or create a custom Safe Links policy covering all users.' `
                    -Impact 'Despite having a Defender license, users receive no URL protection. Phishing links and malware download URLs are not inspected at the time of click. The license investment is not providing its intended protection.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Enable Safe Links policies' `
                    -DataSource 'Get-SafeLinksRule;Get-ATPBuiltInProtectionRule' `
                    -Remediation 'Option 1 (recommended): Enable preset security policies in Security portal: security.microsoft.com > Email & Collaboration > Policies & Rules > Threat policies > Preset security policies. Enable Standard protection for all users. Option 2: New-SafeLinksPolicy -Name "All Users Safe Links" -EnableSafeLinksForEmail $true -TrackClicks $true -ScanUrls $true -EnableForInternalSenders $true; New-SafeLinksRule -Name "All Users Safe Links Rule" -SafeLinksPolicy "All Users Safe Links" -Priority 0 -SentToMemberOf "All Users".' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                    -Notes "EnabledRules: $enabledRuleCount | BuiltInProtection: $builtInActive"))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "DEF-SEC-001: Safe Links check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'DEF-SEC-001' -Workload 'Defender' -Component 'SafeLinks' `
            -CheckName 'Safe Links Policy Coverage' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-SafeLinksRule' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # DEF-SEC-002 — Safe Attachments Policy Coverage
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "DEF-SEC-002: Checking Safe Attachments policy coverage"

        if (-not $defenderP1OrAbove) {
            $findings.Add((New-TtcFinding `
                -FindingId 'DEF-SEC-002' -Workload 'Defender' -Component 'SafeAttachments' `
                -CheckName 'Safe Attachments Policy Coverage' -Category 'Security' -Severity 'High' `
                -Status 'NotAssessed' `
                -IssueDetected 'Defender for Office 365 Plan 1+ not available — Safe Attachments check skipped.' `
                -PossibleSolution 'License users for Microsoft Defender for Office 365 Plan 1 or Plan 2.' `
                -Impact 'Sandbox detonation of suspicious email attachments is not available. Malicious attachments are inspected only by basic anti-malware signature matching.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                -SecureScoreMapping 'Enable Safe Attachments policies' `
                -DataSource 'Get-SafeAttachmentPolicy' -AutoFixAvailable 'No' -RemediationPriority 'P2'))
        }
        else {
            $safeAttachRules   = Get-SafeAttachmentRule -ErrorAction Stop
            $safeAttachEnabled = $safeAttachRules | Where-Object { $_.State -eq 'Enabled' }
            $enabledRuleCount  = ($safeAttachEnabled | Measure-Object).Count

            # Check if any enabled policies have action != Off
            $activePolicies = [System.Collections.Generic.List[string]]::new()
            foreach ($rule in $safeAttachEnabled) {
                try {
                    $policy = Get-SafeAttachmentPolicy -Identity $rule.SafeAttachmentPolicy -ErrorAction SilentlyContinue
                    if ($policy -and $policy.Action -ne 'Off') {
                        $activePolicies.Add("$($policy.Name) [Action=$($policy.Action)]")
                    }
                }
                catch {
                    Write-TtcLog -Level Debug -Message "Could not retrieve policy for rule $($rule.Name): $_"
                }
            }

            $builtInProtection = $null
            try {
                $builtInProtection = Get-ATPBuiltInProtectionRule -ErrorAction SilentlyContinue
            }
            catch {
                Write-TtcLog -Level Debug -Message "Get-ATPBuiltInProtectionRule not available: $_"
            }
            $builtInActive = $builtInProtection -and $builtInProtection.State -eq 'Enabled'

            $notes = "EnabledRules: $enabledRuleCount | ActivePolicies: $($activePolicies.Count) | BuiltIn: $builtInActive"

            if ($activePolicies.Count -gt 0 -or $builtInActive) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'DEF-SEC-002' -Workload 'Defender' -Component 'SafeAttachments' `
                    -CheckName 'Safe Attachments Policy Coverage' -Category 'Security' -Severity 'High' `
                    -Status 'Pass' `
                    -IssueDetected "Safe Attachments policies are active with blocking/quarantine actions configured." `
                    -Explanation 'Safe Attachments detonates suspicious email attachments in a sandbox environment before delivering them to users, blocking malicious attachments that evade signature-based anti-malware.' `
                    -DataSource 'Get-SafeAttachmentRule;Get-SafeAttachmentPolicy' `
                    -Notes $notes))
            }
            elseif ($enabledRuleCount -gt 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'DEF-SEC-002' -Workload 'Defender' -Component 'SafeAttachments' `
                    -CheckName 'Safe Attachments Policy Coverage' -Category 'Security' -Severity 'High' `
                    -Status 'Warning' `
                    -IssueDetected "$enabledRuleCount Safe Attachment rule(s) exist but associated policies have Action=Off — no sandboxing is occurring." `
                    -Explanation 'Safe Attachment policies with Action=Off are in monitor-only mode; attachments are not scanned in a sandbox before delivery. The rules are enabled but the protection action is disabled, meaning the license investment provides no actual attachment sandboxing.' `
                    -PossibleSolution 'Update policy action: Set-SafeAttachmentPolicy -Identity <PolicyName> -Action Block (recommended) or DynamicDelivery (delivers message while scanning attachment). Review in Security portal: security.microsoft.com > Email & Collaboration > Policies & Rules > Threat policies > Safe Attachments.' `
                    -Impact 'Novel malware in email attachments that evades signature detection is delivered to users without sandbox inspection.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Enable Safe Attachments policies' `
                    -DataSource 'Get-SafeAttachmentRule;Get-SafeAttachmentPolicy' `
                    -Remediation 'For each policy with Action=Off: Set-SafeAttachmentPolicy -Identity <Name> -Action Block -Redirect $false. Or use DynamicDelivery to reduce latency: -Action DynamicDelivery. Alternatively, enable preset security policies which configure these settings automatically at Standard or Strict protection level.' `
                    -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                    -Notes $notes))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'DEF-SEC-002' -Workload 'Defender' -Component 'SafeAttachments' `
                    -CheckName 'Safe Attachments Policy Coverage' -Category 'Security' -Severity 'High' `
                    -Status 'Fail' `
                    -IssueDetected 'No enabled Safe Attachment rules found and built-in protection is not active — email attachments are not sandbox-scanned.' `
                    -Explanation 'Defender for Office 365 is licensed but Safe Attachments is not active for any users. Email attachments are inspected only by anti-malware signature matching, leaving users vulnerable to novel and zero-day malware in attachments.' `
                    -PossibleSolution 'Enable preset security policies in the Security portal (Standard or Strict protection), or create a Safe Attachments policy and rule covering all users.' `
                    -Impact 'Novel malware in email attachments evades anti-malware signature detection and is delivered to users without sandbox inspection. The Defender license investment does not provide its intended protection.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Enable Safe Attachments policies' `
                    -DataSource 'Get-SafeAttachmentRule;Get-SafeAttachmentPolicy' `
                    -Remediation 'Option 1 (recommended): Enable preset security policies: security.microsoft.com > Email & Collaboration > Policies & Rules > Threat policies > Preset security policies > Enable Standard protection. Option 2: New-SafeAttachmentPolicy -Name "All Users SA" -Action Block -Redirect $false; New-SafeAttachmentRule -Name "All Users SA Rule" -SafeAttachmentPolicy "All Users SA" -SentToMemberOf "All Users" -Priority 0.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                    -Notes $notes))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "DEF-SEC-002: Safe Attachments check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'DEF-SEC-002' -Workload 'Defender' -Component 'SafeAttachments' `
            -CheckName 'Safe Attachments Policy Coverage' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-SafeAttachmentRule;Get-SafeAttachmentPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # DEF-SEC-003 — Anti-Phishing Policy Configuration
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "DEF-SEC-003: Checking anti-phishing policy configuration"

        $antiPhishPolicies = Get-AntiPhishPolicy -ErrorAction Stop
        $defaultPolicy     = $antiPhishPolicies | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1
        if (-not $defaultPolicy) { $defaultPolicy = $antiPhishPolicies | Select-Object -First 1 }

        if ($defaultPolicy) {
            $gaps = [System.Collections.Generic.List[string]]::new()

            # Spoof intelligence — baseline EOP protection (no Defender P1 required)
            if ($defaultPolicy.EnableSpoofIntelligence -ne $true) {
                $gaps.Add('Spoof intelligence is disabled (EnableSpoofIntelligence = false)')
            }
            # First contact safety tips
            if ($defaultPolicy.EnableFirstContactSafetyTips -ne $true) {
                $gaps.Add('First contact safety tips are not enabled (EnableFirstContactSafetyTips = false)')
            }
            # Unauthenticated sender indicators
            if ($defaultPolicy.EnableUnauthenticatedSender -ne $true) {
                $gaps.Add('Unauthenticated sender indicators are disabled (EnableUnauthenticatedSender = false)')
            }

            # Defender P1+ features: mailbox intelligence
            $mailboxIntelEnabled = $defaultPolicy.EnableMailboxIntelligenceProtection
            if ($defenderP1OrAbove -and $mailboxIntelEnabled -ne $true) {
                $gaps.Add('Mailbox intelligence-based impersonation protection is disabled (EnableMailboxIntelligenceProtection = false)')
            }

            $notes  = "SpoofIntelligence: $($defaultPolicy.EnableSpoofIntelligence)"
            $notes += " | MailboxIntelligence: $($defaultPolicy.EnableMailboxIntelligenceProtection)"
            $notes += " | FirstContactTips: $($defaultPolicy.EnableFirstContactSafetyTips)"
            $notes += " | UnauthSender: $($defaultPolicy.EnableUnauthenticatedSender)"

            if ($gaps.Count -gt 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'DEF-SEC-003' -Workload 'Defender' -Component 'AntiPhishing' `
                    -CheckName 'Anti-Phishing Policy Configuration' -Category 'Security' -Severity 'High' `
                    -Status 'Warning' `
                    -IssueDetected "$($gaps.Count) anti-phishing protection gap(s): $($gaps -join '; ')." `
                    -Explanation 'Anti-phishing policies protect against spoofing, impersonation, and targeted phishing. Spoof intelligence detects unauthorized domain spoofing. Mailbox intelligence builds a communication graph to detect impersonation. First contact tips warn users about unexpected senders. Unauthenticated sender indicators visually flag spoofed messages in Outlook.' `
                    -PossibleSolution 'Update default policy: Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableSpoofIntelligence $true -EnableFirstContactSafetyTips $true -EnableUnauthenticatedSender $true. For Defender P1+, also enable: -EnableMailboxIntelligenceProtection $true -EnableOrganizationDomainsProtection $true.' `
                    -Impact 'Spoofed and impersonation-based phishing emails are less likely to be detected or flagged for users. Users receive no visual warnings about messages from unknown senders, increasing susceptibility to targeted phishing.' `
                    -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Identity' `
                    -SecureScoreMapping 'Enable anti-phishing policies' `
                    -DataSource 'Get-AntiPhishPolicy' `
                    -Remediation 'Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableSpoofIntelligence $true -EnableFirstContactSafetyTips $true -EnableUnauthenticatedSender $true -AuthenticationFailAction MoveToJmf. For Defender P1+: -EnableMailboxIntelligenceProtection $true -MailboxIntelligenceProtectionAction Quarantine -EnableOrganizationDomainsProtection $true -EnableTargetedDomainsProtection $true -TargetedDomainProtectionAction Quarantine. Review in Security portal under Anti-phishing policies.' `
                    -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                    -Notes $notes))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'DEF-SEC-003' -Workload 'Defender' -Component 'AntiPhishing' `
                    -CheckName 'Anti-Phishing Policy Configuration' -Category 'Security' -Severity 'High' `
                    -Status 'Pass' `
                    -IssueDetected 'Anti-phishing policy has spoof intelligence, safety tips, and unauthenticated sender indicators configured.' `
                    -DataSource 'Get-AntiPhishPolicy' `
                    -Notes $notes))
            }
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'DEF-SEC-003' -Workload 'Defender' -Component 'AntiPhishing' `
                -CheckName 'Anti-Phishing Policy Configuration' -Category 'Security' -Severity 'High' `
                -Status 'Error' -IssueDetected 'No anti-phishing policy found — unexpected state in Exchange Online.' `
                -DataSource 'Get-AntiPhishPolicy'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "DEF-SEC-003: Anti-phishing check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'DEF-SEC-003' -Workload 'Defender' -Component 'AntiPhishing' `
            -CheckName 'Anti-Phishing Policy Configuration' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-AntiPhishPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # DEF-CFG-001 — Preset Security Policy Adoption
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "DEF-CFG-001: Checking preset security policy adoption"

        if (-not $defenderP1OrAbove) {
            # EOP-only preset: check EOPProtectionPolicyRule
            $eopPresets = $null
            try {
                $eopPresets = Get-EOPProtectionPolicyRule -ErrorAction SilentlyContinue
            }
            catch {
                Write-TtcLog -Level Debug -Message "Get-EOPProtectionPolicyRule failed: $_"
            }

            $eopActive = $eopPresets | Where-Object { $_.State -eq 'Enabled' }
            $eopCount  = ($eopActive | Measure-Object).Count

            if ($eopCount -gt 0) {
                $presetNames = ($eopActive | Select-Object -ExpandProperty Identity) -join '; '
                $findings.Add((New-TtcFinding `
                    -FindingId 'DEF-CFG-001' -Workload 'Defender' -Component 'PresetPolicies' `
                    -CheckName 'Preset Security Policy Adoption' -Category 'Configuration' -Severity 'Medium' `
                    -Status 'Pass' `
                    -IssueDetected "EOP preset security policies are active ($eopCount rule(s))." `
                    -DataSource 'Get-EOPProtectionPolicyRule' `
                    -Notes "Active EOP preset rules: $presetNames"))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'DEF-CFG-001' -Workload 'Defender' -Component 'PresetPolicies' `
                    -CheckName 'Preset Security Policy Adoption' -Category 'Configuration' -Severity 'Medium' `
                    -Status 'Warning' `
                    -IssueDetected 'No preset security policies (Standard or Strict) are active for EOP. Manual policy configuration requires ongoing maintenance.' `
                    -Explanation 'Preset security policies (Standard and Strict protection) apply Microsoft-recommended configurations for EOP and Defender for Office 365. They are automatically updated as the threat landscape evolves, reducing the operational overhead of manually maintaining individual policies.' `
                    -PossibleSolution 'Enable Standard or Strict preset policies in the Security portal: security.microsoft.com > Email & Collaboration > Policies & Rules > Threat policies > Preset security policies. Apply to all users or specific groups.' `
                    -Impact 'Manual policy configuration may drift from Microsoft best practices over time. New threat categories may not be protected without explicit policy updates.' `
                    -FrameworkMapping 'CIS-SecureConfig' -ZeroTrustPillar 'Data' `
                    -DataSource 'Get-EOPProtectionPolicyRule' `
                    -Remediation 'In Security portal: security.microsoft.com > Email & Collaboration > Policies & Rules > Threat policies > Preset security policies. Enable Standard protection for all users as a baseline. Use Strict protection for high-value targets (executives, IT admins). Preset policies cover: anti-spam, anti-malware, anti-phishing, and (with Defender P1+) Safe Links and Safe Attachments.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P3'))
            }
        }
        else {
            # Defender P1+ available: check both EOP and ATP preset rules
            $eopPresets = $null
            $atpPresets = $null
            try {
                $eopPresets = Get-EOPProtectionPolicyRule -ErrorAction SilentlyContinue
                $atpPresets = Get-ATPProtectionPolicyRule -ErrorAction SilentlyContinue
            }
            catch {
                Write-TtcLog -Level Debug -Message "Preset policy rule query failed: $_"
            }

            $eopActive = ($eopPresets | Where-Object { $_.State -eq 'Enabled' } | Measure-Object).Count
            $atpActive = ($atpPresets | Where-Object { $_.State -eq 'Enabled' } | Measure-Object).Count
            $notes     = "EOP preset active rules: $eopActive | ATP preset active rules: $atpActive"

            if ($eopActive -gt 0 -or $atpActive -gt 0) {
                $findings.Add((New-TtcFinding `
                    -FindingId 'DEF-CFG-001' -Workload 'Defender' -Component 'PresetPolicies' `
                    -CheckName 'Preset Security Policy Adoption' -Category 'Configuration' -Severity 'Medium' `
                    -Status 'Pass' `
                    -IssueDetected "Preset security policies are active (EOP: $eopActive rule(s), ATP: $atpActive rule(s))." `
                    -Explanation 'Preset security policies automatically apply Microsoft-recommended configurations for EOP and Defender for Office 365, and are updated as threat intelligence evolves.' `
                    -DataSource 'Get-EOPProtectionPolicyRule;Get-ATPProtectionPolicyRule' `
                    -Notes $notes))
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'DEF-CFG-001' -Workload 'Defender' -Component 'PresetPolicies' `
                    -CheckName 'Preset Security Policy Adoption' -Category 'Configuration' -Severity 'Medium' `
                    -Status 'Warning' `
                    -IssueDetected 'No preset security policies (Standard or Strict) are active — all protection relies on manually maintained custom policies.' `
                    -Explanation 'Preset security policies automatically apply Microsoft-recommended configurations for EOP and Defender for Office 365 and are kept current with evolving threats. Without them, custom policies must be manually updated to stay aligned with best practices, which is operationally demanding and prone to drift.' `
                    -PossibleSolution 'Enable Standard or Strict preset policies: security.microsoft.com > Email & Collaboration > Policies & Rules > Threat policies > Preset security policies. Standard protection is suitable for most users. Strict protection is recommended for executives and IT administrators.' `
                    -Impact 'Manual policy configuration may fall out of alignment with Microsoft best practices over time. New threat categories (new phishing techniques, attachment types) may not be protected until manually added to custom policies.' `
                    -FrameworkMapping 'CIS-SecureConfig' -ZeroTrustPillar 'Data' `
                    -SecureScoreMapping 'Apply standard or strict protection presets' `
                    -DataSource 'Get-EOPProtectionPolicyRule;Get-ATPProtectionPolicyRule' `
                    -Remediation 'Security portal: security.microsoft.com > Email & Collaboration > Policies & Rules > Threat policies > Preset security policies. Enable Standard protection for all users. Apply Strict protection for: C-Suite, board, IT admins, HR, Finance. Preset policies configure: anti-spam, anti-malware, anti-phishing, Safe Links, Safe Attachments in one operation.' `
                    -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                    -Notes $notes))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "DEF-CFG-001: Preset security policy check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'DEF-CFG-001' -Workload 'Defender' -Component 'PresetPolicies' `
            -CheckName 'Preset Security Policy Adoption' -Category 'Configuration' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-EOPProtectionPolicyRule;Get-ATPProtectionPolicyRule' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # DEF-CFG-002 — Zero-Hour Auto Purge (ZAP) Configuration
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "DEF-CFG-002: Checking Zero-Hour Auto Purge configuration"

        $contentFilter = Get-HostedContentFilterPolicy -ErrorAction Stop |
            Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1
        if (-not $contentFilter) {
            $contentFilter = Get-HostedContentFilterPolicy -ErrorAction Stop | Select-Object -First 1
        }

        $antiPhishDefault = Get-AntiPhishPolicy -ErrorAction Stop |
            Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1

        $spamZapEnabled  = $contentFilter.ZapEnabled
        $phishZapEnabled = if ($antiPhishDefault) { $antiPhishDefault.PhishZapEnabled } else { $null }

        $gaps  = [System.Collections.Generic.List[string]]::new()
        $notes = "SpamZAP: $spamZapEnabled | PhishZAP: $phishZapEnabled"

        if ($spamZapEnabled -ne $true) {
            $gaps.Add('Spam ZAP is not enabled (HostedContentFilterPolicy.ZapEnabled = false)')
        }
        if ($null -ne $phishZapEnabled -and $phishZapEnabled -ne $true) {
            $gaps.Add('Phishing ZAP is not enabled (AntiPhishPolicy.PhishZapEnabled = false)')
        }

        if ($gaps.Count -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'DEF-CFG-002' -Workload 'Defender' -Component 'ZAP' `
                -CheckName 'Zero-Hour Auto Purge Configuration' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected 'Zero-Hour Auto Purge is enabled for spam and phishing — malicious messages delivered before detection are retroactively removed.' `
                -Explanation 'ZAP monitors mailboxes after delivery. When a spam or phishing verdict is updated for a previously delivered message, ZAP moves the message to the Junk folder or Quarantine, reducing dwell time for malicious content.' `
                -DataSource 'Get-HostedContentFilterPolicy;Get-AntiPhishPolicy' `
                -Notes $notes))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'DEF-CFG-002' -Workload 'Defender' -Component 'ZAP' `
                -CheckName 'Zero-Hour Auto Purge Configuration' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected "$($gaps.Count) ZAP gap(s): $($gaps -join '; ')." `
                -Explanation 'Zero-Hour Auto Purge (ZAP) retroactively acts on messages already delivered to mailboxes when new spam or phishing verdicts are issued after delivery (e.g., after threat intelligence updates or detonation results). Without ZAP, malicious messages delivered before detection remain in user mailboxes until users or admins manually remove them.' `
                -PossibleSolution 'Enable ZAP: Set-HostedContentFilterPolicy -Identity Default -ZapEnabled $true. For phishing: Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -PhishZapEnabled $true.' `
                -Impact 'Messages with updated malicious verdicts remain in user mailboxes. Users may interact with phishing or malware-laden messages that were initially missed and later flagged by updated threat intelligence.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                -SecureScoreMapping 'Enable ZAP for spam and phishing' `
                -DataSource 'Get-HostedContentFilterPolicy;Get-AntiPhishPolicy' `
                -Remediation 'Spam ZAP: Set-HostedContentFilterPolicy -Identity Default -ZapEnabled $true. Phishing ZAP: Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -PhishZapEnabled $true. Verify in Security portal: Threat policies > Anti-spam > Inbound spam filter (ZAP setting). ZAP acts within 48 hours of delivery for messages still in the inbox.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                -Notes $notes))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "DEF-CFG-002: ZAP check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'DEF-CFG-002' -Workload 'Defender' -Component 'ZAP' `
            -CheckName 'Zero-Hour Auto Purge Configuration' -Category 'Configuration' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-HostedContentFilterPolicy;Get-AntiPhishPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # DEF-CFG-003 — Defender for Office 365 SharePoint/Teams/OneDrive Protection
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "DEF-CFG-003: Checking Defender for Office 365 SharePoint/Teams/OneDrive protection"

        if (-not $defenderP1OrAbove) {
            $findings.Add((New-TtcFinding `
                -FindingId 'DEF-CFG-003' -Workload 'Defender' -Component 'SPOTeamsODB' `
                -CheckName 'Defender for Office 365 SharePoint Teams OneDrive Protection' -Category 'Configuration' -Severity 'High' `
                -Status 'NotAssessed' `
                -IssueDetected 'Defender for Office 365 Plan 1+ not available — SharePoint/Teams/OneDrive protection check skipped.' `
                -PossibleSolution 'License users for Microsoft Defender for Office 365 Plan 1 or Plan 2.' `
                -Impact 'Malware in files shared via SharePoint, Teams, and OneDrive is not detected by Defender for Office 365 sandbox inspection.' `
                -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                -SecureScoreMapping 'Turn on Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams' `
                -DataSource 'Get-AtpPolicyForO365' -AutoFixAvailable 'No' -RemediationPriority 'P2'))
        }
        else {
            $atpPolicy = Get-AtpPolicyForO365 -ErrorAction Stop | Select-Object -First 1

            if ($atpPolicy) {
                $spoProtection  = $atpPolicy.EnableATPForSPOTeamsODB
                $safeDocsEnabled = $atpPolicy.EnableSafeDocs

                $gaps  = [System.Collections.Generic.List[string]]::new()
                $notes = "EnableATPForSPOTeamsODB: $spoProtection | EnableSafeDocs: $safeDocsEnabled"

                if ($spoProtection -ne $true) {
                    $gaps.Add('Defender for Office 365 protection for SharePoint, Teams, and OneDrive is not enabled (EnableATPForSPOTeamsODB = false)')
                }
                # Safe Documents requires E5 or Defender P2 — only flag if explicitly false
                if ($safeDocsEnabled -eq $false) {
                    $gaps.Add('Safe Documents (opens Office files in Protected View pending cloud scan) is disabled (EnableSafeDocs = false)')
                }

                if ($gaps.Count -eq 0) {
                    $findings.Add((New-TtcFinding `
                        -FindingId 'DEF-CFG-003' -Workload 'Defender' -Component 'SPOTeamsODB' `
                        -CheckName 'Defender for Office 365 SharePoint Teams OneDrive Protection' -Category 'Configuration' -Severity 'High' `
                        -Status 'Pass' `
                        -IssueDetected 'Defender for Office 365 protection is enabled for SharePoint, Teams, and OneDrive.' `
                        -Explanation 'Safe Attachments for SharePoint, Teams, and OneDrive detects and blocks malicious files uploaded to these collaboration services, preventing malware spread through shared files.' `
                        -DataSource 'Get-AtpPolicyForO365' `
                        -Notes $notes))
                }
                else {
                    $findings.Add((New-TtcFinding `
                        -FindingId 'DEF-CFG-003' -Workload 'Defender' -Component 'SPOTeamsODB' `
                        -CheckName 'Defender for Office 365 SharePoint Teams OneDrive Protection' -Category 'Configuration' -Severity 'High' `
                        -Status 'Fail' `
                        -IssueDetected "$($gaps.Count) SharePoint/Teams/OneDrive protection gap(s): $($gaps -join '; ')." `
                        -Explanation 'Defender for Office 365 protection for SharePoint, Teams, and OneDrive (EnableATPForSPOTeamsODB) scans files uploaded to these services for malware. Without it, malware can spread through shared files in collaboration services even when email attachments are protected.' `
                        -PossibleSolution 'Enable: Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true. This requires no additional licensing beyond Defender P1 and takes effect within minutes.' `
                        -Impact 'Malware uploaded to SharePoint libraries, Teams channels, or OneDrive is not detected or blocked. Malware can spread laterally to all users who access the infected file, bypassing email-based protection entirely.' `
                        -FrameworkMapping 'NIST-Protect' -ZeroTrustPillar 'Data' `
                        -SecureScoreMapping 'Turn on Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams' `
                        -DataSource 'Get-AtpPolicyForO365' `
                        -Remediation 'Enable: Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true. Verify: (Get-AtpPolicyForO365).EnableATPForSPOTeamsODB should return True. No additional licensing is required beyond Defender for Office 365 Plan 1. After enabling, infected files in SPO/ODB are quarantined and users blocked from downloading them.' `
                        -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                        -Notes $notes))
                }
            }
            else {
                $findings.Add((New-TtcFinding `
                    -FindingId 'DEF-CFG-003' -Workload 'Defender' -Component 'SPOTeamsODB' `
                    -CheckName 'Defender for Office 365 SharePoint Teams OneDrive Protection' -Category 'Configuration' -Severity 'High' `
                    -Status 'Error' -IssueDetected 'Could not retrieve ATP policy for Office 365.' `
                    -DataSource 'Get-AtpPolicyForO365'))
            }
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "DEF-CFG-003: SPO/Teams/ODB protection check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'DEF-CFG-003' -Workload 'Defender' -Component 'SPOTeamsODB' `
            -CheckName 'Defender for Office 365 SharePoint Teams OneDrive Protection' -Category 'Configuration' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-AtpPolicyForO365' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # DEF-MON-001 — High-Severity Alert Policy Notification
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "DEF-MON-001: Checking high-severity alert policy notification configuration"

        $allAlertPolicies  = Get-AlertPolicy -ErrorAction Stop
        $highSevEnabled    = $allAlertPolicies | Where-Object { $_.Severity -eq 'High' -and $_.IsEnabled -eq $true }
        $highSevCount      = ($highSevEnabled | Measure-Object).Count
        $withoutNotify     = $highSevEnabled | Where-Object { -not $_.NotifyUser -or ($_.NotifyUser | Measure-Object).Count -eq 0 }
        $withoutNotifyCount = ($withoutNotify | Measure-Object).Count

        $notes = "Enabled high-severity policies: $highSevCount | Without notification recipients: $withoutNotifyCount"

        if ($highSevCount -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'DEF-MON-001' -Workload 'Defender' -Component 'AlertPolicies' `
                -CheckName 'High-Severity Alert Policy Notification' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'No enabled high-severity alert policies found — this is unexpected. Default Microsoft alert policies may have been disabled.' `
                -Explanation 'Microsoft creates default high-severity alert policies covering critical events such as mass file downloads, email forwarding rule creation, eDiscovery searches, and admin privilege escalation. If none are enabled, critical security events will not trigger notifications.' `
                -PossibleSolution 'Review alert policies in the Purview compliance portal: compliance.microsoft.com > Policies > Alert policies. Re-enable default Microsoft alert policies. Confirm notification recipients are configured.' `
                -DataSource 'Get-AlertPolicy' `
                -Notes $notes))
        }
        elseif ($withoutNotifyCount -gt 0) {
            $unnotifiedNames = ($withoutNotify | Select-Object -ExpandProperty Name) -join '; '
            $findings.Add((New-TtcFinding `
                -FindingId 'DEF-MON-001' -Workload 'Defender' -Component 'AlertPolicies' `
                -CheckName 'High-Severity Alert Policy Notification' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected "$withoutNotifyCount high-severity alert policy/policies have no email notification recipients configured: $unnotifiedNames" `
                -Explanation 'Alert policies without notification recipients generate alerts visible only in the Microsoft Security portal. Security teams relying solely on portal monitoring may miss critical events if the portal is not actively monitored 24/7. Email notification ensures timely awareness.' `
                -PossibleSolution 'Add notification recipients to each high-severity alert policy: In compliance.microsoft.com > Policies > Alert policies, edit each policy and add the security team email address to "Email recipients". Or use PowerShell: Set-AlertPolicy -Identity <Name> -NotifyUser @("secops@yourdomain.com").' `
                -Impact 'Critical security events (mass data download, privilege escalation, forwarding rules, eDiscovery launches) generate portal-only alerts. Without email notification, these events may not be actioned until the next manual portal review.' `
                -FrameworkMapping 'NIST-Detect' -ZeroTrustPillar 'Infrastructure' `
                -DataSource 'Get-AlertPolicy' `
                -Remediation 'For each policy without recipients: Set-AlertPolicy -Identity "<PolicyName>" -NotifyUser @("secops@yourdomain.com"). Or update in bulk: Get-AlertPolicy | Where-Object { $_.Severity -eq "High" -and $_.IsEnabled -eq $true -and -not $_.NotifyUser } | ForEach-Object { Set-AlertPolicy -Identity $_.Identity -NotifyUser @("secops@yourdomain.com") }. Consider routing alerts to a security mailbox monitored 24/7 or integrated with a SIEM/ticketing system.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P3' `
                -Notes $notes))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'DEF-MON-001' -Workload 'Defender' -Component 'AlertPolicies' `
                -CheckName 'High-Severity Alert Policy Notification' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected "All $highSevCount high-severity alert policies are enabled with email notification recipients configured." `
                -DataSource 'Get-AlertPolicy' `
                -Notes $notes))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "DEF-MON-001: Alert policy notification check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'DEF-MON-001' -Workload 'Defender' -Component 'AlertPolicies' `
            -CheckName 'High-Severity Alert Policy Notification' -Category 'Monitoring' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-AlertPolicy' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # DEF-MON-002 — Compromised Account Alert Policies
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "DEF-MON-002: Checking compromised account alert policies"

        $allAlertPolicies = Get-AlertPolicy -ErrorAction Stop

        # Key Microsoft default alert policies for detecting compromised accounts and BEC
        $targetPolicies = @(
            'Suspicious email sending patterns detected',
            'Email sending limit exceeded',
            'Suspicious email-forwarding activity',
            'New-InboxRule alert',
            'Messages have been delayed',
            'Unusual external user file activity',
            'Unusual volume of external file sharing'
        )

        $missingOrDisabled = [System.Collections.Generic.List[string]]::new()
        $noRecipients      = [System.Collections.Generic.List[string]]::new()
        $healthy           = [System.Collections.Generic.List[string]]::new()

        foreach ($policyName in $targetPolicies) {
            $match = $allAlertPolicies | Where-Object { $_.Name -like "*$policyName*" } | Select-Object -First 1
            if (-not $match) {
                $missingOrDisabled.Add("$policyName (not found — may have been removed)")
            }
            elseif ($match.IsEnabled -ne $true) {
                $missingOrDisabled.Add("$policyName (DISABLED)")
            }
            elseif (-not $match.NotifyUser -or ($match.NotifyUser | Measure-Object).Count -eq 0) {
                $noRecipients.Add("$policyName (enabled but no notification recipients)")
            }
            else {
                $healthy.Add($policyName)
            }
        }

        $totalIssues = $missingOrDisabled.Count + $noRecipients.Count
        $notes = "Policies checked: $($targetPolicies.Count) | Missing/Disabled: $($missingOrDisabled.Count) | No recipients: $($noRecipients.Count) | Healthy: $($healthy.Count)"

        if ($totalIssues -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'DEF-MON-002' -Workload 'Defender' -Component 'AlertPolicies' `
                -CheckName 'Compromised Account Alert Policies' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected "All $($healthy.Count) checked compromised-account indicator alert policies are enabled with notification recipients." `
                -Explanation 'Microsoft default alert policies for suspicious sending, forwarding rules, and inbox rule creation provide early warning of Business Email Compromise (BEC) and account takeover. Having these enabled with notification recipients ensures rapid detection and response.' `
                -DataSource 'Get-AlertPolicy' `
                -Notes $notes))
        }
        elseif ($missingOrDisabled.Count -gt 0) {
            $issueDesc = [System.Collections.Generic.List[string]]::new()
            if ($missingOrDisabled.Count -gt 0) { $issueDesc.Add("Disabled/missing: $($missingOrDisabled -join '; ')") }
            if ($noRecipients.Count -gt 0)       { $issueDesc.Add("No recipients: $($noRecipients -join '; ')") }

            $findings.Add((New-TtcFinding `
                -FindingId 'DEF-MON-002' -Workload 'Defender' -Component 'AlertPolicies' `
                -CheckName 'Compromised Account Alert Policies' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Fail' `
                -IssueDetected "$totalIssues BEC/account compromise indicator alert issue(s): $($issueDesc -join ' | ')" `
                -Explanation 'The Microsoft default alert policies for suspicious sending patterns, inbox rule creation, and external forwarding are designed to detect Business Email Compromise (BEC) at early stages. Disabled or unnotified alerts mean that attackers creating forwarding rules or mass-sending from compromised accounts will not trigger security team notifications.' `
                -PossibleSolution 'Re-enable disabled policies: Set-AlertPolicy -Identity "<name>" -Enabled $true. Add recipients: Set-AlertPolicy -Identity "<name>" -NotifyUser @("secops@yourdomain.com"). These are Microsoft default policies in compliance.microsoft.com > Policies > Alert policies.' `
                -Impact 'BEC attacks proceed undetected. Attackers who compromise mailboxes and create forwarding rules or send fraudulent invoices/wire transfer requests may go undetected for days or weeks, causing significant financial and reputational damage.' `
                -FrameworkMapping 'NIST-Detect' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-AlertPolicy' `
                -Remediation 'For disabled policies: Set-AlertPolicy -Identity "<PolicyName>" -Enabled $true -NotifyUser @("secops@yourdomain.com"). For policies without recipients: Set-AlertPolicy -Identity "<PolicyName>" -NotifyUser @("secops@yourdomain.com"). Integrate alert emails with SIEM or security ticketing system for automated response workflows. Review all alert policies quarterly.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P2' `
                -Notes $notes))
        }
        else {
            # Only no-recipient issues
            $findings.Add((New-TtcFinding `
                -FindingId 'DEF-MON-002' -Workload 'Defender' -Component 'AlertPolicies' `
                -CheckName 'Compromised Account Alert Policies' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected "$($noRecipients.Count) compromised account alert policy/policies are enabled but have no notification recipients: $($noRecipients -join '; ')" `
                -Explanation 'Alert policies enabled without notification recipients generate alerts only in the Microsoft Security portal. If the portal is not monitored 24/7, BEC and account takeover events will not be actioned promptly.' `
                -PossibleSolution 'Add notification recipients: Set-AlertPolicy -Identity "<PolicyName>" -NotifyUser @("secops@yourdomain.com"). Target a security mailbox monitored around the clock, not individual user inboxes.' `
                -Impact 'BEC and account takeover events are detected only if someone is actively monitoring the Security portal at the time of the alert. Delayed detection extends the window for financial fraud and data exfiltration.' `
                -FrameworkMapping 'NIST-Detect' -ZeroTrustPillar 'Identity' `
                -DataSource 'Get-AlertPolicy' `
                -Remediation 'Set-AlertPolicy -Identity "<PolicyName>" -NotifyUser @("secops@yourdomain.com"). Consider using a shared security operations mailbox rather than individual addresses. Integrate with SIEM via mail connector or Microsoft Sentinel for automated alert ingestion.' `
                -AutoFixAvailable 'Partial' -RemediationPriority 'P3' `
                -Notes $notes))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "DEF-MON-002: Compromised account alert check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'DEF-MON-002' -Workload 'Defender' -Component 'AlertPolicies' `
            -CheckName 'Compromised Account Alert Policies' -Category 'Monitoring' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Get-AlertPolicy' -Notes $_.Exception.Message))
    }

    Write-TtcLog -Level Info -Message "Defender for Office 365 assessment complete — $($findings.Count) finding(s) generated"
    return $findings.ToArray()
}
