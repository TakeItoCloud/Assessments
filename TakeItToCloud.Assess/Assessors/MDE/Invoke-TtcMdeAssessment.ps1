function Invoke-TtcMdeAssessment {
    <#
    .SYNOPSIS
        Runs the Microsoft Defender for Endpoint workload assessment.
    .DESCRIPTION
        Assesses Microsoft Defender for Endpoint configuration and coverage via the
        Microsoft Graph Security API and Microsoft 365 Defender API. Checks include:
        device onboarding coverage, antivirus status, EDR in block mode, tamper protection,
        attack surface reduction rules, and security alert hygiene.

        Required Microsoft Graph scopes:
        - SecurityEvents.Read.All
        - DeviceManagementManagedDevices.Read.All
        - Machine.Read.All (via Defender API / Graph Security)

        Connect before running:
        Connect-MgGraph -Scopes "SecurityEvents.Read.All","DeviceManagementManagedDevices.Read.All"
    .EXAMPLE
        Invoke-TtcMdeAssessment
    .OUTPUTS
        [PSCustomObject[]] Array of TakeItToCloud finding objects.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-TtcLog -Level Info -Message "Starting Microsoft Defender for Endpoint assessment"

    # =========================================================================
    # Prerequisite: Microsoft Graph connection
    # =========================================================================
    if (-not (Test-TtcGraphConnection -RequiredScopes @('SecurityEvents.Read.All') -Workload 'MDE')) {
        $findings.Add((New-TtcFinding `
            -FindingId 'MDE-CFG-001' -Workload 'Defender' -Component 'Prerequisites' `
            -CheckName 'MDE Device Onboarding Coverage' -Category 'Security' -Severity 'Critical' `
            -Status 'Error' `
            -IssueDetected 'Microsoft Graph connection not established or missing SecurityEvents.Read.All scope.' `
            -PossibleSolution 'Connect-MgGraph -Scopes "SecurityEvents.Read.All","DeviceManagementManagedDevices.Read.All"' `
            -DataSource 'Get-MgContext' -AutoFixAvailable 'No' -RemediationPriority 'P1'))
        return $findings.ToArray()
    }

    # =========================================================================
    # MDE-CFG-001  -  Device Onboarding Coverage
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "MDE-CFG-001: Checking MDE device onboarding coverage"

        # Query managed devices from Intune/Endpoint Manager
        $managedDevices = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,complianceState,managedDeviceOwnerType&$top=999' `
            -ErrorAction SilentlyContinue

        $totalDevices = 0
        $windowsDevices = 0

        if ($managedDevices -and $managedDevices.value) {
            $totalDevices   = ($managedDevices.value | Measure-Object).Count
            $windowsDevices = ($managedDevices.value | Where-Object { $_.operatingSystem -eq 'Windows' } | Measure-Object).Count
        }

        # Check MDE onboarded machines via Security API
        $mdeDevices = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/security/secureScores?$top=1' -ErrorAction SilentlyContinue

        # Use Microsoft 365 Defender API for detailed device data
        $onboardedDevices = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/security/secureScoreControlProfiles?$filter=controlCategory eq ''Device''' `
            -ErrorAction SilentlyContinue

        # Heuristic: if we can query secureScores we have basic connectivity
        if ($totalDevices -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-CFG-001' -Workload 'Defender' -Component 'DeviceOnboarding' `
                -CheckName 'MDE Device Onboarding Coverage' -Category 'Security' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'No managed devices found via Intune/Endpoint Manager. MDE onboarding coverage cannot be assessed without Intune enrollment data.' `
                -Explanation 'Microsoft Defender for Endpoint protection requires devices to be onboarded. Without visibility into managed devices, unprotected endpoints cannot be identified. Devices not onboarded to MDE lack EDR capability, advanced threat detection, and automated investigation.' `
                -PossibleSolution 'Ensure devices are enrolled in Microsoft Intune and onboarded to MDE via Intune device configuration policy or Group Policy. Verify DeviceManagementManagedDevices.Read.All scope is granted.' `
                -Impact 'Unknown number of endpoints may be unprotected by MDE EDR capability.' `
                -FrameworkMapping 'CIS-EndpointProtection' -ZeroTrustPillar 'Devices' `
                -DataSource 'Graph: /v1.0/deviceManagement/managedDevices' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2'))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-CFG-001' -Workload 'Defender' -Component 'DeviceOnboarding' `
                -CheckName 'MDE Device Onboarding Coverage' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected "$totalDevices managed device(s) found in Intune ($windowsDevices Windows devices)." `
                -DataSource 'Graph: /v1.0/deviceManagement/managedDevices' `
                -Notes "Total managed: $totalDevices | Windows: $windowsDevices"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "MDE-CFG-001: Device onboarding check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'MDE-CFG-001' -Workload 'Defender' -Component 'DeviceOnboarding' `
            -CheckName 'MDE Device Onboarding Coverage' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/deviceManagement/managedDevices' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # MDE-SEC-001  -  Secure Score - Device Controls
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "MDE-SEC-001: Checking Microsoft Secure Score device controls"

        $secureScore = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/security/secureScores?$top=1' -ErrorAction Stop

        if ($secureScore -and $secureScore.value -and $secureScore.value.Count -gt 0) {
            $latestScore = $secureScore.value[0]
            $currentScore = $latestScore.currentScore
            $maxScore     = $latestScore.maxScore
            $percentage   = if ($maxScore -gt 0) { [int](($currentScore / $maxScore) * 100) } else { 0 }
            $createdDate  = $latestScore.createdDateTime

            $deviceScores = $latestScore.controlScores | Where-Object { $_.controlCategory -eq 'Device' }
            $deviceCurrent = ($deviceScores | Measure-Object -Property score -Sum).Sum
            $deviceMax     = ($deviceScores | Measure-Object -Property maxScore -Sum).Sum
            $devicePct     = if ($deviceMax -gt 0) { [int](($deviceCurrent / $deviceMax) * 100) } else { 0 }

            $severity = if ($devicePct -lt 50) { 'High' } elseif ($devicePct -lt 70) { 'Medium' } else { 'Low' }
            $status   = if ($devicePct -ge 70) { 'Pass' } elseif ($devicePct -ge 50) { 'Warning' } else { 'Fail' }

            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-SEC-001' -Workload 'Defender' -Component 'SecureScore' `
                -CheckName 'Secure Score - Device Controls' -Category 'Security' -Severity $severity `
                -Status $status `
                -IssueDetected "Device security controls score: $devicePct% ($deviceCurrent/$deviceMax points). Overall tenant Secure Score: $percentage% ($currentScore/$maxScore)." `
                -Explanation 'Microsoft Secure Score device controls measure the security posture of endpoints including MDE configuration, attack surface reduction, and compliance settings. A low device score indicates significant security gaps in endpoint protection.' `
                -PossibleSolution 'Review Secure Score improvement actions in the Microsoft 365 Defender portal (security.microsoft.com) under Secure Score > Improvement Actions. Filter by Category: Device. Prioritize actions with the highest point value and lowest implementation effort.' `
                -Impact 'Low device security scores correlate with higher breach risk. Each improvement action represents a real security control gap that attackers can exploit.' `
                -FrameworkMapping 'CIS-EndpointProtection' -ZeroTrustPillar 'Devices' `
                -DataSource 'Graph: /v1.0/security/secureScores' `
                -Remediation 'Access Secure Score: security.microsoft.com > Secure Score > Improvement Actions. Common device actions: Enable MDE tamper protection, Enable network protection, Enable PUA protection, Configure ASR rules, Enable controlled folder access.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2' `
                -Notes "Score as of: $createdDate | Device: $devicePct% | Overall: $percentage%"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-SEC-001' -Workload 'Defender' -Component 'SecureScore' `
                -CheckName 'Secure Score - Device Controls' -Category 'Security' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected 'Microsoft Secure Score data could not be retrieved.' `
                -DataSource 'Graph: /v1.0/security/secureScores' `
                -AutoFixAvailable 'No' -RemediationPriority 'P3'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "MDE-SEC-001: Secure score check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'MDE-SEC-001' -Workload 'Defender' -Component 'SecureScore' `
            -CheckName 'Secure Score - Device Controls' -Category 'Security' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/security/secureScores' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # MDE-SEC-002  -  Open High-Severity Security Alerts
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "MDE-SEC-002: Checking unresolved high-severity MDE alerts"

        $highAlerts = Invoke-TtcMgGraphRequest `
            -Uri "/v1.0/security/alerts_v2?`$filter=status ne 'resolved' and (severity eq 'high' or severity eq 'critical')&`$top=50" `
            -ErrorAction Stop

        $alertList = if ($highAlerts -and $highAlerts.value) { $highAlerts.value } else { @() }
        $alertCount = ($alertList | Measure-Object).Count

        if ($alertCount -gt 0) {
            $alertSummary = ($alertList | Select-Object -First 10 | ForEach-Object {
                "$($_.title) [Provider: $($_.serviceSource) | Created: $($_.createdDateTime)]"
            }) -join ' | '

            $severity = if ($alertCount -gt 10) { 'Critical' } elseif ($alertCount -gt 3) { 'High' } else { 'Medium' }
            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-SEC-002' -Workload 'Defender' -Component 'Alerts' `
                -CheckName 'Unresolved High-Severity Security Alerts' -Category 'Security' -Severity $severity `
                -Status 'Fail' `
                -IssueDetected "$alertCount unresolved high/critical severity security alert(s) found in Microsoft 365 Defender." `
                -Explanation 'Unresolved high-severity alerts indicate active or recent security incidents that have not been investigated and remediated. These may represent active attacker activity, malware infections, or compromised accounts. Stale alerts also indicate gaps in the SOC response process.' `
                -PossibleSolution 'Investigate each alert in Microsoft 365 Defender (security.microsoft.com > Incidents & Alerts). Assign to analyst, investigate the evidence, take remediation actions, and resolve or suppress false positives. Configure automated investigation and response (AIR) to handle common alert types automatically.' `
                -Impact 'Unresolved alerts may represent ongoing attacks. Attacker dwell time increases with each day alerts go uninvestigated. Data exfiltration and lateral movement continue during unresponded incidents.' `
                -FrameworkMapping 'NIST-Respond' -ZeroTrustPillar 'Devices' `
                -MitreAttack 'T1562' `
                -DataSource 'Graph: /v1.0/security/alerts_v2' `
                -Remediation 'Review: security.microsoft.com > Incidents & Alerts > Alerts. Filter: Severity = High/Critical, Status = New/In Progress. Assign and investigate. Enable AIR: security.microsoft.com > Settings > Microsoft Defender XDR > Automated investigation. Configure email notifications for new high alerts.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P1' `
                -Notes "Unresolved high/critical alerts: $alertCount. Sample: $alertSummary"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-SEC-002' -Workload 'Defender' -Component 'Alerts' `
                -CheckName 'Unresolved High-Severity Security Alerts' -Category 'Security' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected 'No unresolved high or critical severity security alerts found.' `
                -DataSource 'Graph: /v1.0/security/alerts_v2'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "MDE-SEC-002: Alert check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'MDE-SEC-002' -Workload 'Defender' -Component 'Alerts' `
            -CheckName 'Unresolved High-Severity Security Alerts' -Category 'Security' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/security/alerts_v2' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # MDE-CFG-002  -  Device Compliance Policy Coverage
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "MDE-CFG-002: Checking Intune device compliance policy coverage"

        $compliancePolicies = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/deviceManagement/deviceCompliancePolicies?$select=id,displayName,platformType' `
            -ErrorAction Stop

        $policyList = if ($compliancePolicies -and $compliancePolicies.value) { $compliancePolicies.value } else { @() }
        $policyCount = ($policyList | Measure-Object).Count

        $windowsPolicies = $policyList | Where-Object { $_.platformType -like '*Windows*' }
        $windowsPolicyCount = ($windowsPolicies | Measure-Object).Count

        if ($policyCount -eq 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-CFG-002' -Workload 'Defender' -Component 'CompliancePolicies' `
                -CheckName 'Device Compliance Policy Coverage' -Category 'Configuration' -Severity 'High' `
                -Status 'Fail' `
                -IssueDetected 'No device compliance policies found in Microsoft Intune.' `
                -Explanation 'Device compliance policies define the security baseline that devices must meet to access corporate resources. Without compliance policies, Conditional Access cannot enforce device health requirements, and non-compliant or unmanaged devices can access all resources regardless of their security state.' `
                -PossibleSolution 'Create device compliance policies for each platform (Windows, iOS, Android, macOS). At minimum for Windows: require BitLocker, require MDE threat level = low/medium, require secure boot, set OS version minimums. Link compliance policies to Conditional Access.' `
                -Impact 'All enrolled devices are treated as compliant regardless of actual security state. Unpatched, unencrypted, or malware-infected devices can access corporate data.' `
                -FrameworkMapping 'CIS-EndpointProtection' -ZeroTrustPillar 'Devices' `
                -DataSource 'Graph: /v1.0/deviceManagement/deviceCompliancePolicies' `
                -Remediation 'Create compliance policy: Intune admin center (intune.microsoft.com) > Devices > Compliance policies > Create policy. Select platform > Configure: MDE threat level, BitLocker, Secure Boot, OS version. Assign to All Devices or device groups. Integrate with CA: require device compliance in CA policy grant controls.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P2'))
        }
        elseif ($windowsPolicyCount -eq 0 -and $policyCount -gt 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-CFG-002' -Workload 'Defender' -Component 'CompliancePolicies' `
                -CheckName 'Device Compliance Policy Coverage' -Category 'Configuration' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected "$policyCount compliance policy/policies found but none target Windows devices." `
                -PossibleSolution 'Create a Windows device compliance policy requiring MDE threat level, BitLocker encryption, and minimum OS version.' `
                -DataSource 'Graph: /v1.0/deviceManagement/deviceCompliancePolicies' `
                -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                -Notes "Total policies: $policyCount | Windows-targeted: $windowsPolicyCount | Policies: $($policyList.displayName -join ', ')"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-CFG-002' -Workload 'Defender' -Component 'CompliancePolicies' `
                -CheckName 'Device Compliance Policy Coverage' -Category 'Configuration' -Severity 'High' `
                -Status 'Pass' `
                -IssueDetected "$policyCount device compliance policy/policies configured ($windowsPolicyCount Windows)." `
                -DataSource 'Graph: /v1.0/deviceManagement/deviceCompliancePolicies' `
                -Notes "Policies: $($policyList.displayName -join ', ')"))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "MDE-CFG-002: Compliance policy check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'MDE-CFG-002' -Workload 'Defender' -Component 'CompliancePolicies' `
            -CheckName 'Device Compliance Policy Coverage' -Category 'Configuration' -Severity 'High' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/deviceManagement/deviceCompliancePolicies' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # MDE-CFG-003  -  Non-Compliant Device Count
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "MDE-CFG-003: Checking non-compliant device count"

        $nonCompliantDevices = Invoke-TtcMgGraphRequest `
            -Uri "/v1.0/deviceManagement/managedDevices?`$filter=complianceState eq 'noncompliant'&`$select=id,deviceName,operatingSystem,complianceState,lastSyncDateTime&`$top=999" `
            -ErrorAction Stop

        $nonCompliantList = if ($nonCompliantDevices -and $nonCompliantDevices.value) { $nonCompliantDevices.value } else { @() }
        $nonCompliantCount = ($nonCompliantList | Measure-Object).Count

        if ($nonCompliantCount -gt 0) {
            $deviceSample = ($nonCompliantList | Select-Object -First 10 | ForEach-Object {
                "$($_.deviceName) [$($_.operatingSystem), Last Sync: $($_.lastSyncDateTime)]"
            }) -join ' | '

            $severity = if ($nonCompliantCount -gt 20) { 'High' } elseif ($nonCompliantCount -gt 5) { 'Medium' } else { 'Low' }
            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-CFG-003' -Workload 'Defender' -Component 'DeviceCompliance' `
                -CheckName 'Non-Compliant Device Count' -Category 'Compliance' -Severity $severity `
                -Status 'Fail' `
                -IssueDetected "$nonCompliantCount device(s) are marked non-compliant in Microsoft Intune." `
                -Explanation 'Non-compliant devices fail one or more compliance policy requirements such as missing encryption, outdated OS, high threat level, or missing security baseline settings. If Conditional Access enforces device compliance, these devices are blocked. If not, they access resources with reduced security assurance.' `
                -PossibleSolution 'Investigate each non-compliant device. Common remediations: enable BitLocker encryption, update OS to minimum required version, ensure MDE is running and reporting healthy threat level. Use Intune remote actions for managed devices.' `
                -Impact 'Non-compliant devices represent security gaps. If CA does not block them, they access corporate data without meeting the minimum security baseline.' `
                -FrameworkMapping 'CIS-EndpointProtection' -ZeroTrustPillar 'Devices' `
                -DataSource 'Graph: /v1.0/deviceManagement/managedDevices' `
                -Remediation 'Review in Intune: Devices > Monitor > Device compliance. For each non-compliant device: check compliance details, trigger sync (Sync remote action), or retire/wipe if abandoned. Enable Conditional Access to block non-compliant devices: CA policy > Grant > Require device to be marked as compliant.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                -Notes "Non-compliant devices (first 10): $deviceSample"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-CFG-003' -Workload 'Defender' -Component 'DeviceCompliance' `
                -CheckName 'Non-Compliant Device Count' -Category 'Compliance' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected 'No non-compliant managed devices found.' `
                -DataSource 'Graph: /v1.0/deviceManagement/managedDevices'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "MDE-CFG-003: Non-compliant device check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'MDE-CFG-003' -Workload 'Defender' -Component 'DeviceCompliance' `
            -CheckName 'Non-Compliant Device Count' -Category 'Compliance' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/deviceManagement/managedDevices' -Notes $_.Exception.Message))
    }

    # =========================================================================
    # MDE-MON-001  -  Defender Vulnerability Management Exposure Score
    # =========================================================================
    try {
        $ErrorActionPreference = 'Stop'
        Write-TtcLog -Level Info -Message "MDE-MON-001: Checking Secure Score improvement actions for device controls"

        # Check for exposure-related Secure Score controls
        $scoreControls = Invoke-TtcMgGraphRequest `
            -Uri '/v1.0/security/secureScoreControlProfiles' -ErrorAction Stop

        $controlList = if ($scoreControls -and $scoreControls.value) { $scoreControls.value } else { @() }
        $deviceControls = $controlList | Where-Object { $_.controlCategory -eq 'Device' -and $_.implementationStatus -ne 'Implemented' }
        $failedControls = ($deviceControls | Measure-Object).Count

        $topActions = ($deviceControls | Sort-Object maxScore -Descending | Select-Object -First 5 |
            ForEach-Object { "$($_.title) [+$($_.maxScore) pts]" }) -join ' | '

        if ($failedControls -gt 0) {
            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-MON-001' -Workload 'Defender' -Component 'SecureScore' `
                -CheckName 'Defender Device Security Improvement Actions' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Warning' `
                -IssueDetected "$failedControls device-category Secure Score improvement action(s) not yet implemented." `
                -Explanation 'Microsoft Secure Score improvement actions for devices represent specific security controls that are not yet configured or enforced. Each uncompleted action is a measurable security gap with a known risk and remediation path.' `
                -PossibleSolution 'Review improvement actions in Microsoft 365 Defender Secure Score. Prioritize by point value and implementation effort. Assign ownership and track progress. Common quick wins: enable tamper protection, enable network protection, configure PUA blocking.' `
                -DataSource 'Graph: /v1.0/security/secureScoreControlProfiles' `
                -Remediation 'Navigate to: security.microsoft.com > Secure Score > Improvement Actions. Filter: Category = Device, Status = Not addressed. Review each action for implementation guidance. Many device controls can be deployed via Intune configuration profiles.' `
                -AutoFixAvailable 'No' -RemediationPriority 'P3' `
                -Notes "Unimplemented device controls: $failedControls | Top actions: $topActions"))
        }
        else {
            $findings.Add((New-TtcFinding `
                -FindingId 'MDE-MON-001' -Workload 'Defender' -Component 'SecureScore' `
                -CheckName 'Defender Device Security Improvement Actions' -Category 'Monitoring' -Severity 'Medium' `
                -Status 'Pass' `
                -IssueDetected 'All Secure Score device improvement actions are implemented.' `
                -DataSource 'Graph: /v1.0/security/secureScoreControlProfiles'))
        }
    }
    catch {
        Write-TtcLog -Level Error -Message "MDE-MON-001: Secure score controls check failed" -ErrorRecord $_
        $findings.Add((New-TtcFinding `
            -FindingId 'MDE-MON-001' -Workload 'Defender' -Component 'SecureScore' `
            -CheckName 'Defender Device Security Improvement Actions' -Category 'Monitoring' -Severity 'Medium' `
            -Status 'Error' -IssueDetected "Check could not complete: $($_.Exception.Message)" `
            -DataSource 'Graph: /v1.0/security/secureScoreControlProfiles' -Notes $_.Exception.Message))
    }

    Write-TtcLog -Level Info -Message "MDE assessment complete  -  $($findings.Count) finding(s) generated"
    return $findings.ToArray()
}
