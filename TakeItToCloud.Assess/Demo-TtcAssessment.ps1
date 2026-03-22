<#
.SYNOPSIS
    Demo script for TakeItToCloud.Assess framework.
.DESCRIPTION
    Generates sample findings to demonstrate the full pipeline:
    finding creation → scoring → CSV export → HTML report.

    Run this to validate the framework is working before
    implementing real assessor checks.
.EXAMPLE
    .\Demo-TtcAssessment.ps1
#>

# --- Load the module ---
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'TakeItToCloud.Assess'
Import-Module $modulePath -Force -Verbose

# --- Generate sample findings ---
$findings = @(
    # === Active Directory ===
    New-TtcFindingObject -FindingId "AD-SEC-001" -Workload "ActiveDirectory" -Component "Privileged Groups" `
        -CheckName "Stale Privileged Group Members" `
        -Category "Security" -Severity "High" -Status "Fail" `
        -IssueDetected "5 accounts in Domain Admins have not logged in for 90+ days" `
        -Explanation "Stale privileged accounts increase attack surface. An attacker who compromises a dormant admin account gains full domain control with low detection risk." `
        -PossibleSolution "Disable or remove inactive admin accounts. Implement a quarterly access review for all privileged groups." `
        -Impact "Full domain compromise via dormant admin credentials" `
        -FrameworkMapping "CIS-AccessControl" -ZeroTrustPillar "Identity" `
        -DataSource "Get-ADGroupMember, Get-ADUser" `
        -Remediation "1. Run Get-ADGroupMember 'Domain Admins' | Get-ADUser -Properties LastLogonDate to identify stale accounts. 2. Disable accounts inactive >90 days. 3. Implement PIM or JIT access." `
        -AutoFixAvailable "Partial"

    New-TtcFindingObject -FindingId "AD-SEC-002" -Workload "ActiveDirectory" -Component "Password Policy" `
        -CheckName "Password Policy Weaknesses" `
        -Category "Security" -Severity "High" -Status "Fail" `
        -IssueDetected "Default domain password policy allows 8-character minimum with no complexity beyond Windows defaults" `
        -Explanation "Short passwords with basic complexity are vulnerable to brute-force and credential stuffing attacks. Modern guidance recommends 14+ characters." `
        -PossibleSolution "Increase minimum password length to 14 characters. Consider implementing fine-grained password policies for privileged accounts with 20+ character requirements." `
        -Impact "Credential compromise via brute-force attacks" `
        -FrameworkMapping "NIST-Protect" -ZeroTrustPillar "Identity" `
        -DataSource "Get-ADDefaultDomainPasswordPolicy" `
        -Remediation "1. Set minimum password length to 14 via Group Policy. 2. Create fine-grained password policy for admins with 20+ char minimum. 3. Enable Azure AD Password Protection for banned password lists."

    New-TtcFindingObject -FindingId "AD-HLT-001" -Workload "ActiveDirectory" -Component "Replication" `
        -CheckName "Domain Controller Replication Health" `
        -Category "Health" -Severity "Medium" -Status "Pass" `
        -IssueDetected "All domain controllers are replicating successfully" `
        -Explanation "AD replication is operating normally across all DCs. No replication failures or delays detected." `
        -PossibleSolution "No action required. Continue monitoring replication health." `
        -FrameworkMapping "NIST-Detect" -ZeroTrustPillar "Infrastructure" `
        -DataSource "repadmin /replsummary"

    New-TtcFindingObject -FindingId "AD-MON-001" -Workload "ActiveDirectory" -Component "Audit Policy" `
        -CheckName "Audit Policy Gaps" `
        -Category "Monitoring" -Severity "Medium" -Status "Fail" `
        -IssueDetected "Logon/Logoff and Object Access audit categories are not fully configured" `
        -Explanation "Without comprehensive audit policies, security events such as privilege escalation and lateral movement may go undetected." `
        -PossibleSolution "Enable Success and Failure auditing for Logon/Logoff, Object Access, Privilege Use, and Policy Change categories." `
        -Impact "Inability to detect and investigate security incidents" `
        -FrameworkMapping "NIST-Detect" -ZeroTrustPillar "Infrastructure" `
        -DataSource "auditpol /get /category:*"

    # === Entra ID ===
    New-TtcFindingObject -FindingId "ENT-SEC-001" -Workload "EntraID" -Component "MFA" `
        -CheckName "MFA Posture for All Users" `
        -Category "Security" -Severity "Critical" -Status "Fail" `
        -IssueDetected "23% of users have not registered for MFA" `
        -Explanation "Users without MFA are vulnerable to credential theft attacks including phishing, password spray, and brute-force. MFA blocks 99.9% of automated attacks." `
        -PossibleSolution "Enforce MFA registration via Conditional Access. Use Authentication Strengths to require phishing-resistant MFA for admins." `
        -Impact "Account takeover for any user without MFA" `
        -FrameworkMapping "NIST-Protect" -ZeroTrustPillar "Identity" `
        -SecureScoreMapping "MFA registration" `
        -DataSource "Get-MgReportAuthenticationMethodUserRegistrationDetail" `
        -Remediation "1. Create CA policy requiring MFA registration for all users. 2. Set 14-day registration deadline. 3. Enable number matching for Microsoft Authenticator. 4. Consider FIDO2 keys for admins." `
        -AutoFixAvailable "Partial"

    New-TtcFindingObject -FindingId "ENT-IDN-001" -Workload "EntraID" -Component "Role Management" `
        -CheckName "Global Admin Role Assignment Hygiene" `
        -Category "Identity" -Severity "Critical" -Status "Fail" `
        -IssueDetected "8 permanent Global Administrator assignments found (recommended: 2-4)" `
        -Explanation "Excessive Global Admin assignments violate least-privilege principles. Each permanent GA is a high-value target for attackers." `
        -PossibleSolution "Reduce to 2-4 permanent GAs. Move remaining admins to PIM eligible assignments with time-limited activation and approval workflows." `
        -Impact "Expanded blast radius from any single compromised admin account" `
        -FrameworkMapping "CIS-AccessControl" -ZeroTrustPillar "Identity" `
        -SecureScoreMapping "Admin roles" `
        -DataSource "Get-MgDirectoryRoleMember" `
        -Remediation "1. Inventory all GA assignments. 2. Convert to PIM eligible where possible. 3. Require MFA + approval for GA activation. 4. Set max 4-hour activation window."

    New-TtcFindingObject -FindingId "ENT-SEC-002" -Workload "EntraID" -Component "Conditional Access" `
        -CheckName "Conditional Access Policy Coverage" `
        -Category "Security" -Severity "High" -Status "Warning" `
        -IssueDetected "Conditional Access covers sign-ins but lacks device compliance and app protection requirements" `
        -Explanation "CA policies that only check MFA without device compliance leave a gap for managed vs unmanaged device access. Full Zero Trust requires layered policies." `
        -PossibleSolution "Add CA policies requiring device compliance for corporate apps and app protection policies for mobile access." `
        -Impact "Unmanaged devices accessing corporate data without security controls" `
        -FrameworkMapping "NIST-Protect" -ZeroTrustPillar "Identity" `
        -SecureScoreMapping "Conditional Access policies" `
        -DataSource "Get-MgIdentityConditionalAccessPolicy"

    New-TtcFindingObject -FindingId "ENT-GOV-001" -Workload "EntraID" -Component "App Consent" `
        -CheckName "Application Consent Risk" `
        -Category "Governance" -Severity "Medium" -Status "Fail" `
        -IssueDetected "Users can consent to apps requesting Mail.Read and Files.ReadWrite permissions without admin approval" `
        -Explanation "Unrestricted user consent allows malicious apps to gain access to organizational data through consent phishing attacks." `
        -PossibleSolution "Restrict user consent to verified publishers only. Require admin approval for all other app consent requests." `
        -Impact "Data exfiltration via malicious OAuth applications" `
        -FrameworkMapping "ISO27001-A.9" -ZeroTrustPillar "Applications" `
        -SecureScoreMapping "App consent policies" `
        -DataSource "Get-MgPolicyAuthorizationPolicy"

    # === Hybrid Identity ===
    New-TtcFindingObject -FindingId "HYB-HLT-001" -Workload "HybridIdentity" -Component "Entra Connect" `
        -CheckName "Entra Connect Sync Health" `
        -Category "Health" -Severity "Low" -Status "Pass" `
        -IssueDetected "Entra Connect sync is healthy  -  last sync completed 12 minutes ago" `
        -Explanation "Directory synchronization is operating within expected intervals." `
        -PossibleSolution "No action required. Continue monitoring sync health via Entra Connect Health." `
        -FrameworkMapping "NIST-Identify" -ZeroTrustPillar "Identity" `
        -DataSource "Get-MgDirectoryOnPremisesSynchronization"

    New-TtcFindingObject -FindingId "HYB-SEC-003" -Workload "HybridIdentity" -Component "Break-Glass" `
        -CheckName "Break-Glass Account Protection" `
        -Category "Security" -Severity "Critical" -Status "Fail" `
        -IssueDetected "No cloud-only break-glass accounts detected with emergency access configuration" `
        -Explanation "Break-glass accounts are essential for emergency access if federation or Conditional Access lock out all admins. Without them, a misconfigured CA policy could lock everyone out of the tenant." `
        -PossibleSolution "Create 2 cloud-only break-glass accounts excluded from all CA policies, with strong passwords stored securely, and monitoring alerts on sign-in." `
        -Impact "Complete tenant lockout with no recovery path" `
        -FrameworkMapping "CIS-AccessControl" -ZeroTrustPillar "Identity" `
        -DataSource "Manual verification" `
        -Remediation "1. Create 2 cloud-only GA accounts (no MFA, excluded from CA). 2. Set 64+ char random passwords. 3. Store credentials in separate physical safes. 4. Create alert rule for any sign-in to these accounts. 5. Test quarterly." `
        -AutoFixAvailable "No"

    # === Defender (placeholder) ===
    New-TtcFindingObject -FindingId "DEF-SEC-001" -Workload "Defender" -Component "Onboarding" `
        -CheckName "Device Onboarding Coverage" `
        -Category "Security" -Severity "High" -Status "Warning" `
        -IssueDetected "72% of managed devices are onboarded to Defender for Endpoint (target: 95%+)" `
        -Explanation "Devices not onboarded to Defender lack endpoint detection and response capabilities, creating blind spots in security monitoring." `
        -PossibleSolution "Deploy Defender onboarding via Intune device configuration profiles to all managed Windows, macOS, and mobile devices." `
        -Impact "Unprotected devices as entry points for attacks" `
        -FrameworkMapping "NIST-Detect" -ZeroTrustPillar "Devices" `
        -DataSource "Get-MgDeviceManagementManagedDevice"

    # === Collaboration (placeholder) ===
    New-TtcFindingObject -FindingId "COL-GOV-001" -Workload "Collaboration" -Component "External Sharing" `
        -CheckName "SharePoint External Sharing Posture" `
        -Category "Governance" -Severity "Medium" -Status "Fail" `
        -IssueDetected "SharePoint external sharing is set to 'Anyone' (anonymous links enabled)" `
        -Explanation "Anonymous sharing links allow anyone with the link to access files without authentication, creating significant data leakage risk." `
        -PossibleSolution "Restrict sharing to 'New and existing guests' at minimum. Use sensitivity labels to block sharing on confidential content." `
        -Impact "Data leakage via uncontrolled anonymous access" `
        -FrameworkMapping "ISO27001-A.9" -ZeroTrustPillar "Data" `
        -DataSource "Get-SPOTenant"
)

Write-Host "`n=== TakeItToCloud.Assess Demo ===" -ForegroundColor Cyan
Write-Host "Generated $($findings.Count) sample findings`n" -ForegroundColor Gray

# --- Calculate scores ---
$scores = Get-TtcAssessmentScore -Findings $findings
Write-Host "SCORES:" -ForegroundColor Cyan
Write-Host "  Overall:    $($scores.OverallScore)" -ForegroundColor $(if ($scores.OverallScore -ge 80) { 'Green' } elseif ($scores.OverallScore -ge 50) { 'Yellow' } else { 'Red' })
Write-Host "  Security:   $($scores.SecurityScore)" -ForegroundColor $(if ($scores.SecurityScore -ge 80) { 'Green' } elseif ($scores.SecurityScore -ge 50) { 'Yellow' } else { 'Red' })
Write-Host "  Health:     $($scores.HealthScore)" -ForegroundColor $(if ($scores.HealthScore -ge 80) { 'Green' } elseif ($scores.HealthScore -ge 50) { 'Yellow' } else { 'Red' })
Write-Host "  Governance: $($scores.GovernanceScore)" -ForegroundColor $(if ($scores.GovernanceScore -ge 80) { 'Green' } elseif ($scores.GovernanceScore -ge 50) { 'Yellow' } else { 'Red' })

Write-Host "`nSEVERITY BREAKDOWN:" -ForegroundColor Cyan
Write-Host "  Critical: $($scores.SeveritySummary.Critical)  High: $($scores.SeveritySummary.High)  Medium: $($scores.SeveritySummary.Medium)  Low: $($scores.SeveritySummary.Low)" -ForegroundColor Gray
Write-Host "  Total Pass: $($scores.TotalPass)  Total Fail: $($scores.TotalFail)  Total Warning: $($scores.TotalWarning)" -ForegroundColor Gray

# --- Export CSV ---
$reportDir = Join-Path -Path $PSScriptRoot -ChildPath 'DemoReports'
if (-not (Test-Path $reportDir)) { New-Item -Path $reportDir -ItemType Directory -Force | Out-Null }

$csvPath = Join-Path -Path $reportDir -ChildPath "Demo_Assessment.csv"
$csvFile = Export-TtcCsvReport -Findings $findings -OutputPath $csvPath
Write-Host "`nCSV Report: $($csvFile.FullName)" -ForegroundColor Green

# --- Export HTML ---
$htmlPath = Join-Path -Path $reportDir -ChildPath "Demo_Assessment.html"
$htmlFile = Export-TtcHtmlReport -Findings $findings -Scores $scores `
    -OutputPath $htmlPath `
    -ReportTitle "Demo Security Assessment" `
    -CustomerName "Contoso Ltd" `
    -AssessedBy "Carlos - TakeItToCloud"
Write-Host "HTML Report: $($htmlFile.FullName)" -ForegroundColor Green

Write-Host "`n=== Demo Complete ===" -ForegroundColor Cyan
Write-Host "Open the HTML report in a browser to see the full interactive dashboard." -ForegroundColor Gray
