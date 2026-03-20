#Requires -Version 5.1
<#
.SYNOPSIS
    Pester 5 unit tests for TakeItToCloud.Assess report generation functions.
.DESCRIPTION
    Covers: Export-TtcCsvReport, Export-TtcHtmlReport, Get-TtcFindingSummary.
    All tests write to a temp directory and clean up after themselves.

    Run with: Invoke-Pester -Path .\Tests\TtcReports.Tests.ps1 -Output Detailed
    Requires Pester 5.x: Install-Module Pester -Force -SkipPublisherCheck
#>

BeforeAll {
    $modulePsd1 = Resolve-Path (Join-Path $PSScriptRoot '..\TakeItToCloud.Assess.psd1')
    Import-Module -Name $modulePsd1.Path -Force -ErrorAction Stop

    # Temp output directory — cleaned up in AfterAll
    $script:tempDir = Join-Path $env:TEMP "TtcReportTests_$(Get-Random)"
    $null = New-Item -Path $tempDir -ItemType Directory -Force

    # ---------------------------------------------------------------------------
    # Shared test finding set — covers all category/severity/status combinations
    # used by scoring and filtering logic.
    # ---------------------------------------------------------------------------
    $script:testFindings = @(
        [PSCustomObject]@{
            FindingId = 'ENT-SEC-001'; Workload = 'EntraID'; Component = 'MFA'
            CheckName = 'MFA Registration Coverage'; Category = 'Security'; Severity = 'Critical'
            Status = 'Fail'; IssueDetected = '5 users not registered for MFA'
            Explanation = 'MFA reduces account takeover risk.'; PossibleSolution = 'Enforce MFA via Conditional Access.'
            Impact = 'High breach risk'; RiskLevel = 'Critical'; FrameworkMapping = 'NIST-Protect'
            ZeroTrustPillar = 'Identity'; SecureScoreMapping = 'Require MFA for all users'
            DataSource = 'Get-MgReportAuthenticationMethodUserRegistrationDetail'
            Remediation = 'Set-MgUser -UserId $userId -StrongAuthenticationRequirements $req'
            AutoFixAvailable = 'Yes'; RemediationPriority = 'P1'; Notes = ''; Timestamp = (Get-Date -Format 'o')
        },
        [PSCustomObject]@{
            FindingId = 'AD-HLT-001'; Workload = 'ActiveDirectory'; Component = 'Replication'
            CheckName = 'DC Replication Health'; Category = 'Health'; Severity = 'High'
            Status = 'Fail'; IssueDetected = 'Replication errors on DC01'
            Explanation = 'Replication failures cause directory inconsistency.'
            PossibleSolution = 'Run repadmin /syncall.'; Impact = 'Directory corruption risk'
            RiskLevel = 'High'; FrameworkMapping = 'CIS-SecureConfig'; ZeroTrustPillar = 'Infrastructure'
            SecureScoreMapping = ''; DataSource = 'Get-ADReplicationFailure'
            Remediation = ''; AutoFixAvailable = 'No'; RemediationPriority = 'P2'
            Notes = ''; Timestamp = (Get-Date -Format 'o')
        },
        [PSCustomObject]@{
            FindingId = 'COL-SEC-001'; Workload = 'Collaboration'; Component = 'SharePoint'
            CheckName = 'External Sharing Level'; Category = 'Security'; Severity = 'High'
            Status = 'Warning'; IssueDetected = 'External sharing set to ExistingExternalUsersOnly'
            Explanation = 'Overly permissive sharing exposes data.'; PossibleSolution = 'Restrict to specific people.'
            Impact = 'Data leakage'; RiskLevel = 'High'; FrameworkMapping = 'NIST-Protect'
            ZeroTrustPillar = 'Data'; SecureScoreMapping = 'Review SharePoint sharing settings'
            DataSource = 'Invoke-MgGraphRequest'; Remediation = ''; AutoFixAvailable = 'No'
            RemediationPriority = 'P2'; Notes = ''; Timestamp = (Get-Date -Format 'o')
        },
        [PSCustomObject]@{
            FindingId = 'HYB-HLT-001'; Workload = 'HybridIdentity'; Component = 'DirSync'
            CheckName = 'Directory Sync Status'; Category = 'Health'; Severity = 'Medium'
            Status = 'Pass'; IssueDetected = ''; Explanation = 'Sync is healthy.'
            PossibleSolution = ''; Impact = ''; RiskLevel = 'Medium'; FrameworkMapping = 'CIS-AccessControl'
            ZeroTrustPillar = 'Identity'; SecureScoreMapping = ''; DataSource = 'Get-MgOrganization'
            Remediation = ''; AutoFixAvailable = 'No'; RemediationPriority = 'P3'
            Notes = ''; Timestamp = (Get-Date -Format 'o')
        },
        [PSCustomObject]@{
            FindingId = 'DEF-SEC-001'; Workload = 'Defender'; Component = 'SafeLinks'
            CheckName = 'Safe Links Policy Coverage'; Category = 'Security'; Severity = 'High'
            Status = 'NotAssessed'; IssueDetected = 'Defender P1 not available'
            Explanation = 'Requires Defender for Office 365 Plan 1.'; PossibleSolution = 'Upgrade license.'
            Impact = 'No URL detonation protection'; RiskLevel = 'High'; FrameworkMapping = 'NIST-Protect'
            ZeroTrustPillar = 'Applications'; SecureScoreMapping = ''; DataSource = 'Get-SafeLinksPolicy'
            Remediation = ''; AutoFixAvailable = 'No'; RemediationPriority = 'P2'
            Notes = 'Defender P1 not licensed'; Timestamp = (Get-Date -Format 'o')
        }
    )

    $script:testScores = Get-TtcAssessmentScore -Findings $testFindings
}

AfterAll {
    Remove-Module -Name 'TakeItToCloud.Assess' -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

# =============================================================================
# Export-TtcCsvReport
# =============================================================================
Describe 'Export-TtcCsvReport' {

    BeforeAll {
        $script:csvPath = Join-Path $tempDir 'TestReport.csv'
        Export-TtcCsvReport -Findings $testFindings -OutputPath $csvPath
    }

    It 'Creates the CSV file at the specified path' {
        $csvPath | Should -Exist
    }

    It 'CSV file is non-empty' {
        (Get-Item $csvPath).Length | Should -BeGreaterThan 0
    }

    It 'CSV contains expected column headers' {
        $content = Get-Content -Path $csvPath -Raw
        $content | Should -Match 'FindingId'
        $content | Should -Match 'Severity'
        $content | Should -Match 'Status'
        $content | Should -Match 'Workload'
        $content | Should -Match 'CheckName'
    }

    It 'CSV contains expected finding data' {
        $content = Get-Content -Path $csvPath -Raw
        $content | Should -Match 'ENT-SEC-001'
        $content | Should -Match 'AD-HLT-001'
    }

    It 'CSV row count equals number of findings plus one header row' {
        $rows = Import-Csv -Path $csvPath
        $rows.Count | Should -Be $testFindings.Count
    }
}

# =============================================================================
# Export-TtcHtmlReport
# =============================================================================
Describe 'Export-TtcHtmlReport' {

    BeforeAll {
        $script:htmlPath = Join-Path $tempDir 'TestReport.html'
        Export-TtcHtmlReport -Findings $testFindings -Scores $testScores `
            -OutputPath $htmlPath -ReportTitle 'Pester Test Report' `
            -CustomerName 'Pester Corp' -AssessedBy 'Automated Test'
    }

    It 'Creates the HTML file at the specified path' {
        $htmlPath | Should -Exist
    }

    It 'HTML file is non-empty' {
        (Get-Item $htmlPath).Length | Should -BeGreaterThan 1000
    }

    It 'HTML file contains valid html opening tag' {
        $content = Get-Content -Path $htmlPath -Raw
        $content | Should -Match '<html'
    }

    It 'HTML report contains the customer name in content' {
        $content = Get-Content -Path $htmlPath -Raw
        $content | Should -Match 'Pester Corp'
    }

    It 'HTML report contains at least one finding ID from the test set' {
        $content = Get-Content -Path $htmlPath -Raw
        $content | Should -Match 'ENT-SEC-001'
    }

    It 'HTML report is self-contained (no external CDN references)' {
        $content = Get-Content -Path $htmlPath -Raw
        # Should not reference googleapis, cdnjs, jsdelivr, or unpkg
        $content | Should -Not -Match 'googleapis\.com'
        $content | Should -Not -Match 'cdnjs\.cloudflare\.com'
        $content | Should -Not -Match 'jsdelivr\.net'
        $content | Should -Not -Match 'unpkg\.com'
    }
}

# =============================================================================
# Get-TtcFindingSummary
# =============================================================================
Describe 'Get-TtcFindingSummary' {

    It 'Runs without throwing when given valid findings' {
        { Get-TtcFindingSummary -Findings $testFindings } | Should -Not -Throw
    }

    It 'Accepts pre-computed Scores object without recalculating' {
        { Get-TtcFindingSummary -Findings $testFindings -Scores $testScores } | Should -Not -Throw
    }

    It 'Accepts pipeline input without throwing' {
        { $testFindings | Get-TtcFindingSummary } | Should -Not -Throw
    }

    It '-PassThru returns PSCustomObject with expected properties' {
        $summary = Get-TtcFindingSummary -Findings $testFindings -PassThru
        $summary                           | Should -Not -BeNullOrEmpty
        $summary.TotalFindings             | Should -Be $testFindings.Count
        $summary.PSObject.Properties.Name  | Should -Contain 'CriticalFailCount'
        $summary.PSObject.Properties.Name  | Should -Contain 'HighFailCount'
        $summary.PSObject.Properties.Name  | Should -Contain 'OverallScore'
        $summary.PSObject.Properties.Name  | Should -Contain 'TopFindings'
    }

    It '-PassThru CriticalFailCount matches actual Critical Fail count in findings' {
        $summary       = Get-TtcFindingSummary -Findings $testFindings -PassThru
        $expectedCrit  = ($testFindings | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Fail' } | Measure-Object).Count
        $summary.CriticalFailCount | Should -Be $expectedCrit
    }

    It '-TopFindingsSeverity Critical limits top findings to Critical only' {
        $summary = Get-TtcFindingSummary -Findings $testFindings -TopFindingsSeverity Critical -PassThru
        foreach ($f in $summary.TopFindings) {
            $f.Severity | Should -Be 'Critical'
        }
    }

    It 'Does not return output without -PassThru' {
        $result = Get-TtcFindingSummary -Findings $testFindings
        $result | Should -BeNullOrEmpty
    }
}
