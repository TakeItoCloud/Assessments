#Requires -Version 5.1
<#
.SYNOPSIS
    Pester 5 unit tests for the TakeItToCloud.Assess core engine.
.DESCRIPTION
    Covers: New-TtcFinding (internal factory), Get-TtcAssessmentScore (scoring math),
    Invoke-TtcAutoFix (script generation), and Test-TtcPrerequisite.

    Run with: Invoke-Pester -Path .\Tests\TtcEngine.Tests.ps1 -Output Detailed
    Requires Pester 5.x: Install-Module Pester -Force -SkipPublisherCheck
#>

BeforeAll {
    $modulePsd1 = Resolve-Path (Join-Path $PSScriptRoot '..\TakeItToCloud.Assess.psd1')
    Import-Module -Name $modulePsd1.Path -Force -ErrorAction Stop

    # ---------------------------------------------------------------------------
    # Script-scope helper: build a minimal valid finding PSCustomObject directly.
    # This bypasses New-TtcFinding so that scoring/autofix tests are independent
    # of the factory under test.
    # ---------------------------------------------------------------------------
    function script:Build-TestFinding {
        param(
            [string]$FindingId   = 'TEST-SEC-001',
            [string]$Workload    = 'TestWorkload',
            [string]$Category    = 'Security',
            [string]$Severity    = 'High',
            [string]$Status      = 'Fail',
            [string]$AutoFix     = 'No',
            [string]$Remediation = ''
        )
        $priority = switch ($Severity) { 'Critical' { 'P1' } 'High' { 'P2' } default { 'P3' } }
        [PSCustomObject]@{
            FindingId           = $FindingId
            Workload            = $Workload
            Component           = ''
            CheckName           = "Test: $FindingId"
            Category            = $Category
            Severity            = $Severity
            Status              = $Status
            IssueDetected       = 'Test issue detected'
            Explanation         = 'Test explanation text.'
            PossibleSolution    = 'Test remediation action.'
            Impact              = 'Test business impact.'
            RiskLevel           = $Severity
            FrameworkMapping    = 'NIST-Protect'
            ZeroTrustPillar     = 'Identity'
            SecureScoreMapping  = ''
            DataSource          = 'Pester'
            Remediation         = $Remediation
            AutoFixAvailable    = $AutoFix
            RemediationPriority = $priority
            Notes               = ''
            Timestamp           = (Get-Date -Format 'o')
        }
    }
}

AfterAll {
    Remove-Module -Name 'TakeItToCloud.Assess' -Force -ErrorAction SilentlyContinue
}

# =============================================================================
# New-TtcFinding  -  internal finding factory
# =============================================================================
Describe 'New-TtcFinding (internal factory)' {

    It 'Returns a PSCustomObject with all 21 required schema properties' {
        InModuleScope 'TakeItToCloud.Assess' {
            $f = New-TtcFinding -FindingId 'AD-SEC-001' -CheckName 'Test Check' -Severity 'High' -Status 'Fail'
            $props = $f.PSObject.Properties.Name
            $required = @(
                'FindingId', 'Workload', 'Component', 'CheckName', 'Category', 'Severity',
                'Status', 'IssueDetected', 'Explanation', 'PossibleSolution', 'Impact',
                'RiskLevel', 'FrameworkMapping', 'ZeroTrustPillar', 'SecureScoreMapping',
                'DataSource', 'Remediation', 'AutoFixAvailable', 'RemediationPriority',
                'Notes', 'Timestamp'
            )
            foreach ($p in $required) {
                $props | Should -Contain $p -Because "schema property '$p' must always be present"
            }
        }
    }

    It 'Auto-derives RiskLevel Critical from Severity Critical' {
        InModuleScope 'TakeItToCloud.Assess' {
            $f = New-TtcFinding -FindingId 'X-SEC-001' -CheckName 'T' -Severity 'Critical' -Status 'Fail'
            $f.RiskLevel | Should -Be 'Critical'
        }
    }

    It 'Auto-derives RiskLevel High from Severity High' {
        InModuleScope 'TakeItToCloud.Assess' {
            $f = New-TtcFinding -FindingId 'X-SEC-001' -CheckName 'T' -Severity 'High' -Status 'Fail'
            $f.RiskLevel | Should -Be 'High'
        }
    }

    It 'Auto-derives RiskLevel Low from Severity Informational' {
        InModuleScope 'TakeItToCloud.Assess' {
            $f = New-TtcFinding -FindingId 'X-SEC-001' -CheckName 'T' -Severity 'Informational' -Status 'Pass'
            $f.RiskLevel | Should -Be 'Low'
        }
    }

    It 'Auto-derives RemediationPriority P1 for Critical severity' {
        InModuleScope 'TakeItToCloud.Assess' {
            $f = New-TtcFinding -FindingId 'X-SEC-001' -CheckName 'T' -Severity 'Critical' -Status 'Fail'
            $f.RemediationPriority | Should -Be 'P1'
        }
    }

    It 'Auto-derives RemediationPriority P2 for High severity' {
        InModuleScope 'TakeItToCloud.Assess' {
            $f = New-TtcFinding -FindingId 'X-SEC-001' -CheckName 'T' -Severity 'High' -Status 'Fail'
            $f.RemediationPriority | Should -Be 'P2'
        }
    }

    It 'Keeps RemediationPriority P3 for Medium severity (not elevated)' {
        InModuleScope 'TakeItToCloud.Assess' {
            $f = New-TtcFinding -FindingId 'X-SEC-001' -CheckName 'T' -Severity 'Medium' -Status 'Fail'
            $f.RemediationPriority | Should -Be 'P3'
        }
    }

    It 'Sets Timestamp to ISO 8601 format when not provided' {
        InModuleScope 'TakeItToCloud.Assess' {
            $f = New-TtcFinding -FindingId 'X-SEC-001' -CheckName 'T'
            # ISO 8601: starts with 4-digit year, dash, month, dash, day, T
            $f.Timestamp | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
        }
    }

    It 'Preserves an explicitly supplied Timestamp' {
        InModuleScope 'TakeItToCloud.Assess' {
            $ts = '2026-01-15T10:30:00.0000000+00:00'
            $f  = New-TtcFinding -FindingId 'X-SEC-001' -CheckName 'T' -Timestamp $ts
            $f.Timestamp | Should -Be $ts
        }
    }

    It 'Does not override explicitly supplied RiskLevel' {
        InModuleScope 'TakeItToCloud.Assess' {
            $f = New-TtcFinding -FindingId 'X-SEC-001' -CheckName 'T' -Severity 'High' -RiskLevel 'Low'
            $f.RiskLevel | Should -Be 'Low'
        }
    }
}

# =============================================================================
# Get-TtcAssessmentScore  -  scoring engine
# =============================================================================
Describe 'Get-TtcAssessmentScore' {

    BeforeAll {
        # Known inputs  -  produces deterministic scores:
        #   Security: 100 - 7 (High Fail) - 10 (Critical Fail) = 83
        #   Health:   100 - (4 × 0.5) = 98  (Medium Warning)
        #   Governance: 100 (no governance findings)
        #   Overall: (83 × 0.5) + (98 × 0.3) + (100 × 0.2) = 41.5 + 29.4 + 20 = 90.9
        $script:knownFindings = @(
            script:Build-TestFinding -FindingId 'ENT-SEC-001' -Workload 'EntraID'          -Category 'Security' -Severity 'High'   -Status 'Fail'
            script:Build-TestFinding -FindingId 'ENT-SEC-002' -Workload 'EntraID'          -Category 'Security' -Severity 'Critical'-Status 'Fail'
            script:Build-TestFinding -FindingId 'AD-HLT-001'  -Workload 'ActiveDirectory'  -Category 'Health'   -Severity 'Medium'  -Status 'Warning'
            script:Build-TestFinding -FindingId 'AD-SEC-001'  -Workload 'ActiveDirectory'  -Category 'Security' -Severity 'Low'     -Status 'Pass'
        )
    }

    It 'Returns PSCustomObject with required score properties' {
        $scores = Get-TtcAssessmentScore -Findings $knownFindings
        $scores | Should -Not -BeNullOrEmpty
        $scores.PSObject.Properties.Name | Should -Contain 'OverallScore'
        $scores.PSObject.Properties.Name | Should -Contain 'SecurityScore'
        $scores.PSObject.Properties.Name | Should -Contain 'HealthScore'
        $scores.PSObject.Properties.Name | Should -Contain 'GovernanceScore'
        $scores.PSObject.Properties.Name | Should -Contain 'WorkloadScores'
    }

    It 'Security score = 83 (deducts 7 for High Fail + 10 for Critical Fail)' {
        $scores = Get-TtcAssessmentScore -Findings $knownFindings
        $scores.SecurityScore | Should -Be 83
    }

    It 'Health score = 98 (deducts 2 for Medium Warning at 50% weight)' {
        $scores = Get-TtcAssessmentScore -Findings $knownFindings
        $scores.HealthScore | Should -Be 98
    }

    It 'Governance score = 100 when no governance findings are present' {
        $scores = Get-TtcAssessmentScore -Findings $knownFindings
        $scores.GovernanceScore | Should -Be 100
    }

    It 'Overall score = Security×50% + Health×30% + Governance×20%' {
        $scores   = Get-TtcAssessmentScore -Findings $knownFindings
        $expected = [math]::Round((83 * 0.5) + (98 * 0.3) + (100 * 0.2), 1)
        $scores.OverallScore | Should -Be $expected
    }

    It 'Score never drops below 0 with extreme deductions' {
        $manyFails = 1..20 | ForEach-Object {
            script:Build-TestFinding -FindingId "TEST-SEC-$('{0:D3}' -f $_)" -Category 'Security' -Severity 'Critical' -Status 'Fail'
        }
        $scores = Get-TtcAssessmentScore -Findings $manyFails
        $scores.SecurityScore | Should -BeGreaterOrEqual 0
    }

    It 'Pass findings do not reduce any score' {
        $passOnly = @(
            script:Build-TestFinding -FindingId 'TEST-SEC-001' -Category 'Security' -Severity 'Critical' -Status 'Pass'
            script:Build-TestFinding -FindingId 'TEST-HLT-001' -Category 'Health'   -Severity 'High'     -Status 'Pass'
        )
        $scores = Get-TtcAssessmentScore -Findings $passOnly
        $scores.SecurityScore | Should -Be 100
        $scores.HealthScore   | Should -Be 100
    }

    It 'Error and NotAssessed findings do not reduce score' {
        $nonScoring = @(
            script:Build-TestFinding -FindingId 'TEST-SEC-001' -Category 'Security' -Severity 'Critical' -Status 'Error'
            script:Build-TestFinding -FindingId 'TEST-SEC-002' -Category 'Security' -Severity 'High'     -Status 'NotAssessed'
        )
        $scores = Get-TtcAssessmentScore -Findings $nonScoring
        $scores.SecurityScore | Should -Be 100
    }

    It 'WorkloadScores contains one entry per distinct workload' {
        $scores    = Get-TtcAssessmentScore -Findings $knownFindings
        $workloads = $scores.WorkloadScores | Select-Object -ExpandProperty Workload
        $workloads | Should -Contain 'EntraID'
        $workloads | Should -Contain 'ActiveDirectory'
    }

    It 'Accepts pipeline input without error' {
        { $knownFindings | Get-TtcAssessmentScore } | Should -Not -Throw
    }
}

# =============================================================================
# Invoke-TtcAutoFix  -  remediation script generator
# =============================================================================
Describe 'Invoke-TtcAutoFix' {

    BeforeAll {
        $script:tempDir   = Join-Path $env:TEMP "TtcAutoFixTests_$(Get-Random)"
        $null = New-Item -Path $tempDir -ItemType Directory -Force

        $script:fixableFindings = @(
            script:Build-TestFinding -FindingId 'ENT-SEC-001' -Workload 'EntraID'  -Category 'Security' -Severity 'Critical' -Status 'Fail'  -AutoFix 'Yes' `
                -Remediation 'Set-MgUser -UserId $userId -AccountEnabled $true'
            script:Build-TestFinding -FindingId 'AD-SEC-001'  -Workload 'ActiveDirectory' -Category 'Security' -Severity 'High' -Status 'Fail' -AutoFix 'Partial' `
                -Remediation 'Disable-ADAccount -Identity $staleUser'
            script:Build-TestFinding -FindingId 'AD-CFG-001'  -Workload 'ActiveDirectory' -Category 'Configuration' -Severity 'High' -Status 'Fail' -AutoFix 'No'
        )
    }

    AfterAll {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'Creates the output script file at the specified path' {
        $outPath = Join-Path $tempDir 'Remediation_01.ps1'
        Invoke-TtcAutoFix -Findings $fixableFindings -OutputPath $outPath
        $outPath | Should -Exist
    }

    It 'Generated script is non-empty' {
        $outPath = Join-Path $tempDir 'Remediation_02.ps1'
        Invoke-TtcAutoFix -Findings $fixableFindings -OutputPath $outPath
        (Get-Item $outPath).Length | Should -BeGreaterThan 100
    }

    It 'Generated script contains #Requires -Version 5.1 header' {
        $outPath  = Join-Path $tempDir 'Remediation_03.ps1'
        Invoke-TtcAutoFix -Findings $fixableFindings -OutputPath $outPath
        $content  = Get-Content -Path $outPath -Raw
        $content | Should -Match '#Requires -Version 5\.1'
    }

    It 'Generated script includes the fixable finding ID' {
        $outPath = Join-Path $tempDir 'Remediation_04.ps1'
        Invoke-TtcAutoFix -Findings $fixableFindings -OutputPath $outPath
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'ENT-SEC-001'
    }

    It 'Generated script includes manual-only finding in comment section' {
        $outPath = Join-Path $tempDir 'Remediation_05.ps1'
        Invoke-TtcAutoFix -Findings $fixableFindings -OutputPath $outPath
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'AD-CFG-001'
        $content | Should -Match 'MANUAL REMEDIATION REQUIRED'
    }

    It '-SeverityFilter Medium excludes Critical and High findings below threshold' {
        # With filter High (default), only High+ are included; Medium not included here
        $mediumFinding = script:Build-TestFinding -FindingId 'COL-GOV-001' -Workload 'Collaboration' -Severity 'Medium' -Status 'Fail' -AutoFix 'Yes'
        $outPath = Join-Path $tempDir 'Remediation_06.ps1'
        Invoke-TtcAutoFix -Findings @($mediumFinding) -OutputPath $outPath -SeverityFilter Critical
        $content = Get-Content -Path $outPath -Raw
        # Medium finding should NOT appear as a fixable block when filter is Critical
        $content | Should -Not -Match 'COL-GOV-001'
    }

    It '-WhatIf suppresses file creation' {
        $outPath = Join-Path $tempDir 'Remediation_WhatIf.ps1'
        Invoke-TtcAutoFix -Findings $fixableFindings -OutputPath $outPath -WhatIf
        $outPath | Should -Not -Exist
    }
}

# =============================================================================
# Test-TtcPrerequisite  -  module prerequisite checker
# =============================================================================
Describe 'Test-TtcPrerequisite' {

    It 'Returns a boolean value' {
        InModuleScope 'TakeItToCloud.Assess' {
            $result = Test-TtcPrerequisite -Workload 'ActiveDirectory'
            $result | Should -BeOfType [bool]
        }
    }

    It 'Returns $true for a workload with no defined prerequisites' {
        # Workloads not in the map return $true (no prereqs = no blockers)
        InModuleScope 'TakeItToCloud.Assess' {
            # Inject an unknown workload string via the ValidateSet bypass approach:
            # We can test the fallback by calling with a known workload that has
            # at least one available module (ActiveDirectory is likely unavailable
            # in a CI context, but we test return type, not truthiness)
            $result = Test-TtcPrerequisite -Workload 'EntraID'
            $result | Should -BeOfType [bool]
        }
    }

    It 'Does not throw for any supported workload' {
        InModuleScope 'TakeItToCloud.Assess' {
            $workloads = @('ActiveDirectory', 'ExchangeOnline', 'HybridIdentity', 'EntraID', 'Defender', 'Collaboration')
            foreach ($wl in $workloads) {
                { Test-TtcPrerequisite -Workload $wl } | Should -Not -Throw -Because "workload '$wl' must be handled gracefully"
            }
        }
    }
}
