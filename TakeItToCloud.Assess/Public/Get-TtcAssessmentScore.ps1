function Get-TtcAssessmentScore {
    <#
    .SYNOPSIS
        Calculates assessment scores from finding objects.
    .DESCRIPTION
        Computes Health, Security, and Governance scores (0-100) from assessment
        findings. Also produces per-workload breakdowns and an overall environment
        score using weighted averaging (Security 50%, Health 30%, Governance 20%).

        Only Fail and Warning findings reduce scores. Warning findings count at 50% weight.
        Pass, Error, and NotAssessed findings do not affect scores.
    .PARAMETER Findings
        Array of finding objects from an assessment run.
    .OUTPUTS
        PSCustomObject with HealthScore, SecurityScore, GovernanceScore, OverallScore,
        and WorkloadScores.
    .EXAMPLE
        $scores = Get-TtcAssessmentScore -Findings $allFindings
        $scores.OverallScore  # 72
        $scores.WorkloadScores  # Per-workload breakdown
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Findings
    )

    begin {
        $allFindings = [System.Collections.ArrayList]::new()
    }

    process {
        foreach ($f in $Findings) {
            [void]$allFindings.Add($f)
        }
    }

    end {
        Write-TtcLog -Level Info -Message "Calculating scores for $($allFindings.Count) findings"

        # --- Category-to-score mapping ---
        $healthCategories     = @('Health', 'Configuration', 'Resilience')
        $securityCategories   = @('Security', 'Identity', 'Monitoring')
        $governanceCategories = @('Compliance', 'Governance')

        # --- Helper: calculate score for a set of findings ---
        $calcScore = {
            param([PSCustomObject[]]$ScopeFindings)

            $deduction = 0
            foreach ($f in $ScopeFindings) {
                if ($f.Status -eq 'Fail') {
                    $deduction += (Get-TtcSeverityWeight -Severity $f.Severity)
                }
                elseif ($f.Status -eq 'Warning') {
                    $deduction += (Get-TtcSeverityWeight -Severity $f.Severity) * 0.5
                }
            }
            [math]::Max(0, [math]::Round(100 - $deduction, 1))
        }

        # --- Compute top-level scores ---
        $healthFindings     = $allFindings | Where-Object { $_.Category -in $healthCategories }
        $securityFindings   = $allFindings | Where-Object { $_.Category -in $securityCategories }
        $governanceFindings = $allFindings | Where-Object { $_.Category -in $governanceCategories }

        $healthScore     = & $calcScore $healthFindings
        $securityScore   = & $calcScore $securityFindings
        $governanceScore = & $calcScore $governanceFindings

        # --- Overall: Security 50%, Health 30%, Governance 20% ---
        $overallScore = [math]::Round(($securityScore * 0.5) + ($healthScore * 0.3) + ($governanceScore * 0.2), 1)

        # --- Per-workload scores ---
        $workloads = $allFindings | Select-Object -ExpandProperty Workload -Unique
        $workloadScores = foreach ($wl in $workloads) {
            $wlFindings = $allFindings | Where-Object { $_.Workload -eq $wl }

            $wlHealth     = & $calcScore ($wlFindings | Where-Object { $_.Category -in $healthCategories })
            $wlSecurity   = & $calcScore ($wlFindings | Where-Object { $_.Category -in $securityCategories })
            $wlGovernance = & $calcScore ($wlFindings | Where-Object { $_.Category -in $governanceCategories })
            $wlOverall    = [math]::Round(($wlSecurity * 0.5) + ($wlHealth * 0.3) + ($wlGovernance * 0.2), 1)

            [PSCustomObject]@{
                Workload        = $wl
                HealthScore     = $wlHealth
                SecurityScore   = $wlSecurity
                GovernanceScore = $wlGovernance
                OverallScore    = $wlOverall
                TotalFindings   = $wlFindings.Count
                FailCount       = ($wlFindings | Where-Object { $_.Status -eq 'Fail' }).Count
                WarningCount    = ($wlFindings | Where-Object { $_.Status -eq 'Warning' }).Count
                PassCount       = ($wlFindings | Where-Object { $_.Status -eq 'Pass' }).Count
            }
        }

        # --- Summary counts ---
        $severitySummary = @{
            Critical      = ($allFindings | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Fail' }).Count
            High          = ($allFindings | Where-Object { $_.Severity -eq 'High' -and $_.Status -eq 'Fail' }).Count
            Medium        = ($allFindings | Where-Object { $_.Severity -eq 'Medium' -and $_.Status -eq 'Fail' }).Count
            Low           = ($allFindings | Where-Object { $_.Severity -eq 'Low' -and $_.Status -eq 'Fail' }).Count
            Informational = ($allFindings | Where-Object { $_.Severity -eq 'Informational' }).Count
        }

        $result = [PSCustomObject]@{
            HealthScore      = $healthScore
            SecurityScore    = $securityScore
            GovernanceScore  = $governanceScore
            OverallScore     = $overallScore
            TotalFindings    = $allFindings.Count
            TotalFail        = ($allFindings | Where-Object { $_.Status -eq 'Fail' }).Count
            TotalWarning     = ($allFindings | Where-Object { $_.Status -eq 'Warning' }).Count
            TotalPass        = ($allFindings | Where-Object { $_.Status -eq 'Pass' }).Count
            TotalError       = ($allFindings | Where-Object { $_.Status -eq 'Error' }).Count
            SeveritySummary  = $severitySummary
            WorkloadScores   = $workloadScores
            GeneratedAt      = Get-Date -Format 'o'
        }

        Write-TtcLog -Level Info -Message "Scores calculated — Overall: $overallScore | Security: $securityScore | Health: $healthScore | Governance: $governanceScore"
        return $result
    }
}
