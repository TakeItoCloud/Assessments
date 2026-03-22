function Compare-TtcAssessment {
    <#
    .SYNOPSIS
        Compares two TakeItToCloud assessment CSV exports to identify new, resolved, and changed findings.
    .DESCRIPTION
        Performs a delta comparison between a baseline assessment CSV and a current assessment CSV.
        Identifies findings that are new (appeared since baseline), resolved (no longer present),
        regressed (status worsened), and improved (status improved). Outputs a structured report
        showing security posture trends over time.

        Use this function to track remediation progress between assessments or to compare
        assessments from different points in time.
    .PARAMETER BaselinePath
        Path to the CSV file from the earlier (baseline) assessment run.
    .PARAMETER CurrentPath
        Path to the CSV file from the more recent (current) assessment run.
    .PARAMETER OutputPath
        Optional path to save the delta report as a CSV file.
    .PARAMETER OutputFormat
        Format for the delta report output. Default: Console.
        Console: Colored console output.
        CSV: Save to OutputPath.
        Markdown: Markdown-formatted table suitable for reports/wikis.
        JSON: JSON structured output.
    .PARAMETER Workload
        Filter comparison to a specific workload (e.g., ActiveDirectory, EntraID).
        Default: All workloads.
    .EXAMPLE
        Compare-TtcAssessment -BaselinePath "C:\Reports\2026-01-baseline.csv" `
            -CurrentPath "C:\Reports\2026-03-current.csv"
    .EXAMPLE
        Compare-TtcAssessment -BaselinePath ".\baseline.csv" -CurrentPath ".\current.csv" `
            -OutputFormat Markdown | Out-File ".\delta-report.md"
    .OUTPUTS
        PSCustomObject with properties: NewFindings, ResolvedFindings, RegressedFindings,
        ImprovedFindings, UnchangedCount, BaselineDate, CurrentDate, DeltaSummary.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$BaselinePath,

        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$CurrentPath,

        [string]$OutputPath,

        [ValidateSet('Console', 'CSV', 'Markdown', 'JSON')]
        [string]$OutputFormat = 'Console',

        [string]$Workload
    )

    Write-TtcLog -Level Info -Message "Comparing assessments: Baseline=$BaselinePath | Current=$CurrentPath"

    # -------------------------------------------------------------------------
    # Load CSVs
    # -------------------------------------------------------------------------
    $baseline = Import-Csv -Path $BaselinePath -ErrorAction Stop
    $current  = Import-Csv -Path $CurrentPath  -ErrorAction Stop

    if ($Workload) {
        $baseline = $baseline | Where-Object { $_.Workload -eq $Workload }
        $current  = $current  | Where-Object { $_.Workload -eq $Workload }
    }

    # Try to extract timestamps from data
    $baselineDate = if ($baseline -and $baseline[0].Timestamp) {
        try { [datetime]$baseline[0].Timestamp } catch { [datetime]::MinValue }
    } else { [datetime]::MinValue }

    $currentDate = if ($current -and $current[0].Timestamp) {
        try { [datetime]$current[0].Timestamp } catch { [datetime]::Now }
    } else { [datetime]::Now }

    # Index by FindingId for O(1) lookup
    $baselineIndex = @{}
    foreach ($f in $baseline) {
        if ($f.FindingId) { $baselineIndex[$f.FindingId] = $f }
    }

    $currentIndex = @{}
    foreach ($f in $current) {
        if ($f.FindingId) { $currentIndex[$f.FindingId] = $f }
    }

    # -------------------------------------------------------------------------
    # Status severity ordering for regression/improvement detection
    # -------------------------------------------------------------------------
    $statusWeight = @{
        'Fail'        = 4
        'Error'       = 3
        'Warning'     = 2
        'Pass'        = 1
        'NotAssessed' = 0
    }

    $severityWeight = @{
        'Critical'      = 5
        'High'          = 4
        'Medium'        = 3
        'Low'           = 2
        'Informational' = 1
    }

    # -------------------------------------------------------------------------
    # Categorise findings
    # -------------------------------------------------------------------------
    $newFindings        = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resolvedFindings   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $regressedFindings  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $improvedFindings   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $unchangedCount     = 0

    # New and changed (in current, check against baseline)
    foreach ($id in $currentIndex.Keys) {
        $cur = $currentIndex[$id]

        if (-not $baselineIndex.ContainsKey($id)) {
            # Brand new finding
            $newFindings.Add([PSCustomObject]@{
                FindingId    = $cur.FindingId
                Workload     = $cur.Workload
                CheckName    = $cur.CheckName
                Severity     = $cur.Severity
                Status       = $cur.Status
                IssueDetected = $cur.IssueDetected
                Category     = $cur.Category
                Change       = 'New'
                OldStatus    = 'N/A'
                NewStatus    = $cur.Status
            })
        }
        else {
            $base = $baselineIndex[$id]
            $baseWeight = if ($statusWeight.ContainsKey($base.Status)) { $statusWeight[$base.Status] } else { 0 }
            $curWeight  = if ($statusWeight.ContainsKey($cur.Status))  { $statusWeight[$cur.Status]  } else { 0 }

            if ($curWeight -gt $baseWeight) {
                # Status got worse
                $regressedFindings.Add([PSCustomObject]@{
                    FindingId    = $cur.FindingId
                    Workload     = $cur.Workload
                    CheckName    = $cur.CheckName
                    Severity     = $cur.Severity
                    Status       = $cur.Status
                    IssueDetected = $cur.IssueDetected
                    Category     = $cur.Category
                    Change       = 'Regressed'
                    OldStatus    = $base.Status
                    NewStatus    = $cur.Status
                })
            }
            elseif ($curWeight -lt $baseWeight) {
                # Status improved
                $improvedFindings.Add([PSCustomObject]@{
                    FindingId    = $cur.FindingId
                    Workload     = $cur.Workload
                    CheckName    = $cur.CheckName
                    Severity     = $cur.Severity
                    Status       = $cur.Status
                    IssueDetected = $cur.IssueDetected
                    Category     = $cur.Category
                    Change       = 'Improved'
                    OldStatus    = $base.Status
                    NewStatus    = $cur.Status
                })
            }
            else {
                $unchangedCount++
            }
        }
    }

    # Resolved (in baseline but not in current)
    foreach ($id in $baselineIndex.Keys) {
        if (-not $currentIndex.ContainsKey($id)) {
            $base = $baselineIndex[$id]
            $resolvedFindings.Add([PSCustomObject]@{
                FindingId    = $base.FindingId
                Workload     = $base.Workload
                CheckName    = $base.CheckName
                Severity     = $base.Severity
                Status       = 'Resolved'
                IssueDetected = $base.IssueDetected
                Category     = $base.Category
                Change       = 'Resolved'
                OldStatus    = $base.Status
                NewStatus    = 'Resolved'
            })
        }
    }

    # -------------------------------------------------------------------------
    # Score delta
    # -------------------------------------------------------------------------
    $baselineFailCritical = ($baseline | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Fail' } | Measure-Object).Count
    $baselineFailHigh     = ($baseline | Where-Object { $_.Severity -eq 'High'     -and $_.Status -eq 'Fail' } | Measure-Object).Count
    $currentFailCritical  = ($current  | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Fail' } | Measure-Object).Count
    $currentFailHigh      = ($current  | Where-Object { $_.Severity -eq 'High'     -and $_.Status -eq 'Fail' } | Measure-Object).Count

    $deltaSummary = [PSCustomObject]@{
        BaselineDate        = if ($baselineDate -ne [datetime]::MinValue) { $baselineDate.ToString('yyyy-MM-dd') } else { 'Unknown' }
        CurrentDate         = $currentDate.ToString('yyyy-MM-dd')
        DaysBetween         = if ($baselineDate -ne [datetime]::MinValue) { [int]($currentDate - $baselineDate).TotalDays } else { 0 }
        BaselineTotalChecks = $baseline.Count
        CurrentTotalChecks  = $current.Count
        NewFindings         = $newFindings.Count
        ResolvedFindings    = $resolvedFindings.Count
        ImprovedFindings    = $improvedFindings.Count
        RegressedFindings   = $regressedFindings.Count
        UnchangedFindings   = $unchangedCount
        DeltaCriticalFail   = $currentFailCritical - $baselineFailCritical
        DeltaHighFail       = $currentFailHigh - $baselineFailHigh
        WorkloadFilter      = if ($Workload) { $Workload } else { 'All' }
    }

    # -------------------------------------------------------------------------
    # Output
    # -------------------------------------------------------------------------
    switch ($OutputFormat) {

        'Console' {
            $line = '=' * 70
            Write-Host $line -ForegroundColor Cyan
            Write-Host " ASSESSMENT DELTA REPORT" -ForegroundColor Cyan
            Write-Host " Baseline : $($deltaSummary.BaselineDate) ($($deltaSummary.BaselineTotalChecks) checks)" -ForegroundColor Cyan
            Write-Host " Current  : $($deltaSummary.CurrentDate) ($($deltaSummary.CurrentTotalChecks) checks)" -ForegroundColor Cyan
            Write-Host " Period   : $($deltaSummary.DaysBetween) day(s)" -ForegroundColor Cyan
            Write-Host $line -ForegroundColor Cyan

            Write-Host "`n FINDING CHANGES" -ForegroundColor White
            Write-Host "  New findings      : $($newFindings.Count)"      -ForegroundColor $(if ($newFindings.Count -gt 0) { 'Red' } else { 'Green' })
            Write-Host "  Resolved findings : $($resolvedFindings.Count)"  -ForegroundColor $(if ($resolvedFindings.Count -gt 0) { 'Green' } else { 'Yellow' })
            Write-Host "  Improved findings : $($improvedFindings.Count)"  -ForegroundColor $(if ($improvedFindings.Count -gt 0) { 'Green' } else { 'Yellow' })
            Write-Host "  Regressed findings: $($regressedFindings.Count)" -ForegroundColor $(if ($regressedFindings.Count -gt 0) { 'Red' } else { 'Green' })
            Write-Host "  Unchanged         : $unchangedCount"

            $critDelta = $deltaSummary.DeltaCriticalFail
            $highDelta  = $deltaSummary.DeltaHighFail
            Write-Host "`n SEVERITY TREND" -ForegroundColor White
            $critColor = if ($critDelta -gt 0) { 'Red' } elseif ($critDelta -lt 0) { 'Green' } else { 'Yellow' }
            $highColor  = if ($highDelta -gt 0)  { 'Red' } elseif ($highDelta -lt 0)  { 'Green' } else { 'Yellow' }
            Write-Host "  Critical Fail delta: $(if ($critDelta -ge 0) { '+' })$critDelta (Baseline: $baselineFailCritical -> Current: $currentFailCritical)" -ForegroundColor $critColor
            Write-Host "  High Fail delta    : $(if ($highDelta -ge 0)  { '+' })$highDelta (Baseline: $baselineFailHigh -> Current: $currentFailHigh)"     -ForegroundColor $highColor

            if ($newFindings.Count -gt 0) {
                Write-Host "`n NEW FINDINGS" -ForegroundColor Red
                $newFindings | Sort-Object { $severityWeight[$_.Severity] } -Descending | ForEach-Object {
                    Write-Host "  [$($_.Severity.PadRight(12))] $($_.FindingId) - $($_.CheckName)" -ForegroundColor Red
                }
            }

            if ($regressedFindings.Count -gt 0) {
                Write-Host "`n REGRESSED FINDINGS (status worsened)" -ForegroundColor DarkRed
                $regressedFindings | ForEach-Object {
                    Write-Host "  [$($_.Severity.PadRight(12))] $($_.FindingId) - $($_.CheckName): $($_.OldStatus) -> $($_.NewStatus)" -ForegroundColor DarkRed
                }
            }

            if ($resolvedFindings.Count -gt 0) {
                Write-Host "`n RESOLVED FINDINGS" -ForegroundColor Green
                $resolvedFindings | ForEach-Object {
                    Write-Host "  [$($_.Severity.PadRight(12))] $($_.FindingId) - $($_.CheckName)" -ForegroundColor Green
                }
            }

            if ($improvedFindings.Count -gt 0) {
                Write-Host "`n IMPROVED FINDINGS" -ForegroundColor Green
                $improvedFindings | ForEach-Object {
                    Write-Host "  [$($_.Severity.PadRight(12))] $($_.FindingId) - $($_.CheckName): $($_.OldStatus) -> $($_.NewStatus)" -ForegroundColor DarkGreen
                }
            }

            Write-Host "`n$line" -ForegroundColor Cyan
        }

        'CSV' {
            if (-not $OutputPath) {
                $OutputPath = Join-Path ([System.IO.Path]::GetTempPath()) "TtcDelta_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            }
            $allChanges = @()
            $allChanges += $newFindings
            $allChanges += $resolvedFindings
            $allChanges += $regressedFindings
            $allChanges += $improvedFindings
            $allChanges | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-TtcLog -Level Info -Message "Delta report saved to: $OutputPath"
            Write-Host "Delta CSV saved: $OutputPath" -ForegroundColor Cyan
        }

        'Markdown' {
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.AppendLine("## Assessment Delta Report")
            [void]$sb.AppendLine()
            [void]$sb.AppendLine("| Property | Value |")
            [void]$sb.AppendLine("|----------|-------|")
            [void]$sb.AppendLine("| Baseline Date | $($deltaSummary.BaselineDate) |")
            [void]$sb.AppendLine("| Current Date | $($deltaSummary.CurrentDate) |")
            [void]$sb.AppendLine("| Period | $($deltaSummary.DaysBetween) days |")
            [void]$sb.AppendLine("| New Findings | $($newFindings.Count) |")
            [void]$sb.AppendLine("| Resolved | $($resolvedFindings.Count) |")
            [void]$sb.AppendLine("| Improved | $($improvedFindings.Count) |")
            [void]$sb.AppendLine("| Regressed | $($regressedFindings.Count) |")
            [void]$sb.AppendLine("| Critical Fail Delta | $(if ($deltaSummary.DeltaCriticalFail -ge 0) { '+' })$($deltaSummary.DeltaCriticalFail) |")
            [void]$sb.AppendLine("| High Fail Delta | $(if ($deltaSummary.DeltaHighFail -ge 0) { '+' })$($deltaSummary.DeltaHighFail) |")
            [void]$sb.AppendLine()

            if ($newFindings.Count -gt 0) {
                [void]$sb.AppendLine("### New Findings")
                [void]$sb.AppendLine("| FindingId | Severity | CheckName | Status |")
                [void]$sb.AppendLine("|-----------|----------|-----------|--------|")
                foreach ($f in ($newFindings | Sort-Object { $severityWeight[$_.Severity] } -Descending)) {
                    [void]$sb.AppendLine("| $($f.FindingId) | $($f.Severity) | $($f.CheckName) | $($f.Status) |")
                }
                [void]$sb.AppendLine()
            }

            if ($resolvedFindings.Count -gt 0) {
                [void]$sb.AppendLine("### Resolved Findings")
                [void]$sb.AppendLine("| FindingId | Severity | CheckName |")
                [void]$sb.AppendLine("|-----------|----------|-----------|")
                foreach ($f in $resolvedFindings) {
                    [void]$sb.AppendLine("| $($f.FindingId) | $($f.Severity) | $($f.CheckName) |")
                }
                [void]$sb.AppendLine()
            }

            if ($regressedFindings.Count -gt 0) {
                [void]$sb.AppendLine("### Regressed Findings")
                [void]$sb.AppendLine("| FindingId | Severity | CheckName | Was | Now |")
                [void]$sb.AppendLine("|-----------|----------|-----------|-----|-----|")
                foreach ($f in $regressedFindings) {
                    [void]$sb.AppendLine("| $($f.FindingId) | $($f.Severity) | $($f.CheckName) | $($f.OldStatus) | $($f.NewStatus) |")
                }
                [void]$sb.AppendLine()
            }

            $sb.ToString()
        }

        'JSON' {
            [PSCustomObject]@{
                DeltaSummary      = $deltaSummary
                NewFindings       = $newFindings
                ResolvedFindings  = $resolvedFindings
                RegressedFindings = $regressedFindings
                ImprovedFindings  = $improvedFindings
            } | ConvertTo-Json -Depth 5
        }
    }

    # Save CSV if path provided alongside console/markdown output
    if ($OutputPath -and $OutputFormat -ne 'CSV') {
        $allChanges = @()
        $allChanges += $newFindings
        $allChanges += $resolvedFindings
        $allChanges += $regressedFindings
        $allChanges += $improvedFindings
        $allChanges | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-TtcLog -Level Info -Message "Delta CSV also saved to: $OutputPath"
    }

    # Always return structured object
    return [PSCustomObject]@{
        DeltaSummary      = $deltaSummary
        NewFindings       = $newFindings.ToArray()
        ResolvedFindings  = $resolvedFindings.ToArray()
        RegressedFindings = $regressedFindings.ToArray()
        ImprovedFindings  = $improvedFindings.ToArray()
        UnchangedCount    = $unchangedCount
    }
}
