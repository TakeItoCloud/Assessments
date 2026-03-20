function Get-TtcFindingSummary {
    <#
    .SYNOPSIS
        Prints a formatted console summary of TakeItToCloud assessment findings.
    .DESCRIPTION
        Accepts an array of TakeItToCloud finding objects and writes a colour-coded
        console summary covering scores, severity counts, per-workload breakdown, and
        top priority findings. Designed for quick field review without generating a
        full HTML/CSV report.

        Optionally accepts a pre-computed Scores object (from Get-TtcAssessmentScore).
        If Scores is not supplied, scores are calculated internally from Findings.
    .PARAMETER Findings
        Array of TakeItToCloud finding objects. Accepts pipeline input.
        Typically the output of Invoke-TtcAssessment or an individual assessor.
    .PARAMETER Scores
        Optional. Pre-computed scores PSCustomObject from Get-TtcAssessmentScore.
        When not provided, scores are calculated from the Findings array.
    .PARAMETER CustomerName
        Optional customer name displayed in the summary header.
    .PARAMETER TopFindingsSeverity
        Minimum severity for the top-findings section.
        Default: High (shows Critical and High findings).
        Valid values: Critical, High, Medium, Low, Informational.
    .PARAMETER TopFindingsCount
        Maximum number of priority findings to display. Default: 10.
    .PARAMETER PassThru
        When specified, returns a PSCustomObject summary in addition to printing.
    .EXAMPLE
        # Quick summary after a full assessment
        $result = Invoke-TtcAssessment -CustomerName 'Contoso'
        Get-TtcFindingSummary -Findings $result.Findings -Scores $result.Scores -CustomerName 'Contoso'
    .EXAMPLE
        # Pipeline usage — summary from AD assessor output
        Invoke-TtcAdAssessment | Get-TtcFindingSummary -CustomerName 'Fabrikam'
    .EXAMPLE
        # Show only Critical findings in the top section
        Get-TtcFindingSummary -Findings $result.Findings -TopFindingsSeverity Critical -PassThru
    .OUTPUTS
        [PSCustomObject] Only when -PassThru is specified.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Findings,

        [Parameter()]
        [PSCustomObject]$Scores,

        [Parameter()]
        [string]$CustomerName = '',

        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$TopFindingsSeverity = 'High',

        [Parameter()]
        [ValidateRange(1, 50)]
        [int]$TopFindingsCount = 10,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

        $severityOrder = @{
            Critical      = 5
            High          = 4
            Medium        = 3
            Low           = 2
            Informational = 1
        }
        $severityColour = @{
            Critical      = 'Red'
            High          = 'Yellow'
            Medium        = 'Cyan'
            Low           = 'Gray'
            Informational = 'DarkGray'
        }
    }

    process {
        foreach ($f in $Findings) { $allFindings.Add($f) }
    }

    end {
        # Compute scores if not provided
        if (-not $Scores -and $allFindings.Count -gt 0) {
            $Scores = Get-TtcAssessmentScore -Findings $allFindings
        }

        $width = 80
        $line  = '=' * $width
        $dash  = '-' * $width

        # Helper: score to colour
        $scoreColour = {
            param([double]$s)
            if ($s -ge 85) { 'Green' } elseif ($s -ge 65) { 'Yellow' } else { 'Red' }
        }

        # --- Header ---
        Write-Host ''
        Write-Host $line -ForegroundColor DarkCyan
        Write-Host '  TAKEITTTOCLOUD.ASSESS  —  Assessment Summary' -ForegroundColor Cyan
        $meta = "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')  |  Findings: $($allFindings.Count)"
        if ($CustomerName) { $meta += "  |  Customer: $CustomerName" }
        Write-Host $meta -ForegroundColor DarkCyan
        Write-Host $line -ForegroundColor DarkCyan

        # --- Scores ---
        if ($Scores) {
            Write-Host ''
            Write-Host '  SCORES' -ForegroundColor White
            Write-Host $dash -ForegroundColor DarkGray

            $ov = $Scores.OverallScore
            $sc = $Scores.SecurityScore
            $hc = $Scores.HealthScore
            $gc = $Scores.GovernanceScore

            # Progress bar for overall score (40 chars wide)
            $filled = [math]::Max(0, [math]::Min(40, [math]::Round($ov / 100 * 40)))
            $empty  = 40 - $filled
            $bar    = '[' + ([string][char]0x2588 * $filled) + (' ' * $empty) + ']'

            Write-Host ("  Overall:    {0,5}  " -f "$ov/100") -NoNewline -ForegroundColor White
            Write-Host $bar -ForegroundColor (& $scoreColour $ov)
            Write-Host ("  Security:   {0,5}    Health:     {1,5}    Governance: {2,5}" -f "$sc/100", "$hc/100", "$gc/100") -ForegroundColor White

            $statusMsg = if ($ov -ge 85)   { '  Good posture — review remaining findings before they escalate.' }
                         elseif ($ov -ge 65) { '  Moderate risk — prioritise Critical and High findings for immediate remediation.' }
                         else               { '  High risk — immediate remediation required across multiple areas.' }
            Write-Host $statusMsg -ForegroundColor (& $scoreColour $ov)
        }

        # --- Finding counts by severity ---
        Write-Host ''
        Write-Host '  FINDING SEVERITY SUMMARY (Fail + Warning)' -ForegroundColor White
        Write-Host $dash -ForegroundColor DarkGray

        $actionable = $allFindings | Where-Object { $_.Status -in @('Fail', 'Warning') }
        $anySev = $false
        foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Informational')) {
            $sevCount = ($actionable | Where-Object { $_.Severity -eq $sev } | Measure-Object).Count
            if ($sevCount -gt 0) {
                $anySev = $true
                $label = "  {0,-16}" -f "${sev}:"
                Write-Host $label -NoNewline -ForegroundColor $severityColour[$sev]
                Write-Host "$sevCount finding$(if ($sevCount -ne 1) { 's' })" -ForegroundColor White
            }
        }
        if (-not $anySev) {
            Write-Host '  No actionable findings at this severity level.' -ForegroundColor Green
        }

        $passCount  = ($allFindings | Where-Object { $_.Status -eq 'Pass' }        | Measure-Object).Count
        $naCount    = ($allFindings | Where-Object { $_.Status -eq 'NotAssessed' } | Measure-Object).Count
        $errorCount = ($allFindings | Where-Object { $_.Status -eq 'Error' }       | Measure-Object).Count

        Write-Host ("  {0,-16}{1}" -f 'Pass:', $passCount) -ForegroundColor Green
        if ($naCount    -gt 0) { Write-Host ("  {0,-16}{1}" -f 'Not Assessed:', $naCount)    -ForegroundColor DarkGray }
        if ($errorCount -gt 0) { Write-Host ("  {0,-16}{1}" -f 'Errors:', $errorCount)        -ForegroundColor Magenta }

        # --- Per-workload breakdown ---
        if ($Scores -and $Scores.WorkloadScores) {
            Write-Host ''
            Write-Host '  WORKLOAD BREAKDOWN' -ForegroundColor White
            Write-Host $dash -ForegroundColor DarkGray
            Write-Host ('  {0,-24} {1,7} {2,9} {3,7} {4,7} {5,5} {6,5} {7,5}' -f `
                'Workload', 'Overall', 'Security', 'Health', 'Govern', 'Fail', 'Warn', 'Pass') -ForegroundColor DarkGray

            foreach ($ws in ($Scores.WorkloadScores | Sort-Object OverallScore)) {
                $c = & $scoreColour $ws.OverallScore
                Write-Host ('  {0,-24} {1,7} {2,9} {3,7} {4,7} {5,5} {6,5} {7,5}' -f `
                    $ws.Workload, $ws.OverallScore, $ws.SecurityScore, $ws.HealthScore,
                    $ws.GovernanceScore, $ws.FailCount, $ws.WarningCount, $ws.PassCount) -ForegroundColor $c
            }
        }

        # --- Top priority findings ---
        $minWeight   = $severityOrder[$TopFindingsSeverity]
        $topFindings = $allFindings | Where-Object {
            $_.Status -in @('Fail', 'Warning') -and $severityOrder[$_.Severity] -ge $minWeight
        } | Sort-Object @{e = { $severityOrder[$_.Severity] }; d = $true }, FindingId |
            Select-Object -First $TopFindingsCount

        $topCount = ($topFindings | Measure-Object).Count
        if ($topCount -gt 0) {
            Write-Host ''
            Write-Host "  TOP FINDINGS ($TopFindingsSeverity+ — top $topCount shown)" -ForegroundColor White
            Write-Host $dash -ForegroundColor DarkGray

            foreach ($f in $topFindings) {
                $tag = '[{0,-13}]' -f $f.Severity.ToUpper()
                Write-Host "  $tag" -NoNewline -ForegroundColor $severityColour[$f.Severity]
                Write-Host " $($f.FindingId)  $($f.CheckName)" -ForegroundColor White
                if (-not [string]::IsNullOrWhiteSpace($f.IssueDetected)) {
                    Write-Host "               $($f.IssueDetected)" -ForegroundColor DarkGray
                }
            }
        }

        # --- Footer ---
        Write-Host ''
        Write-Host $line -ForegroundColor DarkCyan
        Write-Host '  Run Export-TtcHtmlReport for the full report with remediation guidance.' -ForegroundColor DarkCyan
        Write-Host '  Run Invoke-TtcAutoFix to generate a remediation script for fixable findings.' -ForegroundColor DarkCyan
        Write-Host $line -ForegroundColor DarkCyan
        Write-Host ''

        Write-TtcLog -Level Info -Message "Get-TtcFindingSummary: displayed summary for $($allFindings.Count) findings"

        # --- PassThru ---
        if ($PassThru) {
            $critFails = ($allFindings | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Fail' } | Measure-Object).Count
            $highFails = ($allFindings | Where-Object { $_.Severity -eq 'High'     -and $_.Status -eq 'Fail' } | Measure-Object).Count
            return [PSCustomObject]@{
                TotalFindings     = $allFindings.Count
                CriticalFailCount = $critFails
                HighFailCount     = $highFails
                OverallScore      = if ($Scores) { $Scores.OverallScore }      else { $null }
                SecurityScore     = if ($Scores) { $Scores.SecurityScore }     else { $null }
                HealthScore       = if ($Scores) { $Scores.HealthScore }       else { $null }
                GovernanceScore   = if ($Scores) { $Scores.GovernanceScore }   else { $null }
                TopFindings       = $topFindings
            }
        }
    }
}
