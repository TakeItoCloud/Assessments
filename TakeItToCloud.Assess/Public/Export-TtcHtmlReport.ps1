function Export-TtcHtmlReport {
    <#
    .SYNOPSIS
        Generates a self-contained HTML assessment report.
    .DESCRIPTION
        Creates a professional, interactive HTML report from assessment findings.
        The report includes executive summary, score cards, severity breakdown,
        workload breakdown, and a filterable/sortable findings table with
        expandable detail rows.

        The HTML is fully self-contained with inline CSS and JavaScript.
        No external CDN dependencies.
    .PARAMETER Findings
        Array of finding objects from an assessment run.
    .PARAMETER Scores
        Score object from Get-TtcAssessmentScore. If not provided, scores are calculated.
    .PARAMETER OutputPath
        Path for the HTML file. Defaults to ./Reports/TtcAssessment_{date}.html.
    .PARAMETER ReportTitle
        Title shown in the report header. Defaults to "Infrastructure Assessment".
    .PARAMETER CustomerName
        Customer name shown in the report metadata.
    .PARAMETER AssessedBy
        Assessor name shown in the report metadata.
    .OUTPUTS
        System.IO.FileInfo  -  the created HTML file.
    .EXAMPLE
        Export-TtcHtmlReport -Findings $findings -CustomerName "Contoso" -AssessedBy "Carlos - TakeItToCloud"
    .EXAMPLE
        $findings | Export-TtcHtmlReport -ReportTitle "Q1 2026 Security Assessment"
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Findings,

        [PSCustomObject]$Scores,

        [string]$OutputPath,

        [string]$ReportTitle = 'Infrastructure Assessment',

        [string]$CustomerName = '',

        [string]$AssessedBy = ''
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
        if ($allFindings.Count -eq 0) {
            Write-TtcLog -Level Warning -Message "No findings to export to HTML"
            return
        }

        Write-TtcLog -Level Info -Message "Generating HTML report for $($allFindings.Count) findings"

        # --- Calculate scores if not provided ---
        if (-not $Scores) {
            $Scores = Get-TtcAssessmentScore -Findings $allFindings
        }

        # --- Default output path ---
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $reportDir = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
            if (-not (Test-Path -Path $reportDir)) {
                New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
            }
            $OutputPath = Join-Path -Path $reportDir -ChildPath "TtcAssessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        }
        else {
            $parentDir = Split-Path -Path $OutputPath -Parent
            if ($parentDir -and -not (Test-Path -Path $parentDir)) {
                New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
            }
        }

        # --- Helper: score CSS class ---
        $scoreClass = {
            param([double]$s)
            if ($s -ge 80) { 'score-good' } elseif ($s -ge 50) { 'score-warn' } else { 'score-bad' }
        }

        # --- Get template ---
        $html = Get-TtcHtmlTemplate

        # --- Replace header tokens ---
        $html = $html -replace '{{ReportTitle}}',   [System.Web.HttpUtility]::HtmlEncode($ReportTitle)
        $html = $html -replace '{{GeneratedAt}}',    (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        $html = $html -replace '{{CustomerName}}',   [System.Web.HttpUtility]::HtmlEncode($CustomerName)
        $html = $html -replace '{{AssessedBy}}',     [System.Web.HttpUtility]::HtmlEncode($AssessedBy)
        $html = $html -replace '{{TotalFindings}}',  $allFindings.Count

        # --- Replace score tokens ---
        $html = $html -replace '{{OverallScore}}',       $Scores.OverallScore
        $html = $html -replace '{{SecurityScore}}',      $Scores.SecurityScore
        $html = $html -replace '{{HealthScore}}',        $Scores.HealthScore
        $html = $html -replace '{{GovernanceScore}}',    $Scores.GovernanceScore
        $html = $html -replace '{{OverallScoreClass}}',  (& $scoreClass $Scores.OverallScore)
        $html = $html -replace '{{SecurityScoreClass}}', (& $scoreClass $Scores.SecurityScore)
        $html = $html -replace '{{HealthScoreClass}}',   (& $scoreClass $Scores.HealthScore)
        $html = $html -replace '{{GovernanceScoreClass}}',(& $scoreClass $Scores.GovernanceScore)

        # --- Replace severity counts ---
        $html = $html -replace '{{CriticalCount}}', $Scores.SeveritySummary.Critical
        $html = $html -replace '{{HighCount}}',     $Scores.SeveritySummary.High
        $html = $html -replace '{{MediumCount}}',   $Scores.SeveritySummary.Medium
        $html = $html -replace '{{LowCount}}',      $Scores.SeveritySummary.Low
        $html = $html -replace '{{PassCount}}',     $Scores.TotalPass

        # --- Build workload cards ---
        $wlCardsHtml = ''
        foreach ($wlScore in $Scores.WorkloadScores) {
            $barColor = & $scoreClass $wlScore.OverallScore
            $barColorVar = switch ($barColor) {
                'score-good' { 'var(--green-500)' }
                'score-warn' { 'var(--orange-500)' }
                'score-bad'  { 'var(--red-500)' }
            }
            $wlCardsHtml += @"
<div class="wl-card">
    <h3>$([System.Web.HttpUtility]::HtmlEncode($wlScore.Workload))</h3>
    <div style="display:flex;justify-content:space-between;font-size:0.82rem;color:var(--navy-500);">
        <span>Score: <strong class="$barColor">$($wlScore.OverallScore)</strong></span>
        <span>Fail: $($wlScore.FailCount) | Warn: $($wlScore.WarningCount) | Pass: $($wlScore.PassCount)</span>
    </div>
    <div class="wl-bar"><div class="wl-bar-fill" style="width:$($wlScore.OverallScore)%;background:$barColorVar;"></div></div>
</div>
"@
        }
        $html = $html -replace '{{WorkloadCards}}', $wlCardsHtml

        # --- Build filter options ---
        $workloads   = $allFindings | Select-Object -ExpandProperty Workload -Unique | Sort-Object
        $categories  = $allFindings | Select-Object -ExpandProperty Category -Unique | Sort-Object
        $frameworks  = $allFindings | Select-Object -ExpandProperty FrameworkMapping -Unique | Where-Object { $_ -ne '' } | Sort-Object

        $wlOpts  = ($workloads  | ForEach-Object { "<option>$([System.Web.HttpUtility]::HtmlEncode($_))</option>" }) -join ''
        $catOpts = ($categories | ForEach-Object { "<option>$([System.Web.HttpUtility]::HtmlEncode($_))</option>" }) -join ''
        $fwOpts  = ($frameworks | ForEach-Object { "<option>$([System.Web.HttpUtility]::HtmlEncode($_))</option>" }) -join ''

        $html = $html -replace '{{WorkloadOptions}}',  $wlOpts
        $html = $html -replace '{{CategoryOptions}}',  $catOpts
        $html = $html -replace '{{FrameworkOptions}}',  $fwOpts

        # --- Build findings rows ---
        $rowsHtml = ''
        $rowIndex = 0
        foreach ($f in ($allFindings | Sort-Object -Property @{Expression={
            switch ($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} 'Low'{3} 'Informational'{4} default{5} }
        }})) {
            $rowIndex++
            $enc = {
                param([string]$s)
                [System.Web.HttpUtility]::HtmlEncode($s)
            }

            $rowsHtml += @"
<tr class="finding-row" data-severity="$(& $enc $f.Severity)" data-workload="$(& $enc $f.Workload)" data-category="$(& $enc $f.Category)" data-status="$(& $enc $f.Status)" data-framework="$(& $enc $f.FrameworkMapping)">
    <td><strong>$(& $enc $f.FindingId)</strong></td>
    <td><span class="sev-badge $($f.Severity)">$($f.Severity)</span></td>
    <td><span class="status-badge $($f.Status)">$($f.Status)</span></td>
    <td>$(& $enc $f.Workload)</td>
    <td>$(& $enc $f.Category)</td>
    <td>$(& $enc $f.CheckName)</td>
    <td>$(& $enc $f.IssueDetected)</td>
    <td>$(& $enc $f.FrameworkMapping)</td>
    <td><span class="detail-toggle" onclick="toggleDetail($rowIndex)">View</span></td>
</tr>
<tr class="detail-row" id="detail-$rowIndex">
    <td colspan="9" class="detail-cell">
        <dl>
            <dt>Explanation</dt><dd>$(& $enc $f.Explanation)</dd>
            <dt>Possible Solution</dt><dd>$(& $enc $f.PossibleSolution)</dd>
            <dt>Remediation</dt><dd>$(& $enc $f.Remediation)</dd>
            <dt>Impact</dt><dd>$(& $enc $f.Impact)</dd>
            <dt>Risk Level</dt><dd>$(& $enc $f.RiskLevel)</dd>
            <dt>Zero Trust Pillar</dt><dd>$(& $enc $f.ZeroTrustPillar)</dd>
            <dt>Secure Score</dt><dd>$(& $enc $f.SecureScoreMapping)</dd>
            <dt>Data Source</dt><dd>$(& $enc $f.DataSource)</dd>
            <dt>Auto-Fix</dt><dd>$(& $enc $f.AutoFixAvailable)</dd>
            <dt>Priority</dt><dd>$(& $enc $f.RemediationPriority)</dd>
            <dt>Component</dt><dd>$(& $enc $f.Component)</dd>
            <dt>Notes</dt><dd>$(& $enc $f.Notes)</dd>
        </dl>
    </td>
</tr>
"@
        }
        $html = $html -replace '{{FindingsRows}}', $rowsHtml

        # --- Write file ---
        try {
            # Add System.Web for HtmlEncode if not loaded (PS 5.1)
            $html | Out-File -FilePath $OutputPath -Encoding utf8

            $fileInfo = Get-Item -Path $OutputPath
            Write-TtcLog -Level Info -Message "HTML report exported: $OutputPath ($([math]::Round($fileInfo.Length / 1KB, 1)) KB)"
            return $fileInfo
        }
        catch {
            Write-TtcLog -Level Error -Message "Failed to export HTML report" -ErrorRecord $_
            throw
        }
    }
}
