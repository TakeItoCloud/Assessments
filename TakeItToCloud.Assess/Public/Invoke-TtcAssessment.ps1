function Invoke-TtcAssessment {
    <#
    .SYNOPSIS
        Runs the TakeItToCloud infrastructure and security assessment.
    .DESCRIPTION
        Main entry point for the TakeItToCloud.Assess framework. Orchestrates
        workload assessors, collects findings, calculates scores, and generates
        CSV and HTML reports.

        Supports selecting specific workloads, filtering severities, and
        customizing output paths. Uses the configuration from DefaultConfig.json
        as defaults, with parameter overrides.
    .PARAMETER Workloads
        Array of workloads to assess. Defaults to all available workloads.
        Valid values: ActiveDirectory, ExchangeOnline, HybridIdentity, EntraID, Defender,
        Collaboration, MDE, PIM, ADCS.
    .PARAMETER ExcludeWorkloads
        Workloads to skip even if listed in Workloads parameter.
    .PARAMETER ExcludeChecks
        Array of FindingId values to exclude from the final results and scoring.
        Example: @('AD-CFG-002', 'ENT-CFG-003') to suppress specific checks.
        Can also be set in DefaultConfig.json under the ExcludeChecks key.
    .PARAMETER ExcludeChecksFile
        Path to a text file (one FindingId per line) of checks to exclude.
        Lines beginning with # are treated as comments and ignored.
    .PARAMETER OutputPath
        Directory for report output. Defaults to ./Reports.
    .PARAMETER ReportTitle
        Title for the HTML report.
    .PARAMETER CustomerName
        Customer name for report metadata.
    .PARAMETER AssessedBy
        Assessor name for report metadata.
    .PARAMETER GenerateCsv
        Whether to generate CSV report. Default: true.
    .PARAMETER GenerateHtml
        Whether to generate HTML report. Default: true.
    .PARAMETER SkipPrerequisiteCheck
        Skip module prerequisite validation.
    .PARAMETER ConfigPath
        Path to a custom configuration JSON file.
    .OUTPUTS
        PSCustomObject with Findings, Scores, CsvPath, and HtmlPath.
    .EXAMPLE
        # Run full assessment with default settings
        $result = Invoke-TtcAssessment -CustomerName "Contoso" -AssessedBy "Carlos"

    .EXAMPLE
        # Run only AD and Entra ID assessments
        $result = Invoke-TtcAssessment -Workloads @('ActiveDirectory', 'EntraID') -CustomerName "Fabrikam"

    .EXAMPLE
        # Run assessment with custom output path
        $result = Invoke-TtcAssessment -OutputPath "C:\Assessments\Contoso" -GenerateHtml $true -GenerateCsv $true
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('ActiveDirectory', 'ExchangeOnline', 'HybridIdentity', 'EntraID', 'Defender', 'Collaboration', 'MDE', 'PIM', 'ADCS')]
        [string[]]$Workloads,

        [string[]]$ExcludeWorkloads = @(),

        [string[]]$ExcludeChecks = @(),

        [string]$ExcludeChecksFile,

        [string]$OutputPath,

        [string]$ReportTitle = 'Infrastructure & Security Assessment',

        [string]$CustomerName = '',

        [string]$AssessedBy = '',

        [bool]$GenerateCsv = $true,

        [bool]$GenerateHtml = $true,

        [switch]$SkipPrerequisiteCheck,

        [string]$ConfigPath
    )

    # --- Load configuration ---
    $config = $null
    if ($ConfigPath -and (Test-Path -Path $ConfigPath)) {
        try {
            $config = Get-Content -Path $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            Write-TtcLog -Level Info -Message "Loaded configuration from: $ConfigPath"
        }
        catch {
            Write-TtcLog -Level Warning -Message "Failed to load config file, using defaults: $_"
        }
    }
    elseif ($script:TtcConfigPath) {
        $defaultConfigFile = Join-Path -Path $script:TtcConfigPath -ChildPath 'DefaultConfig.json'
        if (Test-Path -Path $defaultConfigFile) {
            try {
                $config = Get-Content -Path $defaultConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
                Write-TtcLog -Level Info -Message "Loaded default configuration"
            }
            catch {
                Write-TtcLog -Level Warning -Message "Failed to load default config: $_"
            }
        }
    }

    # --- Resolve workloads ---
    if (-not $Workloads -or $Workloads.Count -eq 0) {
        if ($config -and $config.Workloads) {
            $Workloads = $config.Workloads
        }
        else {
            $Workloads = @('ActiveDirectory', 'ExchangeOnline', 'HybridIdentity', 'EntraID', 'Defender', 'Collaboration', 'MDE', 'PIM', 'ADCS')
        }
    }

    # Apply exclusions
    if ($ExcludeWorkloads.Count -gt 0) {
        $Workloads = $Workloads | Where-Object { $_ -notin $ExcludeWorkloads }
    }
    elseif ($config -and $config.ExcludeWorkloads) {
        $Workloads = $Workloads | Where-Object { $_ -notin $config.ExcludeWorkloads }
    }

    # --- Resolve output path ---
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        if ($config -and $config.OutputPath) {
            $OutputPath = $config.OutputPath
        }
        else {
            $OutputPath = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
        }
    }
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    # --- Resolve metadata ---
    if ([string]::IsNullOrWhiteSpace($CustomerName) -and $config -and $config.EnvironmentMetadata) {
        $CustomerName = $config.EnvironmentMetadata.CustomerName
    }
    if ([string]::IsNullOrWhiteSpace($AssessedBy) -and $config -and $config.EnvironmentMetadata) {
        $AssessedBy = $config.EnvironmentMetadata.AssessedBy
    }

    # --- Load ExcludeChecksFile ---
    if ($ExcludeChecksFile -and (Test-Path -Path $ExcludeChecksFile)) {
        try {
            $fileExcludes = Get-Content -Path $ExcludeChecksFile -Encoding UTF8 |
                Where-Object { $_ -and $_ -notmatch '^\s*#' } |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ }
            if ($fileExcludes) {
                $ExcludeChecks = @($ExcludeChecks) + @($fileExcludes) | Select-Object -Unique
                Write-TtcLog -Level Info -Message "Loaded $($fileExcludes.Count) exclusion(s) from: $ExcludeChecksFile"
            }
        }
        catch {
            Write-TtcLog -Level Warning -Message "Could not load ExcludeChecksFile: $_"
        }
    }

    # --- Begin assessment ---
    $startTime = Get-Date
    Write-TtcLog -Level Info -Message "========================================="
    Write-TtcLog -Level Info -Message "TakeItToCloud Assessment Starting"
    Write-TtcLog -Level Info -Message "Workloads: $($Workloads -join ', ')"
    Write-TtcLog -Level Info -Message "Output: $OutputPath"
    Write-TtcLog -Level Info -Message "========================================="

    $allFindings = [System.Collections.ArrayList]::new()

    # --- Map workloads to assessor functions ---
    $assessorMap = @{
        'ActiveDirectory' = 'Invoke-TtcAdAssessment'
        'ExchangeOnline'  = 'Invoke-TtcExoAssessment'
        'HybridIdentity'  = 'Invoke-TtcHybridAssessment'
        'EntraID'         = 'Invoke-TtcEntraAssessment'
        'Defender'        = 'Invoke-TtcDefenderAssessment'
        'Collaboration'   = 'Invoke-TtcCollabAssessment'
        'MDE'             = 'Invoke-TtcMdeAssessment'
        'PIM'             = 'Invoke-TtcPimAssessment'
        'ADCS'            = 'Invoke-TtcAdcsAssessment'
    }

    # --- Run each workload assessor ---
    $workloadIndex = 0
    foreach ($workload in $Workloads) {
        $workloadIndex++
        Write-Progress -Activity "TakeItToCloud Assessment" `
            -Status "Assessing $workload ($workloadIndex of $($Workloads.Count))" `
            -PercentComplete ([int](($workloadIndex / $Workloads.Count) * 100))
        Write-TtcLog -Level Info -Message "--- Assessing: $workload ($workloadIndex/$($Workloads.Count)) ---"

        # Check prerequisites
        if (-not $SkipPrerequisiteCheck) {
            $prereqMet = Test-TtcPrerequisite -Workload $workload
            if (-not $prereqMet) {
                Write-TtcLog -Level Warning -Message "Prerequisites not met for $workload  -  generating NotAssessed finding"
                $skipFinding = New-TtcFinding `
                    -FindingId "$($workload.Substring(0, [Math]::Min(3, $workload.Length)).ToUpper())-HLT-000" `
                    -Workload $workload `
                    -CheckName "Prerequisite Check" `
                    -Category 'Health' `
                    -Severity 'Informational' `
                    -Status 'NotAssessed' `
                    -IssueDetected "Required PowerShell modules not available for $workload assessment" `
                    -Explanation "The assessment for $workload was skipped because prerequisite modules are not installed." `
                    -PossibleSolution "Install the required modules and re-run the assessment." `
                    -DataSource "Test-TtcPrerequisite"
                [void]$allFindings.Add($skipFinding)
                continue
            }
        }

        # Check if assessor function exists
        $assessorFunc = $assessorMap[$workload]
        if (-not (Get-Command -Name $assessorFunc -ErrorAction SilentlyContinue)) {
            Write-TtcLog -Level Warning -Message "Assessor function not found: $assessorFunc (workload not yet implemented)"
            $notImplFinding = New-TtcFinding `
                -FindingId "$($workload.Substring(0, [Math]::Min(3, $workload.Length)).ToUpper())-HLT-000" `
                -Workload $workload `
                -CheckName "Assessor Not Implemented" `
                -Category 'Health' `
                -Severity 'Informational' `
                -Status 'NotAssessed' `
                -IssueDetected "Assessor for $workload is not yet implemented" `
                -Explanation "This workload assessor has not been built yet." `
                -PossibleSolution "This workload will be available in a future version." `
                -DataSource "Invoke-TtcAssessment"
            [void]$allFindings.Add($notImplFinding)
            continue
        }

        # Execute assessor
        try {
            $ErrorActionPreference = 'Stop'
            $workloadFindings = & $assessorFunc
            if ($workloadFindings) {
                foreach ($wf in $workloadFindings) {
                    [void]$allFindings.Add($wf)
                }
                Write-TtcLog -Level Info -Message "$workload assessment completed: $($workloadFindings.Count) findings"
            }
            else {
                Write-TtcLog -Level Info -Message "$workload assessment completed: 0 findings"
            }
        }
        catch {
            Write-TtcLog -Level Error -Message "Assessor failed for $workload" -ErrorRecord $_
            $errorFinding = New-TtcFinding `
                -FindingId "$($workload.Substring(0, [Math]::Min(3, $workload.Length)).ToUpper())-HLT-999" `
                -Workload $workload `
                -CheckName "Assessor Runtime Error" `
                -Category 'Health' `
                -Severity 'High' `
                -Status 'Error' `
                -IssueDetected "The $workload assessor encountered an error during execution" `
                -Explanation "An unhandled exception occurred: $($_.Exception.Message)" `
                -PossibleSolution "Review the error, check prerequisites, and re-run the assessment." `
                -DataSource "Invoke-TtcAssessment" `
                -Notes $_.Exception.Message
            [void]$allFindings.Add($errorFinding)
        }
        finally {
            $ErrorActionPreference = 'Continue'
        }
    }

    Write-Progress -Activity "TakeItToCloud Assessment" -Completed

    # --- Apply ExcludeChecks filter ---
    # Merge parameter value with config value; parameter takes precedence
    $effectiveExcludes = [System.Collections.Generic.List[string]]::new()
    if ($ExcludeChecks -and $ExcludeChecks.Count -gt 0) {
        foreach ($id in $ExcludeChecks) { $effectiveExcludes.Add($id) }
    }
    elseif ($config -and $config.ExcludeChecks -and $config.ExcludeChecks.Count -gt 0) {
        foreach ($id in $config.ExcludeChecks) { $effectiveExcludes.Add($id) }
    }

    if ($effectiveExcludes.Count -gt 0) {
        $beforeCount = $allFindings.Count
        $allFindings = [System.Collections.ArrayList]($allFindings | Where-Object { $_.FindingId -notin $effectiveExcludes })
        $removed     = $beforeCount - $allFindings.Count
        Write-TtcLog -Level Info -Message "ExcludeChecks: removed $removed finding(s) matching exclusion list ($($effectiveExcludes -join ', '))"
    }

    # --- Calculate scores ---
    Write-TtcLog -Level Info -Message "Calculating assessment scores..."
    $scores = $null
    if ($allFindings.Count -gt 0) {
        $scores = Get-TtcAssessmentScore -Findings $allFindings
    }

    # --- Generate reports ---
    $csvFile  = $null
    $htmlFile = $null
    $dateSuffix = Get-Date -Format 'yyyyMMdd_HHmmss'

    if ($GenerateCsv -and $allFindings.Count -gt 0) {
        $csvPath = Join-Path -Path $OutputPath -ChildPath "TtcAssessment_$dateSuffix.csv"
        $csvFile = Export-TtcCsvReport -Findings $allFindings -OutputPath $csvPath
    }

    if ($GenerateHtml -and $allFindings.Count -gt 0) {
        $htmlPath = Join-Path -Path $OutputPath -ChildPath "TtcAssessment_$dateSuffix.html"
        $htmlFile = Export-TtcHtmlReport -Findings $allFindings -Scores $scores `
            -OutputPath $htmlPath -ReportTitle $ReportTitle `
            -CustomerName $CustomerName -AssessedBy $AssessedBy
    }

    # --- Summary ---
    $elapsed = (Get-Date) - $startTime
    Write-TtcLog -Level Info -Message "========================================="
    Write-TtcLog -Level Info -Message "Assessment Complete"
    Write-TtcLog -Level Info -Message "Total Findings: $($allFindings.Count)"
    Write-TtcLog -Level Info -Message "Duration: $([math]::Round($elapsed.TotalSeconds, 1))s"
    if ($scores) {
        Write-TtcLog -Level Info -Message "Overall Score: $($scores.OverallScore)"
    }
    Write-TtcLog -Level Info -Message "========================================="

    # --- Return result ---
    [PSCustomObject]@{
        Findings     = $allFindings.ToArray()
        Scores       = $scores
        CsvReport    = $csvFile
        HtmlReport   = $htmlFile
        Duration     = $elapsed
        Workloads    = $Workloads
        GeneratedAt  = Get-Date -Format 'o'
    }
}
