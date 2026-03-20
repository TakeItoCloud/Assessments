function Invoke-TtcAutoFix {
    <#
    .SYNOPSIS
        Generates a PowerShell remediation script from TakeItToCloud assessment findings.
    .DESCRIPTION
        Accepts an array of TakeItToCloud finding objects (from Invoke-TtcAssessment or an
        individual assessor) and generates a documented, ready-to-review PowerShell remediation
        script file for all findings where AutoFixAvailable is 'Yes' or 'Partial'.

        IMPORTANT: This function GENERATES a remediation script — it does NOT execute any fixes.
        The generated script must be reviewed and executed separately by a qualified administrator.
        All remediation commands are wrapped in a confirmation prompt framework.

        The generated script includes:
        - Header with assessment context and safety warnings
        - Per-finding remediation blocks with finding metadata as comments
        - Inline $WhatIf guard (use -WhatIf on the generated script to preview)
        - Summary of manual-only findings that require portal action
    .PARAMETER Findings
        Array of TakeItToCloud finding objects. Accepts pipeline input.
        Typically the output of Invoke-TtcAssessment or an individual assessor.
    .PARAMETER OutputPath
        Path to write the generated remediation .ps1 script.
        If not specified, outputs to the current directory as TtcRemediation_{timestamp}.ps1.
    .PARAMETER SeverityFilter
        Only generate remediation blocks for findings at or above this severity level.
        Valid values: Critical, High, Medium, Low, Informational.
        Default: High (only Critical and High findings).
    .PARAMETER IncludePartial
        When specified, includes findings with AutoFixAvailable = 'Partial'.
        By default, only 'Yes' findings are included (fully automatable).
        Default: $true (both Yes and Partial are included).
    .PARAMETER PassThru
        When specified, returns the path of the generated script as output.
    .EXAMPLE
        # Generate remediation script from full assessment
        $result = Invoke-TtcAssessment -CustomerName "Contoso"
        Invoke-TtcAutoFix -Findings $result.Findings -OutputPath "C:\Remediation\Contoso_Fix.ps1"
    .EXAMPLE
        # Pipeline usage — generate script for AD findings only
        Invoke-TtcAdAssessment | Invoke-TtcAutoFix -SeverityFilter Critical
    .EXAMPLE
        # Generate script for all severities including partial fixes
        Invoke-TtcAutoFix -Findings $result.Findings -SeverityFilter Low -IncludePartial -PassThru
    .OUTPUTS
        [string] Path to the generated script file (only when -PassThru is specified).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Findings,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$SeverityFilter = 'High',

        [Parameter()]
        [switch]$IncludePartial = $true,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

        # Severity weight map for filtering
        $severityOrder = @{
            'Critical'      = 5
            'High'          = 4
            'Medium'        = 3
            'Low'           = 2
            'Informational' = 1
        }
        $minWeight = $severityOrder[$SeverityFilter]

        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
            $OutputPath = Join-Path -Path (Get-Location).Path -ChildPath "TtcRemediation_$timestamp.ps1"
        }

        Write-TtcLog -Level Info -Message "Invoke-TtcAutoFix: collecting findings for remediation script generation"
    }

    process {
        foreach ($finding in $Findings) {
            $allFindings.Add($finding)
        }
    }

    end {
        # Filter to fixable findings at or above the severity threshold
        $autoFixValues = if ($IncludePartial) { @('Yes', 'Partial') } else { @('Yes') }

        $fixableFindings = $allFindings | Where-Object {
            $_.AutoFixAvailable -in $autoFixValues -and
            $_.Status -in @('Fail', 'Warning') -and
            $severityOrder[$_.Severity] -ge $minWeight
        } | Sort-Object @{e = { $severityOrder[$_.Severity] }; d = $true }, FindingId

        $manualFindings = $allFindings | Where-Object {
            $_.AutoFixAvailable -eq 'No' -and
            $_.Status -in @('Fail', 'Warning') -and
            $severityOrder[$_.Severity] -ge $minWeight
        } | Sort-Object @{e = { $severityOrder[$_.Severity] }; d = $true }, FindingId

        $fixableCount = ($fixableFindings | Measure-Object).Count
        $manualCount  = ($manualFindings  | Measure-Object).Count

        Write-TtcLog -Level Info -Message "AutoFix: $fixableCount fixable findings, $manualCount manual-only findings at or above $SeverityFilter severity"

        if (-not $PSCmdlet.ShouldProcess($OutputPath, "Generate remediation script ($fixableCount fixable findings)")) {
            return
        }

        # =====================================================================
        # Build the remediation script content
        # =====================================================================
        $sb = [System.Text.StringBuilder]::new()

        # Header
        [void]$sb.AppendLine('#Requires -Version 5.1')
        [void]$sb.AppendLine('<#')
        [void]$sb.AppendLine('.SYNOPSIS')
        [void]$sb.AppendLine('    TakeItToCloud Auto-Generated Remediation Script')
        [void]$sb.AppendLine('.DESCRIPTION')
        [void]$sb.AppendLine("    Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$sb.AppendLine("    Source: TakeItToCloud.Assess Invoke-TtcAutoFix")
        [void]$sb.AppendLine("    Fixable findings: $fixableCount | Manual findings: $manualCount")
        [void]$sb.AppendLine("    Severity threshold: $SeverityFilter and above")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('    IMPORTANT SAFETY NOTICE:')
        [void]$sb.AppendLine('    - Review EVERY remediation block before executing')
        [void]$sb.AppendLine('    - Test in a non-production environment first')
        [void]$sb.AppendLine('    - Findings marked Partial require additional manual steps')
        [void]$sb.AppendLine('    - Some commands require specific PowerShell module connections')
        [void]$sb.AppendLine('    - Run with -WhatIf where supported to preview changes')
        [void]$sb.AppendLine('    - Document changes in your change management system')
        [void]$sb.AppendLine('#>')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('[CmdletBinding(SupportsShouldProcess)]')
        [void]$sb.AppendLine('param(')
        [void]$sb.AppendLine('    [switch]$Force   # Suppress per-finding confirmation prompts')
        [void]$sb.AppendLine(')')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Set-StrictMode -Version Latest')
        [void]$sb.AppendLine('$ErrorActionPreference = ''Stop''')
        [void]$sb.AppendLine('')

        if ($fixableCount -eq 0) {
            [void]$sb.AppendLine('# No fixable findings were found at the specified severity threshold.')
            [void]$sb.AppendLine("# Severity filter: $SeverityFilter | AutoFixAvailable values included: $($autoFixValues -join ', ')")
        }
        else {
            # Group by workload
            $byWorkload = $fixableFindings | Group-Object -Property Workload

            foreach ($group in $byWorkload) {
                $workloadName = $group.Name
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine('#' + ('=' * 79))
                [void]$sb.AppendLine("# WORKLOAD: $workloadName")
                [void]$sb.AppendLine('#' + ('=' * 79))

                foreach ($finding in $group.Group) {
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine('#' + ('-' * 79))
                    [void]$sb.AppendLine("# [$($finding.FindingId)] $($finding.CheckName)")
                    [void]$sb.AppendLine("# Severity: $($finding.Severity) | Status: $($finding.Status) | AutoFix: $($finding.AutoFixAvailable)")
                    [void]$sb.AppendLine("# Priority: $($finding.RemediationPriority) | Framework: $($finding.FrameworkMapping)")
                    [void]$sb.AppendLine("# Issue: $($finding.IssueDetected)")
                    [void]$sb.AppendLine('#' + ('-' * 79))

                    if ($finding.AutoFixAvailable -eq 'Partial') {
                        [void]$sb.AppendLine('# NOTE: AutoFixAvailable = Partial — manual steps may be required after running this block.')
                        [void]$sb.AppendLine("# Possible Solution: $($finding.PossibleSolution)")
                    }

                    [void]$sb.AppendLine('')

                    # Emit the remediation block with confirmation guard
                    [void]$sb.AppendLine("if (`$Force -or `$PSCmdlet.ShouldProcess('$($finding.FindingId)', '$($finding.CheckName -replace "'","''")')) {")
                    [void]$sb.AppendLine('    try {')

                    # Emit remediation steps as commented lines with the actual command
                    # The Remediation field contains the steps; emit each line indented
                    if (-not [string]::IsNullOrWhiteSpace($finding.Remediation)) {
                        $remLines = $finding.Remediation -split "`n"
                        foreach ($line in $remLines) {
                            $trimmed = $line.TrimEnd()
                            if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                                # Lines that look like PowerShell commands are emitted as code;
                                # prose lines are emitted as comments
                                if ($trimmed -match '^\s*(Get-|Set-|New-|Remove-|Add-|Enable-|Disable-|Import-|Connect-|Update-|Invoke-|Install-|Uninstall-)') {
                                    [void]$sb.AppendLine("        $trimmed")
                                }
                                else {
                                    [void]$sb.AppendLine("        # $trimmed")
                                }
                            }
                        }
                    }
                    else {
                        [void]$sb.AppendLine("        # No automated remediation command available for this finding.")
                        [void]$sb.AppendLine("        # Refer to the PossibleSolution and Impact fields for guidance:")
                        [void]$sb.AppendLine("        # $($finding.PossibleSolution)")
                    }

                    [void]$sb.AppendLine('        Write-Host "[FIXED] $($finding.FindingId): $($finding.CheckName -replace "'","''")" -ForegroundColor Green')
                    [void]$sb.AppendLine('    }')
                    [void]$sb.AppendLine('    catch {')
                    [void]$sb.AppendLine("        Write-Warning `"[FAILED] $($finding.FindingId): `$(`$_.Exception.Message)`"")
                    [void]$sb.AppendLine('    }')
                    [void]$sb.AppendLine('}')
                }
            }
        }

        # Manual findings summary section
        if ($manualCount -gt 0) {
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('#' + ('=' * 79))
            [void]$sb.AppendLine('# MANUAL REMEDIATION REQUIRED')
            [void]$sb.AppendLine('# The following findings have no automated fix (AutoFixAvailable = No).')
            [void]$sb.AppendLine('# Review each and take manual action as described.')
            [void]$sb.AppendLine('#' + ('=' * 79))

            foreach ($finding in $manualFindings) {
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine("# [$($finding.FindingId)] $($finding.CheckName) | $($finding.Severity) | $($finding.Status)")
                [void]$sb.AppendLine("# Issue    : $($finding.IssueDetected)")
                [void]$sb.AppendLine("# Solution : $($finding.PossibleSolution)")
                [void]$sb.AppendLine("# Priority : $($finding.RemediationPriority)")
            }
        }

        # Footer
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('# End of TakeItToCloud Remediation Script')
        [void]$sb.AppendLine("# Generated by Invoke-TtcAutoFix on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")

        # Write the file
        try {
            $scriptContent = $sb.ToString()
            $outputDir     = Split-Path -Path $OutputPath -Parent
            if (-not (Test-Path -Path $outputDir)) {
                New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
            }

            [System.IO.File]::WriteAllText($OutputPath, $scriptContent, [System.Text.Encoding]::UTF8)

            Write-TtcLog -Level Info -Message "Remediation script written to: $OutputPath ($fixableCount fixable, $manualCount manual)"
            Write-Host "[TtcAutoFix] Script generated: $OutputPath" -ForegroundColor Cyan
            Write-Host "[TtcAutoFix] Fixable findings: $fixableCount | Manual-only: $manualCount" -ForegroundColor Cyan
            Write-Host "[TtcAutoFix] Review the script carefully before executing." -ForegroundColor Yellow

            if ($PassThru) {
                return $OutputPath
            }
        }
        catch {
            Write-TtcLog -Level Error -Message "Failed to write remediation script to $OutputPath" -ErrorRecord $_
            Write-Error "Invoke-TtcAutoFix: Failed to write script — $($_.Exception.Message)"
        }
    }
}
