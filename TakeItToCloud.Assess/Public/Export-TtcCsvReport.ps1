function Export-TtcCsvReport {
    <#
    .SYNOPSIS
        Exports assessment findings to a CSV report.
    .DESCRIPTION
        Creates a UTF-8 (with BOM) CSV file containing all findings from an assessment.
        The output is structured for easy ingestion in Excel, Power BI, or remediation
        tracking systems. One row per finding with all schema properties as columns.
    .PARAMETER Findings
        Array of finding objects from an assessment run.
    .PARAMETER OutputPath
        Path for the CSV file. Defaults to ./Reports/TtcAssessment_{date}.csv.
    .OUTPUTS
        System.IO.FileInfo — the created CSV file.
    .EXAMPLE
        Export-TtcCsvReport -Findings $findings -OutputPath "C:\Reports\Assessment.csv"
    .EXAMPLE
        $findings | Export-TtcCsvReport
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Findings,

        [string]$OutputPath
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
            Write-TtcLog -Level Warning -Message "No findings to export to CSV"
            return
        }

        # Default output path
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $reportDir = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
            if (-not (Test-Path -Path $reportDir)) {
                New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
            }
            $OutputPath = Join-Path -Path $reportDir -ChildPath "TtcAssessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        }
        else {
            $parentDir = Split-Path -Path $OutputPath -Parent
            if ($parentDir -and -not (Test-Path -Path $parentDir)) {
                New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
            }
        }

        try {
            # Export with UTF-8 BOM for Excel compatibility
            $allFindings | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

            $fileInfo = Get-Item -Path $OutputPath
            Write-TtcLog -Level Info -Message "CSV report exported: $OutputPath ($($allFindings.Count) findings, $([math]::Round($fileInfo.Length / 1KB, 1)) KB)"
            return $fileInfo
        }
        catch {
            Write-TtcLog -Level Error -Message "Failed to export CSV report" -ErrorRecord $_
            throw
        }
    }
}
