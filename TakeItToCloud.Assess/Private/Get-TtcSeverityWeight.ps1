function Get-TtcSeverityWeight {
    <#
    .SYNOPSIS
        Returns the numeric weight for a severity level.
    .DESCRIPTION
        Maps severity strings to numeric weights used in scoring calculations.
        Critical=10, High=7, Medium=4, Low=1, Informational=0.
    .PARAMETER Severity
        The severity level string.
    .EXAMPLE
        Get-TtcSeverityWeight -Severity 'Critical'  # Returns 10
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Severity
    )

    switch ($Severity) {
        'Critical'      { 10 }
        'High'          { 7 }
        'Medium'        { 4 }
        'Low'           { 1 }
        'Informational' { 0 }
        default         { 0 }
    }
}
