function Test-TtcPrerequisite {
    <#
    .SYNOPSIS
        Checks if required PowerShell modules are available for a workload.
    .DESCRIPTION
        Validates that the necessary modules are installed/imported for a given
        workload assessment. Returns a boolean and logs warnings for missing modules.
    .PARAMETER Workload
        The workload to check prerequisites for.
    .EXAMPLE
        if (Test-TtcPrerequisite -Workload 'ActiveDirectory') { # proceed }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ActiveDirectory', 'ExchangeOnline', 'HybridIdentity', 'EntraID', 'Defender', 'Collaboration', 'MDE', 'PIM', 'ADCS')]
        [string]$Workload
    )

    $prerequisites = @{
        'ActiveDirectory' = @('ActiveDirectory')
        'ExchangeOnline'  = @('ExchangeOnlineManagement')
        'HybridIdentity'  = @('Microsoft.Graph.Authentication')
        'EntraID'         = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Identity.SignIns')
        'Defender'        = @('ExchangeOnlineManagement')
        'Collaboration'   = @('Microsoft.Graph.Authentication')
        'MDE'             = @('Microsoft.Graph.Authentication')
        'PIM'             = @('Microsoft.Graph.Authentication')
        'ADCS'            = @('ActiveDirectory')
    }

    $required = $prerequisites[$Workload]
    if (-not $required) {
        Write-TtcLog -Level Warning -Message "No prerequisite definition for workload: $Workload"
        return $true
    }

    $allPresent = $true
    foreach ($module in $required) {
        if (-not (Get-Module -Name $module -ListAvailable -ErrorAction SilentlyContinue)) {
            Write-TtcLog -Level Warning -Message "Required module not found: $module (needed for $Workload assessment)"
            $allPresent = $false
        }
        else {
            Write-TtcLog -Level Debug -Message "Prerequisite met: $module"
        }
    }

    return $allPresent
}
