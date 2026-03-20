function Get-TtcRulePack {
    <#
    .SYNOPSIS
        Loads a JSON rule pack for a given workload.
    .DESCRIPTION
        Reads and parses a rule definition file from the Rules directory.
        Returns the rules as PowerShell objects for use by assessor functions.
    .PARAMETER Workload
        The workload name matching a Rules/{Workload}.Rules.json file.
    .PARAMETER RulesPath
        Optional override for the rules directory path.
    .EXAMPLE
        $rules = Get-TtcRulePack -Workload 'ActiveDirectory'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Workload,

        [string]$RulesPath
    )

    if ([string]::IsNullOrWhiteSpace($RulesPath)) {
        $RulesPath = if ($script:TtcRulesPath) { $script:TtcRulesPath } else { Join-Path $PSScriptRoot '..\Rules' }
    }

    # Map workload names to file names
    $fileMap = @{
        'ActiveDirectory' = 'AD.Rules.json'
        'ExchangeOnline'  = 'ExchangeOnline.Rules.json'
        'HybridIdentity'  = 'HybridIdentity.Rules.json'
        'EntraID'         = 'EntraID.Rules.json'
        'Defender'        = 'Defender.Rules.json'
        'Collaboration'   = 'Collaboration.Rules.json'
    }

    $fileName = $fileMap[$Workload]
    if (-not $fileName) {
        Write-TtcLog -Level Warning -Message "No rule pack mapping found for workload: $Workload"
        return $null
    }

    $filePath = Join-Path -Path $RulesPath -ChildPath $fileName

    if (-not (Test-Path -Path $filePath)) {
        Write-TtcLog -Level Warning -Message "Rule pack file not found: $filePath"
        return $null
    }

    try {
        $content = Get-Content -Path $filePath -Raw -Encoding UTF8
        $rulePack = $content | ConvertFrom-Json
        Write-TtcLog -Level Info -Message "Loaded rule pack '$($rulePack.RulePackName)' with $($rulePack.Rules.Count) rules"
        return $rulePack
    }
    catch {
        Write-TtcLog -Level Error -Message "Failed to parse rule pack: $filePath" -ErrorRecord $_
        return $null
    }
}
