function Test-TtcGraphConnection {
    <#
    .SYNOPSIS
        Validates that an active Microsoft Graph connection exists with required scopes.
    .DESCRIPTION
        Checks for an active Connect-MgGraph session and optionally verifies that the
        required permission scopes are present in the current context. Returns $true if
        the connection is valid, $false otherwise.
    .PARAMETER RequiredScopes
        Optional array of scope names that must be present in the current context.
        Example: @('Directory.Read.All', 'AuditLog.Read.All')
    .PARAMETER Workload
        Workload name used for log messages. Default: 'Unknown'.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [string[]]$RequiredScopes = @(),
        [string]$Workload = 'Unknown'
    )

    try {
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $ctx) {
            Write-TtcLog -Level Warning -Message "[$Workload] No active Microsoft Graph connection. Run Connect-MgGraph before the assessment."
            return $false
        }

        if ($RequiredScopes.Count -gt 0) {
            $grantedScopes = $ctx.Scopes
            $missing = $RequiredScopes | Where-Object { $_ -notin $grantedScopes }
            if ($missing.Count -gt 0) {
                Write-TtcLog -Level Warning -Message "[$Workload] Graph connection exists but missing scopes: $($missing -join ', '). Re-run Connect-MgGraph with the required scopes."
                return $false
            }
        }

        return $true
    }
    catch {
        Write-TtcLog -Level Warning -Message "[$Workload] Could not validate Graph connection: $_"
        return $false
    }
}
