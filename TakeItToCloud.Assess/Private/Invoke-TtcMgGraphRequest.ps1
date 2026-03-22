function Invoke-TtcMgGraphRequest {
    <#
    .SYNOPSIS
        Wrapper around Invoke-MgGraphRequest with automatic retry on throttling.
    .DESCRIPTION
        Handles HTTP 429 (Too Many Requests) and 503 (Service Unavailable) responses
        from the Microsoft Graph API by honouring the Retry-After header and retrying
        up to MaxRetries times. Falls through to the caller on any other error.
    .PARAMETER Uri
        The Graph API URI to request (e.g. '/v1.0/users').
    .PARAMETER Method
        HTTP method. Default: GET.
    .PARAMETER Body
        Optional request body for POST/PATCH requests.
    .PARAMETER MaxRetries
        Maximum number of retry attempts on throttling. Default: 3.
    .PARAMETER DefaultRetrySeconds
        Seconds to wait if no Retry-After header is present. Default: 30.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [string]$Method = 'GET',

        [hashtable]$Body,

        [ValidateRange(1, 10)]
        [int]$MaxRetries = 3,

        [ValidateRange(1, 120)]
        [int]$DefaultRetrySeconds = 30
    )

    $attempt = 0

    while ($attempt -le $MaxRetries) {
        try {
            $params = @{ Uri = $Uri; Method = $Method; ErrorAction = 'Stop' }
            if ($Body) { $params['Body'] = $Body }
            return Invoke-MgGraphRequest @params
        }
        catch {
            $statusCode = $null
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}

            if ($statusCode -in @(429, 503) -and $attempt -lt $MaxRetries) {
                $retryAfter = $DefaultRetrySeconds
                try {
                    $headerVal = $_.Exception.Response.Headers.GetValues('Retry-After') | Select-Object -First 1
                    if ($headerVal) { $retryAfter = [int]$headerVal }
                }
                catch {}

                $attempt++
                Write-TtcLog -Level Warning -Message "Graph API throttled (HTTP $statusCode). Waiting ${retryAfter}s before retry $attempt/$MaxRetries — URI: $Uri"
                Start-Sleep -Seconds $retryAfter
            }
            else {
                throw
            }
        }
    }
}
