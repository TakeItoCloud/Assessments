function Write-TtcLog {
    <#
    .SYNOPSIS
        Centralized logging for the TakeItToCloud.Assess framework.
    .DESCRIPTION
        Writes log messages to console (via Write-Verbose/Write-Warning/Write-Error)
        and to a date-stamped log file in the Logs directory.
    .PARAMETER Level
        Log level: Info, Warning, Error, Debug.
    .PARAMETER Message
        The log message text.
    .PARAMETER ErrorRecord
        Optional ErrorRecord object for Error-level logging.
    .EXAMPLE
        Write-TtcLog -Level Info -Message "Starting AD assessment"
    .EXAMPLE
        Write-TtcLog -Level Error -Message "Connection failed" -ErrorRecord $_
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry  = "[$timestamp] [$Level] $Message"

    if ($ErrorRecord) {
        $logEntry += " | Exception: $($ErrorRecord.Exception.Message)"
    }

    # Console output
    switch ($Level) {
        'Info'    { Write-Verbose -Message $logEntry }
        'Warning' { Write-Warning -Message $Message }
        'Error'   { Write-Warning -Message "[ERROR] $Message" }
        'Debug'   { Write-Debug -Message $logEntry }
    }

    # File output
    try {
        $logDir = if ($script:TtcLogPath) { $script:TtcLogPath } else { Join-Path $PSScriptRoot '..\Logs' }
        if (-not (Test-Path -Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        $logFile = Join-Path -Path $logDir -ChildPath "TtcAssess_$(Get-Date -Format 'yyyyMMdd').log"
        $logEntry | Out-File -FilePath $logFile -Append -Encoding utf8
    }
    catch {
        # Logging should never crash the pipeline
        Write-Debug "Failed to write log file: $_"
    }
}
