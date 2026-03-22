function Write-TtcLog {
    <#
    .SYNOPSIS
        Centralized logging for the TakeItToCloud.Assess framework.
    .DESCRIPTION
        Writes structured log messages to console and to a date-stamped log file.

        Console output behaviour:
        - Info    : Written to Write-Host (green label) when $script:TtcConsoleLogging = $true,
                    or always via Write-Verbose when running with -Verbose.
        - Warning : Always written to Write-Warning (yellow).
        - Error   : Always written to Write-Warning with [ERROR] prefix and exception detail.
        - Debug   : Written to Write-Debug (requires -Debug switch).

        File output:
        - All levels (including Debug) are written to the daily log file unconditionally.
        - Log file path: <ModuleRoot>\Logs\TtcAssess_yyyyMMdd.log
        - Each entry: [timestamp] [LEVEL] [caller] message | Exception: ...

        Control behaviour via module-scope variables (set in psm1 or at runtime):
        - $script:TtcLogPath        : Override log directory (default: <module>\Logs)
        - $script:TtcConsoleLogging : $true = show Info to console without needing -Verbose
        - $script:TtcSessionId      : Short ID stamped on every log entry for multi-run tracing
    .PARAMETER Level
        Log level: Info, Warning, Error, Debug.
    .PARAMETER Message
        The log message text.
    .PARAMETER ErrorRecord
        Optional ErrorRecord for Error-level logging. Appends exception message and
        script stack trace to the log entry.
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

    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $sessionId  = if ($script:TtcSessionId) { $script:TtcSessionId } else { '' }
    $sessionTag = if ($sessionId) { " [$sessionId]" } else { '' }

    # Caller info (one frame up from Write-TtcLog itself)
    $caller = ''
    try {
        $callStack = Get-PSCallStack
        if ($callStack -and $callStack.Count -gt 1) {
            $caller = $callStack[1].FunctionName
            if ($caller -eq '<ScriptBlock>') { $caller = $callStack[1].ScriptName | Split-Path -Leaf }
        }
    }
    catch { }
    $callerTag = if ($caller) { " [$caller]" } else { '' }

    # Build log entry for file
    $logEntry = "[$timestamp]$sessionTag [$Level]$callerTag $Message"

    if ($ErrorRecord) {
        $excMsg   = $ErrorRecord.Exception.Message
        $excType  = $ErrorRecord.Exception.GetType().Name
        $position = if ($ErrorRecord.InvocationInfo.PositionMessage) {
            $ErrorRecord.InvocationInfo.PositionMessage -replace "`r?`n", ' | '
        } else { '' }
        $logEntry += " | Exception($excType): $excMsg"
        if ($position) { $logEntry += " | At: $position" }

        # Append inner exception if present
        if ($ErrorRecord.Exception.InnerException) {
            $logEntry += " | InnerException: $($ErrorRecord.Exception.InnerException.Message)"
        }
    }

    # --- Console output ---
    $consoleLogging = if ($null -ne $script:TtcConsoleLogging) { $script:TtcConsoleLogging } else { $false }

    switch ($Level) {
        'Info' {
            if ($consoleLogging) {
                Write-Host "  " -NoNewline
                Write-Host "[INFO] " -NoNewline -ForegroundColor DarkGreen
                Write-Host $Message -ForegroundColor Gray
            }
            Write-Verbose -Message $logEntry
        }
        'Warning' {
            Write-Warning -Message $Message
        }
        'Error' {
            $errConsole = "[ERROR] $Message"
            if ($ErrorRecord) { $errConsole += ": $($ErrorRecord.Exception.Message)" }
            Write-Warning -Message $errConsole
        }
        'Debug' {
            Write-Debug -Message $logEntry
        }
    }

    # --- File output (always, all levels) ---
    try {
        $logDir = if ($script:TtcLogPath) { $script:TtcLogPath } else {
            Join-Path -Path $PSScriptRoot -ChildPath '..\Logs'
        }
        if (-not (Test-Path -Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        $logFile = Join-Path -Path $logDir -ChildPath "TtcAssess_$(Get-Date -Format 'yyyyMMdd').log"
        Add-Content -Path $logFile -Value $logEntry -Encoding UTF8
    }
    catch {
        # Logging must never crash the assessment pipeline
        Write-Debug "Write-TtcLog: failed to write log file: $_"
    }
}


function Enable-TtcConsoleLogging {
    <#
    .SYNOPSIS
        Enables verbose INFO-level console output for the TakeItToCloud.Assess module.
    .DESCRIPTION
        Sets the module-scope $script:TtcConsoleLogging flag to $true so that
        Write-TtcLog at Info level writes to the console (Write-Host) in addition
        to the log file, without requiring PowerShell -Verbose mode.

        Useful when running assessments interactively and wanting to see progress
        without capturing verbose stream output.
    .EXAMPLE
        Enable-TtcConsoleLogging
        $result = Invoke-TtcAssessment -CustomerName "Contoso"
    #>
    [CmdletBinding()]
    param()
    $script:TtcConsoleLogging = $true
    Write-Host "[TTC] Console logging enabled - Info messages will appear in terminal." -ForegroundColor DarkGreen
}


function Disable-TtcConsoleLogging {
    <#
    .SYNOPSIS
        Disables verbose INFO-level console output.
    .DESCRIPTION
        Sets $script:TtcConsoleLogging to $false. Info messages go to log file only.
    .EXAMPLE
        Disable-TtcConsoleLogging
    #>
    [CmdletBinding()]
    param()
    $script:TtcConsoleLogging = $false
    Write-Host "[TTC] Console logging disabled." -ForegroundColor DarkYellow
}


function Set-TtcLogPath {
    <#
    .SYNOPSIS
        Overrides the default log file directory for the current session.
    .DESCRIPTION
        Sets $script:TtcLogPath to the specified directory. Subsequent Write-TtcLog
        calls write to this path instead of the default <module>\Logs directory.
        Creates the directory if it does not exist.
    .PARAMETER Path
        Directory path for log files.
    .EXAMPLE
        Set-TtcLogPath -Path "C:\Assessments\Logs"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
    $script:TtcLogPath = $Path
    Write-Host "[TTC] Log path set to: $Path" -ForegroundColor DarkGreen
}


function Get-TtcLogPath {
    <#
    .SYNOPSIS
        Returns the current log file directory path.
    .EXAMPLE
        Get-TtcLogPath
    #>
    [CmdletBinding()]
    param()
    $path = if ($script:TtcLogPath) { $script:TtcLogPath } else { Join-Path -Path $script:TtcModuleRoot -ChildPath 'Logs' }
    return $path
}
