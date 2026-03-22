#Requires -Version 5.1
<#
.SYNOPSIS
    TakeItToCloud.Assess module loader.
.DESCRIPTION
    Dot-sources all public, private, and assessor functions.
    Public functions are exported via the module manifest.
    Private functions and assessor functions remain internal.
#>

$ModuleRoot = $PSScriptRoot

# --- Dot-source Private functions first (dependencies for Public + Assessors) ---
$PrivatePath = Join-Path -Path $ModuleRoot -ChildPath 'Private'
if (Test-Path -Path $PrivatePath) {
    $PrivateFiles = Get-ChildItem -Path $PrivatePath -Filter '*.ps1' -ErrorAction SilentlyContinue
    foreach ($file in $PrivateFiles) {
        try {
            . $file.FullName
            Write-Verbose "Loaded private function: $($file.BaseName)"
        }
        catch {
            Write-Warning "Failed to load private function $($file.Name): $_"
        }
    }
}

# --- Dot-source Assessor functions ---
$AssessorPath = Join-Path -Path $ModuleRoot -ChildPath 'Assessors'
if (Test-Path -Path $AssessorPath) {
    $AssessorFiles = Get-ChildItem -Path $AssessorPath -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $AssessorFiles) {
        try {
            . $file.FullName
            Write-Verbose "Loaded assessor: $($file.BaseName)"
        }
        catch {
            Write-Warning "Failed to load assessor $($file.Name): $_"
        }
    }
}

# --- Dot-source Public functions last ---
$PublicPath = Join-Path -Path $ModuleRoot -ChildPath 'Public'
if (Test-Path -Path $PublicPath) {
    $PublicFiles = Get-ChildItem -Path $PublicPath -Filter '*.ps1' -ErrorAction SilentlyContinue
    foreach ($file in $PublicFiles) {
        try {
            . $file.FullName
            Write-Verbose "Loaded public function: $($file.BaseName)"
        }
        catch {
            Write-Warning "Failed to load public function $($file.Name): $_"
        }
    }
}

# --- Set module-level variables ---
$script:TtcModuleRoot     = $ModuleRoot
$script:TtcLogPath        = Join-Path -Path $ModuleRoot -ChildPath 'Logs'
$script:TtcRulesPath      = Join-Path -Path $ModuleRoot -ChildPath 'Rules'
$script:TtcConfigPath     = Join-Path -Path $ModuleRoot -ChildPath 'Config'
$script:TtcConsoleLogging = $false  # Set to $true or call Enable-TtcConsoleLogging
$script:TtcSessionId      = [System.Guid]::NewGuid().ToString('N').Substring(0, 8)  # Short session ID for log correlation

# Ensure Logs directory exists
if (-not (Test-Path -Path $script:TtcLogPath)) {
    New-Item -Path $script:TtcLogPath -ItemType Directory -Force | Out-Null
}

# Write session start banner to log file
$sessionBanner = "=" * 80
$sessionInfo   = "[$([datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))] [INFO] [$($script:TtcSessionId)] === TakeItToCloud.Assess v1.1.0 session started | User: $env:USERNAME | Host: $env:COMPUTERNAME | PS: $($PSVersionTable.PSVersion) ==="
try {
    $logFile = Join-Path -Path $script:TtcLogPath -ChildPath "TtcAssess_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $sessionBanner    -Encoding UTF8
    Add-Content -Path $logFile -Value $sessionInfo      -Encoding UTF8
    Add-Content -Path $logFile -Value $sessionBanner    -Encoding UTF8
}
catch { }

Write-Verbose "TakeItToCloud.Assess module loaded from $ModuleRoot (Session: $($script:TtcSessionId))"
