# TakeItToCloud.Assess — Complete How-To Guide

> **Version 1.1.0** | Production-grade Microsoft 365, Hybrid Identity & On-Premises Infrastructure Assessment Framework

---

## Table of Contents

1. [Overview](#1-overview)
2. [Repository Layout](#2-repository-layout)
3. [Installation & First-Time Setup](#3-installation--first-time-setup)
4. [Connecting to Services](#4-connecting-to-services)
5. [Running a Full Assessment](#5-running-a-full-assessment)
6. [Running Individual Workload Assessors](#6-running-individual-workload-assessors)
7. [Output Files — Reports, Logs, and CSVs](#7-output-files--reports-logs-and-csvs)
8. [Console Summary — Get-TtcFindingSummary](#8-console-summary--get-ttcfindingsummary)
9. [Delta / Trend Reporting — Compare-TtcAssessment](#9-delta--trend-reporting--compare-ttcassessment)
10. [Remediation Script Generator — Invoke-TtcAutoFix](#10-remediation-script-generator--invoke-ttcautofix)
11. [Logging — Enhanced Logging System](#11-logging--enhanced-logging-system)
12. [Configuration File — DefaultConfig.json](#12-configuration-file--defaultconfigjson)
13. [Excluding Checks](#13-excluding-checks)
14. [Scoring Engine](#14-scoring-engine)
15. [All Assessors — Complete Check Reference](#15-all-assessors--complete-check-reference)
16. [Advanced Usage & Automation](#16-advanced-usage--automation)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. Overview

**TakeItToCloud.Assess** is a PowerShell 5.1+ module that performs automated security, health, and governance assessments across:

| Workload | Assessor | Checks |
|----------|----------|--------|
| Active Directory | `Invoke-TtcAdAssessment` | 19 checks (AD replication, delegation, Kerberoasting, DCSync, AdminSDHolder, etc.) |
| Entra ID (Azure AD) | `Invoke-TtcEntraAssessment` | 16 checks (MFA, CA, PIM adoption, FIDO2, break-glass, etc.) |
| Exchange Online | `Invoke-TtcExoAssessment` | 14 checks (DKIM, DMARC, inbox rules, EWS, SCL bypass, etc.) |
| Hybrid Identity | `Invoke-TtcHybridAssessment` | 8 checks (Entra Connect sync, PHS, stale sync objects, etc.) |
| Defender for Office 365 | `Invoke-TtcDefenderAssessment` | 8 checks (Safe Links, Safe Attachments, anti-phishing, etc.) |
| Collaboration (SPO/Teams) | `Invoke-TtcCollabAssessment` | 8 checks (external sharing, sensitivity labels, retention, etc.) |
| Microsoft Defender for Endpoint | `Invoke-TtcMdeAssessment` | 6 checks (device onboarding, Secure Score, alerts, compliance) |
| Privileged Identity Management | `Invoke-TtcPimAssessment` | 4 checks (activation policy, standing access, access reviews) |
| AD Certificate Services | `Invoke-TtcAdcsAssessment` | 5 checks (ESC1/2/3/6/8 certificate template vulnerabilities) |

---

## 2. Repository Layout

```
Assessments/
|-- TakeItToCloud.Assess/              # Module root
|   |-- TakeItToCloud.Assess.psd1      # Module manifest (version, exports)
|   |-- TakeItToCloud.Assess.psm1      # Module loader (dot-sources all functions)
|   |
|   |-- Assessors/                     # One subfolder per workload
|   |   |-- ActiveDirectory/Invoke-TtcAdAssessment.ps1
|   |   |-- EntraID/Invoke-TtcEntraAssessment.ps1
|   |   |-- ExchangeOnline/Invoke-TtcExoAssessment.ps1
|   |   |-- HybridIdentity/Invoke-TtcHybridAssessment.ps1
|   |   |-- Defender/Invoke-TtcDefenderAssessment.ps1
|   |   |-- Collaboration/Invoke-TtcCollabAssessment.ps1
|   |   |-- MDE/Invoke-TtcMdeAssessment.ps1
|   |   |-- PIM/Invoke-TtcPimAssessment.ps1
|   |   |-- ADCS/Invoke-TtcAdcsAssessment.ps1
|   |
|   |-- Public/                        # Exported (user-facing) functions
|   |   |-- Invoke-TtcAssessment.ps1   # Main orchestrator
|   |   |-- Export-TtcCsvReport.ps1    # CSV export
|   |   |-- Export-TtcHtmlReport.ps1   # HTML report
|   |   |-- Get-TtcAssessmentScore.ps1 # Scoring engine
|   |   |-- Get-TtcFindingSummary.ps1  # Console/Markdown/JSON summary
|   |   |-- Invoke-TtcAutoFix.ps1      # Remediation script generator
|   |   |-- Compare-TtcAssessment.ps1  # Delta/trend comparison
|   |   |-- New-TtcFindingObject.ps1   # Public finding constructor
|   |
|   |-- Private/                       # Internal helper functions
|   |   |-- Write-TtcLog.ps1           # Logging engine + Enable/Disable/Set helpers
|   |   |-- New-TtcFinding.ps1         # Internal finding factory
|   |   |-- Invoke-TtcMgGraphRequest.ps1  # Graph API retry wrapper
|   |   |-- Test-TtcGraphConnection.ps1   # Graph connection validator
|   |   |-- Test-TtcPrerequisite.ps1   # Module prereq checker
|   |   |-- Get-TtcHtmlTemplate.ps1    # HTML report template
|   |   |-- Get-TtcRulePack.ps1        # JSON rule loader
|   |   |-- Get-TtcSeverityWeight.ps1  # Severity weight lookup
|   |   |-- Resolve-TtcFrameworkMapping.ps1
|   |
|   |-- Config/
|   |   |-- DefaultConfig.json         # Default assessment configuration
|   |
|   |-- Rules/                         # JSON rule packs per workload
|   |   |-- AD.Rules.json
|   |   |-- EntraID.Rules.json
|   |   |-- ExchangeOnline.Rules.json
|   |   |-- Defender.Rules.json
|   |   |-- HybridIdentity.Rules.json
|   |   |-- Collaboration.Rules.json
|   |   |-- MDE.Rules.json
|   |   |-- PIM.Rules.json
|   |   |-- ADCS.Rules.json
|   |
|   |-- Tests/                         # Pester 5.x test suite
|   |   |-- TtcEngine.Tests.ps1        # 23 unit tests (engine, scoring, autofix)
|   |   |-- TtcReports.Tests.ps1       # 18 unit tests (CSV, HTML, summary)
|   |
|   |-- Logs/                          # Auto-created on first run
|   |   |-- TtcAssess_yyyyMMdd.log     # Daily log file (UTF-8)
|   |
|   |-- Reports/                       # Default output folder (auto-created)
|       |-- TtcAssessment_*.csv        # CSV findings export
|       |-- TtcAssessment_*.html       # HTML interactive report
|
|-- ProjectDocs/
|   |-- PHASE_TRACKER.md              # Development phase log
|   |-- PROJECT_SPEC.md               # Architecture specification
|
|-- HOWTO.md                          # This file
|-- README.md                         # Quick-start and overview
```

---

## 3. Installation & First-Time Setup

### Step 1 — Unblock files (required for downloaded scripts)

```powershell
# Run once after cloning/downloading the repository
Get-ChildItem -Path "C:\Scripts\Assessment\Assessments" -Recurse -Filter "*.ps1" |
    Unblock-File

Get-ChildItem -Path "C:\Scripts\Assessment\Assessments" -Recurse -Filter "*.psd1" |
    Unblock-File
```

> **Why?** Windows marks files downloaded from the internet as blocked. PowerShell refuses to load blocked modules. This must run **before** `Import-Module`.

### Step 2 — Import the module

```powershell
# Navigate to the repository root
Set-Location "C:\Scripts\Assessment\Assessments"

# Import the module (-Force ensures a clean reload)
Import-Module .\TakeItToCloud.Assess\TakeItToCloud.Assess.psd1 -Force

# Verify it loaded correctly
Get-Module TakeItToCloud.Assess
Get-Command -Module TakeItToCloud.Assess
```

### Step 3 — Install required PowerShell modules

Install the modules needed for the workloads you plan to assess. Each module only needs to be installed once.

```powershell
# Active Directory and AD CS
# (RSAT must be installed at the OS level on Windows 10/11 or Windows Server)
# For Windows 10/11:
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.CertificateServices.Tools~~~~0.0.1.0

# Exchange Online / Defender for Office 365 / Collaboration
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force

# Entra ID / Hybrid Identity / MDE / PIM
Install-Module Microsoft.Graph -Scope CurrentUser -Force
# Or install specific sub-modules (smaller download):
Install-Module Microsoft.Graph.Authentication               -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.SignIns             -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Reports                      -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Users                        -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Security                     -Scope CurrentUser -Force
Install-Module Microsoft.Graph.DeviceManagement            -Scope CurrentUser -Force

# Pester (for running the test suite)
Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck
```

---

## 4. Connecting to Services

Connect **before** running the assessment for each workload. You do not need to connect to services for workloads you are not assessing.

### Active Directory (on-premises)

```powershell
# No explicit connection needed — uses current domain credentials.
# Machine must be domain-joined or have AD module installed.
Import-Module ActiveDirectory

# Verify connectivity
Get-ADDomain
```

### Exchange Online

```powershell
# Basic connection (uses browser-based modern auth)
Connect-ExchangeOnline

# With explicit UPN
Connect-ExchangeOnline -UserPrincipalName admin@contoso.com

# With certificate-based auth (for unattended/automation)
Connect-ExchangeOnline -AppId $appId -CertificateThumbprint $thumbprint -Organization contoso.com

# Verify
Get-OrganizationConfig | Select-Object DisplayName, Name
```

### Microsoft Graph (Entra ID, Hybrid Identity, MDE, PIM)

```powershell
# Full assessment — all scopes for all Graph-based workloads
Connect-MgGraph -Scopes @(
    "User.Read.All",
    "Policy.Read.All",
    "Directory.Read.All",
    "IdentityRiskyUser.Read.All",
    "AuditLog.Read.All",
    "Organization.Read.All",
    "Reports.Read.All",
    "UserAuthenticationMethod.Read.All",
    "SecurityEvents.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "RoleManagement.Read.Directory",
    "PrivilegedAccess.Read.AzureAD",
    "Application.Read.All"
)

# Verify
Get-MgContext

# Minimum scopes for individual workloads:

# Entra ID only
Connect-MgGraph -Scopes "User.Read.All","Policy.Read.All","Directory.Read.All","IdentityRiskyUser.Read.All","AuditLog.Read.All","Organization.Read.All","Reports.Read.All","UserAuthenticationMethod.Read.All"

# MDE only
Connect-MgGraph -Scopes "SecurityEvents.Read.All","DeviceManagementManagedDevices.Read.All"

# PIM only
Connect-MgGraph -Scopes "RoleManagement.Read.Directory","PrivilegedAccess.Read.AzureAD","Directory.Read.All"
```

### SharePoint Online / Collaboration (optional fallback)

```powershell
# Primary: Collaboration assessor uses Microsoft Graph (included in Connect-MgGraph above)
# Fallback: Install SPO Management Shell if Graph scopes cannot be granted
Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
Connect-SPOService -Url https://contoso-admin.sharepoint.com

# Optional: IPPS (Compliance) for retention policy check
Connect-IPPSSession -UserPrincipalName admin@contoso.com

# Optional: Teams for Teams guest access check
Import-Module MicrosoftTeams
Connect-MicrosoftTeams
```

---

## 5. Running a Full Assessment

### Basic full assessment

```powershell
$result = Invoke-TtcAssessment -CustomerName "Contoso Ltd" -AssessedBy "Alice"
```

This runs all 9 workload assessors, generates a CSV and HTML report in `.\Reports\`, and returns a result object.

### Full assessment with all parameters

```powershell
$result = Invoke-TtcAssessment `
    -CustomerName    "Contoso Ltd" `
    -AssessedBy      "Alice Smith" `
    -ReportTitle     "Q1 2026 Security Assessment" `
    -OutputPath      "C:\Assessments\Contoso\2026-Q1" `
    -GenerateCsv     $true `
    -GenerateHtml    $true `
    -Workloads       @("ActiveDirectory", "EntraID", "ExchangeOnline", "MDE", "PIM", "ADCS") `
    -ExcludeWorkloads @() `
    -ExcludeChecks   @("AD-CFG-002") `
    -ExcludeChecksFile "C:\Assessments\suppressions.txt" `
    -ConfigPath      "C:\Assessments\myconfig.json" `
    -SkipPrerequisiteCheck:$false
```

### Parameter reference

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-CustomerName` | String | `''` | Customer name in report header |
| `-AssessedBy` | String | `''` | Assessor name in report metadata |
| `-ReportTitle` | String | `'Infrastructure & Security Assessment'` | HTML report title |
| `-OutputPath` | String | `.\Reports` | Directory for CSV and HTML output |
| `-Workloads` | String[] | All 9 | Limit to specific workloads |
| `-ExcludeWorkloads` | String[] | `@()` | Skip these workloads |
| `-ExcludeChecks` | String[] | `@()` | Suppress specific FindingId values |
| `-ExcludeChecksFile` | String | — | Path to a text file with one FindingId per line to suppress. Lines starting with `#` are comments |
| `-GenerateCsv` | Bool | `$true` | Write CSV report to `-OutputPath` |
| `-GenerateHtml` | Bool | `$true` | Write HTML report to `-OutputPath` |
| `-SkipPrerequisiteCheck` | Switch | — | Skip module prereq check (use if modules load differently) |
| `-ConfigPath` | String | — | Custom JSON config file path |

### Accessing the result object

```powershell
# View summary in console
Get-TtcFindingSummary -Findings $result.Findings -Scores $result.Scores -CustomerName "Contoso"

# See what files were generated
$result.CsvReport
$result.HtmlReport

# See the scores
$result.Scores.OverallScore
$result.Scores.SecurityScore
$result.Scores.HealthScore
$result.Scores.GovernanceScore

# Count Critical failures
($result.Findings | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Fail' }).Count

# See all failed findings sorted by severity
$result.Findings | Where-Object { $_.Status -eq 'Fail' } |
    Sort-Object @{e={@{Critical=5;High=4;Medium=3;Low=2;Informational=1}[$_.Severity]};d=$true} |
    Select-Object FindingId, Severity, CheckName, IssueDetected | Format-Table -AutoSize
```

### Valid workload names

```
ActiveDirectory   ExchangeOnline   HybridIdentity   EntraID
Defender          Collaboration    MDE              PIM     ADCS
```

### Example: AD and Entra only, no HTML

```powershell
$result = Invoke-TtcAssessment `
    -Workloads @("ActiveDirectory", "EntraID") `
    -GenerateHtml $false `
    -CustomerName "Fabrikam"
```

### Example: Everything except AD CS (cloud-only tenant)

```powershell
$result = Invoke-TtcAssessment `
    -ExcludeWorkloads @("ADCS") `
    -CustomerName "Acme Corp"
```

---

## 6. Running Individual Workload Assessors

Each assessor can be run independently. This is useful when:
- You only have one service connection available
- You want to iterate quickly on a single area
- You are integrating findings with other tools

### Active Directory

```powershell
# Basic
$adFindings = Invoke-TtcAdAssessment

# Results include: DC replication, OS version, Kerberoasting, AS-REP, DCSync, AdminSDHolder, etc.
$adFindings | Where-Object { $_.Status -eq 'Fail' } | Format-Table FindingId, Severity, CheckName
```

### Entra ID

```powershell
# Basic (uses current Graph connection)
$entFindings = Invoke-TtcEntraAssessment

# With tuned thresholds
$entFindings = Invoke-TtcEntraAssessment `
    -StaleGuestDays  60 `   # Flag guests who haven't signed in for 60 days (default 90)
    -MaxGlobalAdmins 4      # Flag more than 4 permanent GAs (default 5)
```

### Exchange Online

```powershell
# Basic
$exoFindings = Invoke-TtcExoAssessment

# Tune the Organization Management role group member limit
$exoFindings = Invoke-TtcExoAssessment -MaxOrgMgmtMembers 3

# Include .onmicrosoft.com domains in DKIM/SPF checks
$exoFindings = Invoke-TtcExoAssessment -IncludeOnmicrosoftDomains
```

### Hybrid Identity

```powershell
$hybFindings = Invoke-TtcHybridAssessment

# Only check Graph-side (no AD module needed)
$hybFindings = Invoke-TtcHybridAssessment -SkipAdChecks
```

### Defender for Office 365

```powershell
$defFindings = Invoke-TtcDefenderAssessment
# Note: Uses same ExchangeOnline session — no separate connection needed
```

### Collaboration (SharePoint / Teams)

```powershell
# With custom thresholds
$collabFindings = Invoke-TtcCollabAssessment `
    -AnonymousLinkMaxExpirationDays 14 `  # Flag anon links > 14 days (default 30)
    -GuestLinkMaxExpirationDays     60    # Flag guest links > 60 days (default 90)
```

### MDE (Defender for Endpoint)

```powershell
# Requires: Connect-MgGraph -Scopes "SecurityEvents.Read.All","DeviceManagementManagedDevices.Read.All"
$mdeFindings = Invoke-TtcMdeAssessment
```

### PIM

```powershell
# Requires: Connect-MgGraph -Scopes "RoleManagement.Read.Directory","PrivilegedAccess.Read.AzureAD","Directory.Read.All"
# Requires: Entra ID P2 license
$pimFindings = Invoke-TtcPimAssessment
```

### AD Certificate Services

```powershell
# Run from a domain-joined machine with RSAT installed
$adcsFindings = Invoke-TtcAdcsAssessment

# Assess a specific domain
$adcsFindings = Invoke-TtcAdcsAssessment -Domain "child.contoso.com"
```

### Generating reports from individual assessor output

```powershell
# Run just one assessor
$adFindings = Invoke-TtcAdAssessment

# Calculate scores
$scores = Get-TtcAssessmentScore -Findings $adFindings

# Export CSV
$csv = Export-TtcCsvReport -Findings $adFindings -OutputPath "C:\Reports\AD_$(Get-Date -Format yyyyMMdd).csv"

# Export HTML
$html = Export-TtcHtmlReport `
    -Findings     $adFindings `
    -Scores       $scores `
    -OutputPath   "C:\Reports\AD_$(Get-Date -Format yyyyMMdd).html" `
    -ReportTitle  "Active Directory Assessment" `
    -CustomerName "Contoso" `
    -AssessedBy   "Bob"

Write-Host "CSV:  $csv"
Write-Host "HTML: $html"
```

---

## 7. Output Files — Reports, Logs, and CSVs

### Default file locations

| File Type | Default Path | Controlled By |
|-----------|-------------|---------------|
| CSV Report | `.\Reports\TtcAssessment_yyyyMMdd_HHmmss.csv` | `-OutputPath` parameter |
| HTML Report | `.\Reports\TtcAssessment_yyyyMMdd_HHmmss.html` | `-OutputPath` parameter |
| Log file | `.\TakeItToCloud.Assess\Logs\TtcAssess_yyyyMMdd.log` | `Set-TtcLogPath` or `Config.LogPath` |
| Config file | `.\TakeItToCloud.Assess\Config\DefaultConfig.json` | `-ConfigPath` parameter |
| Exclusion file | (user-defined) | `-ExcludeChecksFile` parameter |
| AutoFix script | (user-defined) | `-OutputPath` in `Invoke-TtcAutoFix` |
| Delta report | (user-defined) | `-OutputPath` in `Compare-TtcAssessment` |

### CSV report columns

```
Timestamp, FindingId, Workload, Component, CheckName, Category,
Severity, Status, RiskLevel, IssueDetected, Explanation,
PossibleSolution, Impact, Remediation, AutoFixAvailable, RemediationPriority,
FrameworkMapping, ZeroTrustPillar, SecureScoreMapping, MitreAttack,
DataSource, Notes
```

### HTML report features

- **Dark-themed** self-contained report (no CDN, no internet required)
- **Interactive filtering** by Severity, Status, Workload, and Category
- **Full-text search** across all fields
- **Score dials** for Overall, Security, Health, and Governance
- **Per-finding expandable detail** with Explanation, Remediation, MITRE ATT&CK mapping
- Opens in any browser; forward to stakeholders as a single `.html` file

### Changing the default output path

```powershell
# Via parameter
$result = Invoke-TtcAssessment -OutputPath "C:\CustomerReports\Contoso"

# Via config file (DefaultConfig.json)
# Set: "OutputPath": "C:\\CustomerReports\\Contoso"
```

### Log file format

Each line in the log file follows:
```
[2026-03-22 14:31:05] [a1b2c3d4] [Info] [Invoke-TtcAdAssessment] Starting Active Directory assessment
[2026-03-22 14:31:07] [a1b2c3d4] [Warning] [Invoke-TtcAdAssessment] Could not reach DC01: Connection refused
[2026-03-22 14:31:08] [a1b2c3d4] [Error] [Invoke-TtcExoAssessment] Check could not complete: Connect-ExchangeOnline required | Exception(InvalidOperationException): ...
```

Fields: `[timestamp] [sessionId] [level] [callerFunction] message | Exception(...): ...`

The **session ID** is an 8-character hex string generated at module import time. Every log entry from the same PowerShell session shares the same session ID, making it easy to correlate log entries when log files span multiple sessions.

---

## 8. Console Summary — Get-TtcFindingSummary

Prints a quick colour-coded summary without opening any files.

### Basic usage

```powershell
# After a full assessment
Get-TtcFindingSummary -Findings $result.Findings -Scores $result.Scores -CustomerName "Contoso"

# Pipeline style (from any assessor)
Invoke-TtcAdAssessment | Get-TtcFindingSummary

# Show only Critical findings in the top section
Get-TtcFindingSummary -Findings $result.Findings -TopFindingsSeverity Critical
```

### All parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Findings` | (required) | Array of finding objects (pipeline supported) |
| `-Scores` | (auto-calculated) | Pre-computed scores from `Get-TtcAssessmentScore` |
| `-CustomerName` | `''` | Customer name in the summary header |
| `-TopFindingsSeverity` | `High` | Minimum severity for top-findings list (`Critical`/`High`/`Medium`/`Low`/`Informational`) |
| `-TopFindingsCount` | `10` | Number of top findings to display (1-50) |
| `-PassThru` | off | Returns a PSCustomObject in addition to printing |
| `-OutputFormat` | `Console` | `Console` (coloured), `Markdown` (text), `JSON` (structured) |

### Export as Markdown (for reports/wikis)

```powershell
$md = Get-TtcFindingSummary -Findings $result.Findings -Scores $result.Scores `
    -CustomerName "Contoso" -OutputFormat Markdown

$md | Out-File "C:\Reports\summary.md" -Encoding UTF8
```

### Export as JSON (for automation/SIEM integration)

```powershell
$json = Get-TtcFindingSummary -Findings $result.Findings -OutputFormat JSON
$json | Out-File "C:\Reports\summary.json" -Encoding UTF8

# Or pipe to API endpoint
$json | Invoke-RestMethod -Uri "https://your-api/assessments" -Method Post -ContentType "application/json"
```

### PassThru — capture the summary object

```powershell
$summary = Get-TtcFindingSummary -Findings $result.Findings -PassThru

$summary.TotalFindings       # Total finding count
$summary.CriticalFailCount   # Critical severity failures
$summary.HighFailCount       # High severity failures
$summary.OverallScore        # 0-100
$summary.TopFindings         # Array of top priority findings
```

---

## 9. Delta / Trend Reporting — Compare-TtcAssessment

Compares two assessment CSV files to show what changed between runs. Use this to track remediation progress.

### Workflow

```powershell
# Run 1 — Baseline (save the CSV path)
$baseline = Invoke-TtcAssessment -CustomerName "Contoso" -OutputPath "C:\Reports\Contoso"
$baselineCsv = $baseline.CsvReport   # e.g. C:\Reports\Contoso\TtcAssessment_20260101_090000.csv

# ... customer performs remediations over several weeks ...

# Run 2 — Current
$current = Invoke-TtcAssessment -CustomerName "Contoso" -OutputPath "C:\Reports\Contoso"
$currentCsv = $current.CsvReport

# Compare
$delta = Compare-TtcAssessment -BaselinePath $baselineCsv -CurrentPath $currentCsv
```

### All parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-BaselinePath` | (required) | Path to older CSV file |
| `-CurrentPath` | (required) | Path to newer CSV file |
| `-OutputPath` | — | Optional CSV file to save the delta changes |
| `-OutputFormat` | `Console` | `Console` / `CSV` / `Markdown` / `JSON` |
| `-Workload` | All | Filter to a specific workload |

### Examples

```powershell
# Console output (default)
Compare-TtcAssessment -BaselinePath ".\jan-baseline.csv" -CurrentPath ".\mar-current.csv"

# Save delta as CSV
Compare-TtcAssessment -BaselinePath ".\jan-baseline.csv" -CurrentPath ".\mar-current.csv" `
    -OutputFormat CSV -OutputPath "C:\Reports\delta-q1.csv"

# Markdown for a progress report
$md = Compare-TtcAssessment -BaselinePath ".\jan-baseline.csv" -CurrentPath ".\mar-current.csv" `
    -OutputFormat Markdown
$md | Out-File ".\progress-report.md"

# JSON for automation
$deltaJson = Compare-TtcAssessment -BaselinePath ".\jan-baseline.csv" -CurrentPath ".\mar-current.csv" `
    -OutputFormat JSON

# Focus on only Active Directory changes
Compare-TtcAssessment -BaselinePath ".\jan.csv" -CurrentPath ".\mar.csv" -Workload ActiveDirectory
```

### Reading the delta result object

```powershell
$delta = Compare-TtcAssessment -BaselinePath ".\jan.csv" -CurrentPath ".\mar.csv"

$delta.DeltaSummary.NewFindings       # Count of newly appeared findings
$delta.DeltaSummary.ResolvedFindings  # Count of findings that disappeared
$delta.DeltaSummary.ImprovedFindings  # Count that moved from Fail -> Warning or Warning -> Pass
$delta.DeltaSummary.RegressedFindings # Count that moved from Pass/Warning -> Fail
$delta.DeltaSummary.DeltaCriticalFail # Change in Critical failures (+/- integer)
$delta.NewFindings                    # Array of new finding objects
$delta.ResolvedFindings               # Array of resolved finding objects
```

---

## 10. Remediation Script Generator — Invoke-TtcAutoFix

Generates a **reviewed, human-safe** PowerShell remediation script. It never auto-executes anything — the output file must be reviewed and run manually.

### Basic usage

```powershell
# Generate script for all fixable findings
Invoke-TtcAutoFix -Findings $result.Findings -OutputPath "C:\Remediation\contoso-fix.ps1"

# Open in VS Code for review
code "C:\Remediation\contoso-fix.ps1"
```

### All parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Findings` | (required) | Array of finding objects |
| `-OutputPath` | (required) | Path for the generated `.ps1` file |
| `-SeverityFilter` | `@('Critical','High')` | Only include findings at these severities |
| `-IncludeManualSteps` | `$true` | Include manual remediation steps as comments |
| `-WhatIf` | — | Preview what would be generated without writing the file |

### Examples

```powershell
# Only Critical and High findings
Invoke-TtcAutoFix -Findings $result.Findings -OutputPath ".\fix-crit-high.ps1" `
    -SeverityFilter @("Critical", "High")

# Include Medium findings too
Invoke-TtcAutoFix -Findings $result.Findings -OutputPath ".\fix-all.ps1" `
    -SeverityFilter @("Critical", "High", "Medium")

# AD findings only
$adFindings | Invoke-TtcAutoFix -OutputPath ".\fix-ad.ps1"

# Preview without writing
Invoke-TtcAutoFix -Findings $result.Findings -OutputPath ".\fix.ps1" -WhatIf
```

The generated script:
- Has a `ShouldProcess` guard for every finding (supports `-WhatIf` and `-Confirm`)
- Groups remediation steps by workload
- Includes `#requires` statements for needed modules
- Marks non-scriptable remediations as `# MANUAL:` comments
- Has a header with assessment metadata, generation date, and review instructions

---

## 11. Logging — Enhanced Logging System

### Log file location

```
TakeItToCloud.Assess\Logs\TtcAssess_yyyyMMdd.log
```

One file per calendar day. Each module import appends a session banner with timestamp, username, hostname, and PowerShell version.

### Enable real-time console INFO output

By default, Info-level messages go to the log file only (they are silent on the console unless you use `-Verbose`). To see all Info messages live:

```powershell
# Enable coloured console output for Info level
Enable-TtcConsoleLogging

# Run assessment — you will see [INFO] messages as they happen
$result = Invoke-TtcAssessment -CustomerName "Contoso"

# Disable when done
Disable-TtcConsoleLogging
```

### Using PowerShell -Verbose mode

```powershell
# Standard PowerShell Verbose mode (shows Write-Verbose output)
$result = Invoke-TtcAssessment -CustomerName "Contoso" -Verbose

# Verbose for a single assessor
$adFindings = Invoke-TtcAdAssessment -Verbose
```

### Changing the log directory

```powershell
# Redirect logs for this session
Set-TtcLogPath -Path "C:\CustomerLogs\Contoso"

# Check the current log path
Get-TtcLogPath

# Then run your assessment — logs go to the new path
$result = Invoke-TtcAssessment -CustomerName "Contoso"
```

### Reading the current log

```powershell
# Get current log path
$logPath = Get-TtcLogPath
$logFile = Join-Path $logPath "TtcAssess_$(Get-Date -Format 'yyyyMMdd').log"

# Tail the log (follow progress)
Get-Content $logFile -Wait

# See all errors from today's log
Get-Content $logFile | Where-Object { $_ -match '\[Error\]' }

# See all warnings
Get-Content $logFile | Where-Object { $_ -match '\[Warning\]' }

# Filter by session ID (to isolate one run)
$sessionId = "a1b2c3d4"  # from the session banner at top of log
Get-Content $logFile | Where-Object { $_ -match $sessionId }
```

### Log entry format

```
[2026-03-22 14:31:05] [a1b2c3d4] [Info] [Invoke-TtcAdAssessment] Starting AD assessment
[2026-03-22 14:31:08] [a1b2c3d4] [Warning] [Invoke-TtcExoAssessment] Connect-ExchangeOnline required
[2026-03-22 14:32:01] [a1b2c3d4] [Error] [Invoke-TtcEntraAssessment] ENT-SEC-006 failed | Exception(HttpRequestException): 401 Unauthorized
```

---

## 12. Configuration File — DefaultConfig.json

Located at: `TakeItToCloud.Assess\Config\DefaultConfig.json`

```json
{
    "AssessmentName": "TakeItToCloud Assessment",
    "Workloads": [
        "ActiveDirectory", "EntraID", "HybridIdentity",
        "ExchangeOnline", "Defender", "Collaboration",
        "MDE", "PIM", "ADCS"
    ],
    "ExcludeWorkloads": [],
    "ExcludeChecks": [],
    "SeverityFilter": ["Critical", "High", "Medium", "Low", "Informational"],
    "OutputPath": "./Reports",
    "LogPath": "./Logs",
    "GenerateCsv": true,
    "GenerateHtml": true,
    "EnvironmentMetadata": {
        "CustomerName": "",
        "AssessedBy": "TakeItToCloud",
        "EngagementId": ""
    }
}
```

### Using a custom config

```powershell
# Save a customer-specific config
$config = @{
    AssessmentName = "Contoso Q2 2026"
    Workloads = @("ActiveDirectory", "EntraID", "ExchangeOnline")
    ExcludeChecks = @("AD-CFG-002", "ENT-CFG-003")
    OutputPath = "C:\\Reports\\Contoso\\2026-Q2"
    GenerateCsv = $true
    GenerateHtml = $true
    EnvironmentMetadata = @{
        CustomerName = "Contoso Ltd"
        AssessedBy = "Alice Smith"
        EngagementId = "ENG-2026-042"
    }
} | ConvertTo-Json -Depth 3

$config | Out-File "C:\Configs\contoso-config.json" -Encoding UTF8

# Use it
$result = Invoke-TtcAssessment -ConfigPath "C:\Configs\contoso-config.json"
```

---

## 13. Excluding Checks

### Method 1 — Inline parameter

```powershell
$result = Invoke-TtcAssessment -ExcludeChecks @("AD-CFG-002", "ENT-CFG-003", "EXO-CFG-001")
```

### Method 2 — Exclusion file (recommended for repeatable runs)

Create a text file with one FindingId per line. Lines starting with `#` are comments.

```text
# suppressions.txt
# Approved suppressions for Contoso - reviewed 2026-03-22

# AD Recycle Bin - not available on this DFL, risk accepted
AD-CFG-004

# SSPR not licensed (F1 only) - out of scope
ENT-CFG-003

# SPO external sharing - contractual requirement
COL-SEC-001
```

```powershell
$result = Invoke-TtcAssessment -ExcludeChecksFile "C:\Assessments\Contoso\suppressions.txt"
```

### Method 3 — Config file

Add to `DefaultConfig.json`:
```json
"ExcludeChecks": ["AD-CFG-002", "ENT-CFG-003"]
```

**Priority order**: `-ExcludeChecks` parameter > `-ExcludeChecksFile` > Config file.

---

## 14. Scoring Engine

Scores are calculated by `Get-TtcAssessmentScore` automatically during `Invoke-TtcAssessment`.

### Formula

```
Security Score    = 100 - (sum of weighted penalty points for Security category)
Health Score      = 100 - (sum of weighted penalty points for Health category)
Governance Score  = 100 - (sum of weighted penalty points for Governance category)
Overall Score     = (Security * 0.50) + (Health * 0.30) + (Governance * 0.20)
```

### Penalty weights

| Severity | Status=Fail | Status=Warning |
|----------|-------------|----------------|
| Critical | 10 pts | 5 pts |
| High | 7 pts | 3.5 pts |
| Medium | 4 pts | 2 pts |
| Low | 1 pt | 0.5 pt |
| Informational | 0 pts | 0 pts |

Pass, Error, and NotAssessed findings do not deduct points.

### Using the scoring engine directly

```powershell
# Score any array of findings
$scores = Get-TtcAssessmentScore -Findings $adFindings

$scores.OverallScore      # 0-100
$scores.SecurityScore     # 0-100
$scores.HealthScore       # 0-100
$scores.GovernanceScore   # 0-100
$scores.WorkloadScores    # Array with per-workload breakdown

# Per-workload breakdown
$scores.WorkloadScores | Format-Table Workload, OverallScore, FailCount, WarningCount, PassCount
```

---

## 15. All Assessors — Complete Check Reference

### Active Directory (19 checks)

| FindingId | CheckName | Severity | MITRE |
|-----------|-----------|----------|-------|
| AD-HLT-001 | Domain Controller Replication Health | High | |
| AD-HLT-002 | Domain Controller Redundancy | Critical | |
| AD-HLT-003 | Domain Controller OS Version | High | |
| AD-HLT-004 | FSMO Role Holder Accessibility | Critical | |
| AD-SEC-001 | Stale Privileged Group Members | Critical/High | |
| AD-SEC-002 | Default Administrator Account Hygiene | High | |
| AD-SEC-003 | Unconstrained Kerberos Delegation | Critical | T1550.003 |
| AD-SEC-004 | Krbtgt Account Password Age | Critical/High | T1558.001 |
| AD-SEC-005 | Protected Users Security Group Coverage | Medium | |
| AD-SEC-006 | Kerberoastable User Accounts | High | T1558.003 |
| AD-SEC-007 | AS-REP Roastable Accounts | Critical | T1558.004 |
| AD-SEC-008 | Unauthorized DCSync Rights | Critical | T1003.006 |
| AD-SEC-009 | AdminSDHolder Rogue ACEs | Critical | T1484.001 |
| AD-CFG-001 | Default Domain Password Policy | High/Medium | |
| AD-CFG-002 | Fine-Grained Password Policies | Medium | |
| AD-CFG-003 | Machine Account Quota (ms-DS-MachineAccountQuota) | High | T1078.002 |
| AD-CFG-004 | AD Recycle Bin Status | Medium | |
| AD-CFG-005 | Domain/Forest Functional Level | Medium | |
| AD-MON-001 | Advanced Audit Policy Configuration | Medium | |

**Prerequisites:** Domain-joined machine with RSAT-AD-PowerShell. Runs as current user.

### Entra ID (16 checks)

| FindingId | CheckName | Severity |
|-----------|-----------|----------|
| ENT-SEC-001 | MFA Registration Coverage | Critical/High |
| ENT-SEC-002 | Legacy Authentication Blocked | High |
| ENT-SEC-003 | Global Administrator Count | Critical/High |
| ENT-SEC-004 | Risky Users Not Remediated | Critical/High |
| ENT-SEC-005 | Conditional Access Baseline Coverage | Critical/Medium |
| ENT-SEC-006 | Workload Identity Credential Expiry | High/Medium |
| ENT-SEC-007 | Over-Privileged Enterprise Applications | High |
| ENT-SEC-008 | Privileged Identity Management Adoption | High/Medium |
| ENT-SEC-009 | FIDO2/Passwordless Authentication Enablement | Medium |
| ENT-SEC-010 | Emergency Access Account Validation | High |
| ENT-CFG-001 | User Application Consent Policy | High/Medium |
| ENT-CFG-002 | External Collaboration Settings | High/Medium |
| ENT-CFG-003 | Self-Service Password Reset Configuration | Medium |
| ENT-CFG-004 | Cross-Tenant Access Settings | Medium |
| ENT-IDN-001 | Stale Guest User Accounts | High/Medium |
| ENT-MON-001 | Entra ID Audit and Sign-in Log Accessibility | Medium |

**Prerequisites:** `Connect-MgGraph` with User.Read.All, Policy.Read.All, Directory.Read.All, IdentityRiskyUser.Read.All, AuditLog.Read.All, Organization.Read.All, Reports.Read.All, UserAuthenticationMethod.Read.All, Application.Read.All

### Exchange Online (14 checks)

| FindingId | CheckName | Severity | MITRE |
|-----------|-----------|----------|-------|
| EXO-MON-001 | Mailbox Audit Logging | Medium | |
| EXO-MON-002 | Unified Audit Log Status | High | |
| EXO-SEC-001 | Modern Authentication Status | High | |
| EXO-SEC-002 | Anti-Malware Policy Configuration | High | |
| EXO-SEC-003 | DKIM Signing Configuration | High | |
| EXO-SEC-004 | Inbox Rules Forwarding to External Recipients | High | T1114.003 |
| EXO-SEC-005 | Transport Rules Bypassing Spam Filtering (SCL=-1) | High | T1566.001 |
| EXO-SEC-006 | Mailbox Full Access Delegation | Medium | T1114.002 |
| EXO-CFG-001 | SPF and DMARC Record Configuration | High | |
| EXO-CFG-002 | Automatic External Email Forwarding | High | |
| EXO-CFG-003 | Connector TLS Enforcement | Medium | |
| EXO-CFG-004 | Anti-Spam Outbound Notification | Medium | |
| EXO-CFG-005 | Exchange Web Services Access Policy | Medium | |
| EXO-GOV-001 | Exchange Admin Role Hygiene | High | |

**Prerequisites:** `Connect-ExchangeOnline`

### Defender for Office 365 (8 checks)

| FindingId | CheckName | Severity |
|-----------|-----------|----------|
| DEF-SEC-001 | Safe Links Policy Coverage | High |
| DEF-SEC-002 | Safe Attachments Policy Coverage | High |
| DEF-SEC-003 | Anti-Phishing Policy Configuration | High |
| DEF-CFG-001 | Preset Security Policy Adoption | Medium |
| DEF-CFG-002 | Zero-Hour Auto Purge Configuration | Medium |
| DEF-CFG-003 | Defender for Office 365 SPO/Teams/ODB Protection | High |
| DEF-MON-001 | High-Severity Alert Policy Notification | Medium |
| DEF-MON-002 | Compromised Account Alert Policies | Medium |

**Prerequisites:** Same `Connect-ExchangeOnline` session as EXO. Defender P1+ license for DEF-SEC-001/002/003.

### Hybrid Identity (8 checks)

| FindingId | CheckName | Severity |
|-----------|-----------|----------|
| HYB-HLT-001 | Directory Sync Status | Critical/High |
| HYB-HLT-002 | Password Hash Sync Currency | High/Medium |
| HYB-HLT-003 | Directory Synchronization Errors | Medium |
| HYB-CFG-001 | Password Hash Sync Configuration | High |
| HYB-CFG-002 | Authentication Mode Assessment | Medium |
| HYB-CFG-003 | Entra Connect Service Account Privileges | Critical/Medium |
| HYB-SEC-001 | On-Premises Admin Accounts Synced to Cloud | High |
| HYB-SEC-002 | Break-Glass Accounts Are Cloud-Only | High |

**Prerequisites:** `Connect-MgGraph`. AD module recommended but not required.

### Collaboration / SharePoint / Teams (8 checks)

| FindingId | CheckName | Severity |
|-----------|-----------|----------|
| COL-SEC-001 | SharePoint and OneDrive External Sharing Level | High |
| COL-SEC-002 | Anonymous Link Expiration Policy | High |
| COL-SEC-003 | External Guest Link Expiration Policy | Medium |
| COL-SEC-004 | Default Sharing Link Scope | Medium |
| COL-GOV-001 | Microsoft 365 Groups Guest Access Policy | Medium |
| COL-GOV-002 | Sensitivity Labels Published to Users | Medium |
| COL-GOV-003 | Microsoft Purview Retention Policy Coverage | Medium |
| COL-GOV-004 | Teams External and Guest Access Configuration | Medium |

**Prerequisites:** `Connect-MgGraph` with SharePointTenantSettings.Read.All. Optional: `Connect-SPOService`, `Connect-IPPSSession`, `Connect-MicrosoftTeams`.

### MDE (6 checks)

| FindingId | CheckName | Severity | MITRE |
|-----------|-----------|----------|-------|
| MDE-CFG-001 | MDE Device Onboarding Coverage | High | |
| MDE-CFG-002 | Device Compliance Policy Coverage | High | |
| MDE-CFG-003 | Non-Compliant Device Count | Medium | |
| MDE-SEC-001 | Secure Score - Device Controls | High/Medium | |
| MDE-SEC-002 | Unresolved High-Severity Security Alerts | Critical/High | T1562 |
| MDE-MON-001 | Defender Device Security Improvement Actions | Medium | |

**Prerequisites:** `Connect-MgGraph -Scopes "SecurityEvents.Read.All","DeviceManagementManagedDevices.Read.All"`

### PIM (4 checks)

| FindingId | CheckName | Severity | MITRE |
|-----------|-----------|----------|-------|
| PIM-CFG-001 | PIM Activation Policy Configuration | High | T1078.004 |
| PIM-SEC-001 | Stale PIM Eligible Assignments | Medium | |
| PIM-SEC-002 | Standing Privileged Role Assignments | High | T1078.004 |
| PIM-GOV-001 | Access Reviews for Privileged Roles | Medium | |

**Prerequisites:** `Connect-MgGraph -Scopes "RoleManagement.Read.Directory","PrivilegedAccess.Read.AzureAD","Directory.Read.All"` + Entra ID P2 license.

### AD Certificate Services (5 checks)

| FindingId | CheckName | Severity | ESC Class | MITRE |
|-----------|-----------|----------|-----------|-------|
| ADCS-SEC-001 | ESC1 - Enrollee Supplies Subject SAN | Critical | ESC1 | T1649 |
| ADCS-SEC-002 | ESC2 - Any Purpose or No EKU Templates | High | ESC2 | T1649 |
| ADCS-SEC-003 | ESC3 - Certificate Request Agent Templates | High | ESC3 | T1649 |
| ADCS-SEC-004 | ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 CA Flag | Critical | ESC6 | T1649 |
| ADCS-SEC-005 | ESC8 - HTTP Certificate Web Enrollment Endpoint | Critical | ESC8 | T1187 |

**Prerequisites:** Domain-joined machine. `Import-Module ActiveDirectory`. `certutil` must be in `$env:PATH`. Run as domain user with read access to PKI containers.

---

## 16. Advanced Usage & Automation

### Scheduled / unattended assessment

For fully automated execution (no interactive browser consent), use app registration with certificate-based auth:

```powershell
# Create app registration in Entra with:
# - Application permissions (not delegated): see scope list above
# - A self-signed certificate uploaded

$appId     = "your-app-registration-client-id"
$tenantId  = "your-tenant-id"
$certThumb = "your-certificate-thumbprint"

# Connect Graph with certificate
Connect-MgGraph -ClientId $appId -TenantId $tenantId -CertificateThumbprint $certThumb

# Connect Exchange with certificate
Connect-ExchangeOnline -AppId $appId -Organization contoso.onmicrosoft.com `
    -CertificateThumbprint $certThumb

# Run assessment
$result = Invoke-TtcAssessment -CustomerName "Contoso" -OutputPath "D:\Reports"
```

### Running Pester tests

```powershell
# Install Pester 5.x
Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck

# Run all tests
Invoke-Pester -Path ".\TakeItToCloud.Assess\Tests\" -Output Detailed

# Engine tests only
Invoke-Pester -Path ".\TakeItToCloud.Assess\Tests\TtcEngine.Tests.ps1" -Output Detailed

# Reports tests only
Invoke-Pester -Path ".\TakeItToCloud.Assess\Tests\TtcReports.Tests.ps1" -Output Detailed

# With code coverage
Invoke-Pester -Path ".\TakeItToCloud.Assess\Tests\" `
    -CodeCoverage ".\TakeItToCloud.Assess\Public\*.ps1" -Output Detailed
```

### Multi-tenant assessment loop

```powershell
$tenants = @(
    @{ Name = "Contoso"; TenantId = "aaa-bbb"; AppId = "ccc"; Thumb = "DDD" },
    @{ Name = "Fabrikam"; TenantId = "eee-fff"; AppId = "ggg"; Thumb = "HHH" }
)

foreach ($t in $tenants) {
    Write-Host "=== Assessing $($t.Name) ===" -ForegroundColor Cyan

    Connect-MgGraph -ClientId $t.AppId -TenantId $t.TenantId -CertificateThumbprint $t.Thumb
    Connect-ExchangeOnline -AppId $t.AppId -Organization "$($t.Name.ToLower()).onmicrosoft.com" `
        -CertificateThumbprint $t.Thumb

    $result = Invoke-TtcAssessment `
        -CustomerName $t.Name `
        -OutputPath   "C:\Reports\$($t.Name)" `
        -Workloads    @("EntraID", "ExchangeOnline", "Defender")

    Write-Host "$($t.Name): Overall Score = $($result.Scores.OverallScore)" -ForegroundColor Yellow

    Disconnect-MgGraph
    Disconnect-ExchangeOnline -Confirm:$false
}
```

### Exporting findings to JSON for integration

```powershell
$result = Invoke-TtcAssessment -CustomerName "Contoso"

# Export all findings as JSON
$result.Findings | ConvertTo-Json -Depth 3 | Out-File ".\findings.json" -Encoding UTF8

# Export only failures
$result.Findings | Where-Object { $_.Status -eq 'Fail' } |
    ConvertTo-Json -Depth 3 | Out-File ".\failures.json" -Encoding UTF8

# Push to a webhook/SIEM
$body = @{
    customer = "Contoso"
    date     = (Get-Date -Format 'o')
    score    = $result.Scores.OverallScore
    findings = $result.Findings | Where-Object { $_.Status -eq 'Fail' } |
               Select-Object FindingId, Severity, CheckName, IssueDetected
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Uri "https://your-siem/api/assessments" -Method Post `
    -Body $body -ContentType "application/json"
```

---

## 17. Troubleshooting

### "Invoke-TtcAssessment is not recognized"

```powershell
# Step 1: Unblock all files (must be done before Import-Module)
Get-ChildItem ".\TakeItToCloud.Assess" -Recurse -Filter "*.ps1" | Unblock-File
Get-ChildItem ".\TakeItToCloud.Assess" -Recurse -Filter "*.psd1" | Unblock-File

# Step 2: Force reload the module
Import-Module .\TakeItToCloud.Assess\TakeItToCloud.Assess.psd1 -Force

# Verify
Get-Command Invoke-TtcAssessment
```

### "Parse error at line X" / module fails to load

Usually caused by Unicode punctuation in `.ps1` files (em dashes, curly quotes) being misread by PowerShell 5.1 as Windows-1252.

```powershell
# Check which files have problematic characters
$files = Get-ChildItem ".\TakeItToCloud.Assess" -Recurse -Filter "*.ps1"
foreach ($f in $files) {
    $content = [System.IO.File]::ReadAllBytes($f.FullName)
    # Look for 0x94 (right double quote in Win-1252 = part of UTF-8 em dash E2 80 94)
    if ($content -contains 0x94 -or $content -contains 0x93) {
        Write-Warning "Encoding issue in: $($f.FullName)"
    }
}
```

Fix: re-save the affected file in UTF-8 without BOM using VS Code (`Save with Encoding > UTF-8`).

### "Cannot connect to Exchange Online"

```powershell
# Verify the module is installed
Get-Module ExchangeOnlineManagement -ListAvailable

# Install if missing
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force

# Connect with explicit UPN
Connect-ExchangeOnline -UserPrincipalName youradmin@contoso.com

# Verify
Get-OrganizationConfig | Select-Object Name
```

### "Microsoft.Graph module not loaded"

```powershell
# Check what Graph modules are available
Get-Module -Name "Microsoft.Graph*" -ListAvailable | Select-Object Name, Version

# Install the full SDK
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Or check if already connected
Get-MgContext
```

### Assessment completes but scores are all 0

```powershell
# Check if any findings were actually collected
$result.Findings.Count

# Check for Error status findings (e.g., prereq failures)
$result.Findings | Where-Object { $_.Status -eq 'Error' } |
    Select-Object FindingId, Workload, IssueDetected | Format-Table -AutoSize
```

### Checking the log for errors after a run

```powershell
$logPath = Get-TtcLogPath
$today   = Get-Date -Format 'yyyyMMdd'
$logFile = Join-Path $logPath "TtcAssess_$today.log"

# Show all errors and warnings
Get-Content $logFile | Where-Object { $_ -match '\[(Error|Warning)\]' }
```

---

*Generated by TakeItToCloud.Assess v1.1.0 — github.com/TakeItoCloud/TakeItToCloud.Assess*
