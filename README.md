# TakeItToCloud.Assess

> **Production-grade PowerShell assessment framework for Microsoft 365, Hybrid Identity, and on-premises infrastructure**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://github.com/PowerShell/PowerShell)
[![Module Version](https://img.shields.io/badge/version-1.1.0-green)](./TakeItToCloud.Assess/TakeItToCloud.Assess.psd1)
[![Workloads](https://img.shields.io/badge/workloads-9-orange)](./HOWTO.md#15-all-assessors--complete-check-reference)
[![Checks](https://img.shields.io/badge/security%20checks-97-red)](./HOWTO.md#15-all-assessors--complete-check-reference)

---

## What It Does

TakeItToCloud.Assess runs automated security, health, and governance assessments across **9 workloads** with **97 security checks**, then generates interactive HTML reports, CSV exports, and console summaries — in a single command.

```powershell
$result = Invoke-TtcAssessment -CustomerName "Contoso" -AssessedBy "Alice"
```

That's it. Reports are auto-generated in `.\Reports\`.

---

## Workloads Covered

| Workload | Checks | Key Areas |
|----------|--------|-----------|
| **Active Directory** | 19 | Kerberoasting, DCSync, AdminSDHolder, AS-REP, unconstrained delegation, password policy, replication |
| **Entra ID** | 16 | MFA coverage, Conditional Access, PIM adoption, FIDO2, app over-privilege, break-glass accounts |
| **Exchange Online** | 14 | DKIM/DMARC/SPF, inbox forwarding rules, SCL bypass, EWS access, mailbox delegation |
| **Hybrid Identity** | 8 | Entra Connect sync health, PHS, cloud-only sync errors, service account privileges |
| **Defender for Office 365** | 8 | Safe Links, Safe Attachments, anti-phishing, ZAP, alert policies |
| **Collaboration** | 8 | SharePoint external sharing, anonymous links, sensitivity labels, retention policies, Teams guest access |
| **Microsoft Defender for Endpoint** | 6 | Device onboarding, Secure Score, open alerts, compliance policies |
| **Privileged Identity Management** | 4 | PIM activation policy, standing access, stale eligible assignments, access reviews |
| **AD Certificate Services** | 5 | ESC1/2/3/6/8 vulnerability classes (Certified Pre-Owned attack vectors) |

---

## Quick Start

### 1. Unblock and import

```powershell
# Unblock files (required after download)
Get-ChildItem ".\TakeItToCloud.Assess" -Recurse -Filter "*.ps1" | Unblock-File
Get-ChildItem ".\TakeItToCloud.Assess" -Recurse -Filter "*.psd1" | Unblock-File

# Import the module
Import-Module .\TakeItToCloud.Assess\TakeItToCloud.Assess.psd1 -Force
```

### 2. Install required modules

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module Microsoft.Graph          -Scope CurrentUser -Force
# RSAT AD tools: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

### 3. Connect to services

```powershell
# Exchange Online + Defender
Connect-ExchangeOnline -UserPrincipalName admin@contoso.com

# Entra ID, Hybrid, MDE, PIM
Connect-MgGraph -Scopes "User.Read.All","Policy.Read.All","Directory.Read.All",
    "IdentityRiskyUser.Read.All","AuditLog.Read.All","Organization.Read.All",
    "Reports.Read.All","UserAuthenticationMethod.Read.All",
    "SecurityEvents.Read.All","DeviceManagementManagedDevices.Read.All",
    "RoleManagement.Read.Directory","Application.Read.All"
```

### 4. Run the assessment

```powershell
$result = Invoke-TtcAssessment -CustomerName "Contoso" -AssessedBy "Alice"

# Quick console summary
Get-TtcFindingSummary -Findings $result.Findings -Scores $result.Scores -CustomerName "Contoso"

# Open the HTML report
Invoke-Item $result.HtmlReport
```

---

## Common Commands

```powershell
# Full assessment — all workloads
Invoke-TtcAssessment -CustomerName "Contoso" -AssessedBy "Alice"

# Selected workloads only
Invoke-TtcAssessment -Workloads @("ActiveDirectory","EntraID","PIM","ADCS") -CustomerName "Contoso"

# Skip a workload (e.g., no AD CS in the environment)
Invoke-TtcAssessment -ExcludeWorkloads @("ADCS","MDE") -CustomerName "Contoso"

# Suppress specific checks
Invoke-TtcAssessment -ExcludeChecks @("AD-CFG-002","ENT-CFG-003") -CustomerName "Contoso"

# Suppress checks via file (supports # comments)
Invoke-TtcAssessment -ExcludeChecksFile ".\suppressions.txt" -CustomerName "Contoso"

# Enable verbose progress logging to console
Enable-TtcConsoleLogging
$result = Invoke-TtcAssessment -CustomerName "Contoso"

# Delta report — track remediation progress between runs
Compare-TtcAssessment -BaselinePath ".\jan-assessment.csv" -CurrentPath ".\mar-assessment.csv"

# Generate remediation script
Invoke-TtcAutoFix -Findings $result.Findings -OutputPath ".\remediation.ps1"

# Export summary as Markdown
Get-TtcFindingSummary -Findings $result.Findings -OutputFormat Markdown | Out-File ".\summary.md"

# Change log directory
Set-TtcLogPath -Path "C:\Logs\Assessments"
```

---

## Output Files

| File | Location | Description |
|------|----------|-------------|
| **HTML Report** | `.\Reports\TtcAssessment_*.html` | Interactive dark-themed report with filtering, search, score dials, and full remediation guidance. Single self-contained file — no internet required. |
| **CSV Export** | `.\Reports\TtcAssessment_*.csv` | All 22 finding fields. UTF-8 BOM for Excel compatibility. Feed into Power BI, SIEM, or ticketing systems. |
| **Log File** | `.\TakeItToCloud.Assess\Logs\TtcAssess_yyyyMMdd.log` | Structured daily log with session ID, timestamps, caller function, and exception details. |
| **AutoFix Script** | (user-defined path) | Human-reviewed remediation `.ps1` with ShouldProcess guards. Never auto-executes. |
| **Delta Report** | (user-defined path) | CSV/Markdown/JSON showing new, resolved, improved, and regressed findings between two runs. |

---

## Scoring

Findings are scored across three domains:

| Domain | Weight | What It Measures |
|--------|--------|-----------------|
| Security | 50% | Vulnerability exposure, attack surface |
| Health | 30% | Configuration correctness, service availability |
| Governance | 20% | Policy, compliance, access reviews |

**Overall Score = Security×0.50 + Health×0.30 + Governance×0.20**

Penalty weights: Critical=10, High=7, Medium=4, Low=1 (Fail = full weight, Warning = 50%).

---

## Logging

Every log entry includes: `[timestamp] [sessionId] [level] [callerFunction] message`

```powershell
Enable-TtcConsoleLogging      # Show Info messages on console (not just in log file)
Disable-TtcConsoleLogging     # Quiet mode (default)
Set-TtcLogPath -Path "C:\Logs"  # Override log directory
Get-TtcLogPath                # Show current log directory

# Read today's log
Get-Content (Join-Path (Get-TtcLogPath) "TtcAssess_$(Get-Date -Format 'yyyyMMdd').log")

# Filter for errors
Get-Content ... | Where-Object { $_ -match '\[Error\]' }
```

---

## MITRE ATT&CK Mapping

All findings include a `MitreAttack` field with technique IDs where applicable:

| Technique | Checks |
|-----------|--------|
| T1558.003 Kerberoasting | AD-SEC-006 |
| T1558.004 AS-REP Roasting | AD-SEC-007 |
| T1003.006 DCSync | AD-SEC-008 |
| T1484.001 AdminSDHolder | AD-SEC-009 |
| T1649 Steal/Forge Certificates | ADCS-SEC-001 through ADCS-SEC-005 |
| T1114.003 Email Forwarding Rules | EXO-SEC-004 |
| T1078.004 Valid Cloud Accounts | PIM-CFG-001, PIM-SEC-002 |
| T1528 Steal App Access Token | ENT-SEC-006 |
| T1098.002 Additional Email Delegate Permissions | ENT-SEC-007 |

---

## Framework Alignment

Each finding maps to at least one compliance/security framework:

- **NIST CSF** (Identify, Protect, Detect, Respond, Recover)
- **CIS Controls** (Access Control, Endpoint Protection, Data Protection, etc.)
- **ISO 27001** (A.9, A.12, A.15, etc.)
- **Zero Trust Pillars** (Identity, Devices, Applications, Data, Infrastructure)
- **Microsoft Secure Score** (SecureScoreMapping field)

---

## Project Structure

```
Assessments/
|-- TakeItToCloud.Assess/      # Module (import this)
|-- ProjectDocs/               # Architecture and phase documentation
|-- HOWTO.md                   # Full end-to-end usage guide
|-- README.md                  # This file
```

**See [HOWTO.md](./HOWTO.md) for the complete usage guide** — covering all parameters, examples, automation patterns, troubleshooting, and a full check reference for all 9 workloads.

---

## Requirements

| Requirement | Details |
|-------------|---------|
| PowerShell | 5.1 or higher (Windows) |
| OS | Windows 10/11 or Windows Server 2016+ |
| Machine | Domain-joined recommended for AD/ADCS assessments |
| Modules | ExchangeOnlineManagement, Microsoft.Graph (per workload) |
| License | Entra ID P2 for PIM assessor; Defender P1+ for some Defender checks |

---

*TakeItToCloud.Assess v1.1.0 — Built for Microsoft 365 security practitioners*
