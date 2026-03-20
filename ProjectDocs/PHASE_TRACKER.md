# TakeItToCloud.Assess — Phase Tracker

> **Purpose**: This file tracks what has been built, what's next, and key decisions.
> Updated at the end of every development session.
> Every new Claude conversation reads this to know the current state.

---

## Completed Phases

### Phase 1+2 — Core Engine + Reporting (Completed 2026-03-20)

**Files Created:**

| File | Purpose |
|------|---------|
| `TakeItToCloud.Assess.psd1` | Module manifest |
| `TakeItToCloud.Assess.psm1` | Root module loader (dot-sources Public/ and Private/) |
| `Public/Invoke-TtcAssessment.ps1` | Main orchestrator — runs selected workload assessors |
| `Public/Export-TtcCsvReport.ps1` | CSV export with UTF-8 BOM |
| `Public/Export-TtcHtmlReport.ps1` | Self-contained HTML report with filtering/search |
| `Public/Get-TtcAssessmentScore.ps1` | Scoring engine (Health/Security/Governance/Overall) |
| `Public/New-TtcFindingObject.ps1` | Public finding constructor with validation |
| `Private/New-TtcFinding.ps1` | Internal finding factory (quick creation) |
| `Private/Write-TtcLog.ps1` | Logging engine (console + file) |
| `Private/Get-TtcRulePack.ps1` | JSON rule file loader |
| `Private/Resolve-TtcFrameworkMapping.ps1` | Framework mapping resolver |
| `Private/Get-TtcSeverityWeight.ps1` | Severity weight lookup |
| `Private/Get-TtcHtmlTemplate.ps1` | HTML report template generator |
| `Private/Test-TtcPrerequisite.ps1` | Module prerequisite checker |
| `Config/DefaultConfig.json` | Default assessment configuration |
| `Rules/AD.Rules.json` | AD rule pack (placeholder — upgraded in Phase 3) |
| `Rules/EntraID.Rules.json` | Entra ID rule pack (placeholder — upgraded in Phase 3) |

**Key Decisions Made:**
- Finding object: 21 properties (see PROJECT_SPEC.md §3)
- Scoring weights: Critical=10, High=7, Medium=4, Low=1, Info=0
- Overall score formula: Security 50% + Health 30% + Governance 20%
- Warning findings count at 50% weight in scoring
- HTML report: dark navy (#0f172a) + security green (#10b981) brand theme
- HTML report: inline JS for filtering/search, no CDN dependencies
- CSV: UTF-8 with BOM for Excel compatibility
- Module loader dot-sources all .ps1 files in Public/ and Private/ folders
- Assessor functions are also dot-sourced from Assessors/ subdirectories
- Each assessor returns an array of finding objects

---

### Phase 3 — Active Directory + Entra ID + Hybrid Identity Assessors (Completed 2026-03-20)

**Files Created:**

| File | Purpose |
|------|---------|
| `Assessors/ActiveDirectory/Invoke-TtcAdAssessment.ps1` | Full AD assessor — 12 checks |
| `Assessors/EntraID/Invoke-TtcEntraAssessment.ps1` | Full Entra ID assessor — 9 checks |
| `Assessors/HybridIdentity/Invoke-TtcHybridAssessment.ps1` | Full Hybrid assessor — 8 checks |
| `Rules/AD.Rules.json` | Full rule definitions (upgraded from placeholder, v2.0.0) |
| `Rules/EntraID.Rules.json` | Full rule definitions (upgraded from placeholder, v2.0.0) |
| `Rules/HybridIdentity.Rules.json` | Full rule definitions (upgraded from placeholder, v2.0.0) |

**AD Assessor Checks (Invoke-TtcAdAssessment):**
| FindingId | CheckName | Severity |
|-----------|-----------|----------|
| AD-HLT-001 | Domain Controller Replication Health | High |
| AD-HLT-002 | Domain Controller Redundancy | Critical |
| AD-HLT-003 | Domain Controller OS Version | High |
| AD-HLT-004 | FSMO Role Holder Accessibility | Critical |
| AD-SEC-001 | Stale Privileged Group Members | High/Critical |
| AD-SEC-002 | Default Administrator Account Hygiene | High |
| AD-SEC-003 | Unconstrained Kerberos Delegation | Critical |
| AD-SEC-004 | Krbtgt Account Password Age | High/Critical |
| AD-SEC-005 | Protected Users Security Group Coverage | Medium |
| AD-CFG-001 | Default Domain Password Policy | Medium/High |
| AD-CFG-002 | Fine-Grained Password Policies | Medium |
| AD-MON-001 | Advanced Audit Policy Configuration | Medium |

**Entra ID Assessor Checks (Invoke-TtcEntraAssessment):**
| FindingId | CheckName | Severity |
|-----------|-----------|----------|
| ENT-SEC-001 | MFA Registration Coverage | Critical/High |
| ENT-SEC-002 | Legacy Authentication Blocked | High |
| ENT-SEC-003 | Global Administrator Count | Critical/High |
| ENT-SEC-004 | Risky Users Not Remediated | Critical/High |
| ENT-SEC-005 | Conditional Access Baseline Coverage | Critical/Medium |
| ENT-CFG-001 | User Application Consent Policy | High |
| ENT-CFG-002 | External Collaboration Settings | High/Medium |
| ENT-CFG-003 | Self-Service Password Reset Configuration | Medium |
| ENT-IDN-001 | Stale Guest User Accounts | High/Medium |
| ENT-MON-001 | Entra ID Audit and Sign-in Log Accessibility | Medium |

**Hybrid Identity Assessor Checks (Invoke-TtcHybridAssessment):**
| FindingId | CheckName | Severity |
|-----------|-----------|----------|
| HYB-HLT-001 | Directory Sync Status | High/Critical |
| HYB-HLT-002 | Password Hash Sync Currency | Medium/High |
| HYB-HLT-003 | Directory Synchronization Errors | Medium |
| HYB-CFG-001 | Password Hash Sync Configuration | High |
| HYB-CFG-002 | Authentication Mode Assessment | Medium |
| HYB-CFG-003 | Entra Connect Service Account Privileges | Critical/Medium |
| HYB-SEC-001 | On-Premises Admin Accounts Synced to Cloud | High |
| HYB-SEC-002 | Break-Glass Accounts Are Cloud-Only | High |

**Key Decisions Made:**
- AD assessor uses RSAT ActiveDirectory module; gracefully returns Error findings if module unavailable
- Entra assessor uses Microsoft.Graph SDK; falls back to per-user method query if reporting API unavailable
- Hybrid assessor supports partial execution — runs cloud-side checks even if AD module unavailable, and vice versa
- All assessors follow try/catch-per-check pattern: one check failure never prevents subsequent checks from running
- `Join-String` (PS 6.2+) avoided throughout — `($array -join '; ')` used for PS 5.1 compatibility
- FSMO accessibility test uses `Test-NetConnection -Port 389` (LDAP) rather than ICMP ping for reliability
- MFA assessment: primary path uses `Get-MgReportAuthenticationMethodUserRegistrationDetail`; falls back to per-user method query with 50-user sample if reports API unavailable
- Hybrid assessor detects cloud-only tenants (OnPremisesSyncEnabled=false) and returns NotAssessed rather than false positives
- krbtgt and Administrator RID-500 lookups use SID-based identity resolution for rename-resilience

**Required Prerequisites:**
- AD assessor: `Import-Module ActiveDirectory` (RSAT-AD-PowerShell)
- Entra/Hybrid assessors: `Connect-MgGraph` with scopes listed in function help
- Hybrid assessor: both Graph + AD module recommended; partially functions with either alone

---

### Phase 4 — Exchange Online + Defender Assessors (Completed 2026-03-20)

**Files Created:**

| File | Purpose |
|------|---------|
| `Assessors/ExchangeOnline/Invoke-TtcExoAssessment.ps1` | Full EXO assessor — 10 checks |
| `Assessors/Defender/Invoke-TtcDefenderAssessment.ps1` | Full Defender for Office 365 assessor — 8 checks |
| `Rules/ExchangeOnline.Rules.json` | Full rule definitions (upgraded from placeholder, v2.0.0) |
| `Rules/Defender.Rules.json` | Full rule definitions (upgraded from placeholder, v2.0.0) |

**EXO Assessor Checks (Invoke-TtcExoAssessment):**
| FindingId | CheckName | Severity |
|-----------|-----------|----------|
| EXO-MON-002 | Unified Audit Log Status | High |
| EXO-MON-001 | Mailbox Audit Logging | Medium |
| EXO-SEC-001 | Modern Authentication Status | High |
| EXO-SEC-002 | Anti-Malware Policy Configuration | High |
| EXO-SEC-003 | DKIM Signing Configuration | High |
| EXO-CFG-001 | SPF and DMARC Record Configuration | High |
| EXO-CFG-002 | Automatic External Email Forwarding | High |
| EXO-CFG-003 | Connector TLS Enforcement | Medium |
| EXO-CFG-004 | Anti-Spam Outbound Notification | Medium |
| EXO-GOV-001 | Exchange Admin Role Hygiene | High |

**Defender Assessor Checks (Invoke-TtcDefenderAssessment):**
| FindingId | CheckName | Severity |
|-----------|-----------|----------|
| DEF-SEC-001 | Safe Links Policy Coverage | High |
| DEF-SEC-002 | Safe Attachments Policy Coverage | High |
| DEF-SEC-003 | Anti-Phishing Policy Configuration | High |
| DEF-CFG-001 | Preset Security Policy Adoption | Medium |
| DEF-CFG-002 | Zero-Hour Auto Purge Configuration | Medium |
| DEF-CFG-003 | Defender for Office 365 SharePoint Teams OneDrive Protection | High |
| DEF-MON-001 | High-Severity Alert Policy Notification | Medium |
| DEF-MON-002 | Compromised Account Alert Policies | Medium |

**Key Decisions Made:**
- EXO assessor uses ExchangeOnlineManagement module; gracefully returns Error finding with guidance if `Connect-ExchangeOnline` not established
- Defender assessor shares the EXO session (no separate connection needed); probes for Defender P1+ by testing `Get-SafeLinksPolicy` availability
- DEF-SEC-001/002/003 return `NotAssessed` (not Error) when Defender P1+ cmdlets are absent — this is expected for EOP-only tenants and not a configuration error
- SPF/DMARC check (EXO-CFG-001) uses `Resolve-DnsName` (Windows DNSAPI) for DNS checks; filters out .onmicrosoft.com domains by default (controlled by `-IncludeOnmicrosoftDomains` switch)
- Connector TLS check distinguishes partner connectors (UseMxRecord = false) from default routing connectors to avoid false positives
- Defender preset policy check handles both EOP-only (`Get-EOPProtectionPolicyRule`) and Defender P1+ (`Get-ATPProtectionPolicyRule`) scenarios
- `Get-ATPBuiltInProtectionRule` is probed opportunistically to detect Microsoft built-in protection baseline active state
- Alert policy checks enumerate Microsoft default policy names by substring match (case-insensitive) for resilience to minor naming variations

**Required Prerequisites:**
- EXO assessor: `Connect-ExchangeOnline` (ExchangeOnlineManagement module)
- Defender assessor: same `Connect-ExchangeOnline` session; no separate Graph connection required
- Defender P1+ license required for: DEF-SEC-001 (Safe Links), DEF-SEC-002 (Safe Attachments), DEF-CFG-001 (ATP preset policies), DEF-CFG-003 (SPO/Teams/ODB protection)

---

### Phase 5 — Collaboration Assessor + Extensibility (Completed 2026-03-20)

**Files Created/Modified:**

| File | Purpose |
|------|---------|
| `Assessors/Collaboration/Invoke-TtcCollabAssessment.ps1` | Full Collaboration assessor — 8 checks |
| `Rules/Collaboration.Rules.json` | Full rule definitions (v2.0.0) |
| `Public/Invoke-TtcAutoFix.ps1` | Auto-fix script generator — creates reviewed remediation .ps1 |
| `Public/Invoke-TtcAssessment.ps1` | Added `-ExcludeChecks` parameter + config-driven ExcludeChecks filtering |
| `Private/Test-TtcPrerequisite.ps1` | Fixed Collaboration prereq (Graph.Authentication only); fixed Defender prereq (ExchangeOnlineManagement) |

**Collaboration Assessor Checks (Invoke-TtcCollabAssessment):**
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

**Key Decisions Made:**
- Collaboration assessor uses `Invoke-MgGraphRequest GET /v1.0/admin/sharepoint/settings` as primary SPO data source; falls back to `Get-SPOTenant` (SPO Management Shell) if Graph scope `SharePointTenantSettings.Read.All` is not consented
- Inner helper `Get-SpoValue` normalises field name differences between Graph camelCase and SPO PascalCase properties
- COL-GOV-003 probes `Get-RetentionCompliancePolicy` cmdlet existence (requires Connect-IPPSSession); returns NotAssessed if IPPS session not available — this is expected in many environments
- COL-GOV-004 probes MicrosoftTeams module availability; returns NotAssessed if module absent — not an error
- Parameters: `-AnonymousLinkMaxExpirationDays 30` and `-GuestLinkMaxExpirationDays 90` allow threshold tuning
- ExcludeChecks filtering added to `Invoke-TtcAssessment`: merges `-ExcludeChecks` parameter with `Config.ExcludeChecks` array; parameter takes precedence over config file
- `Invoke-TtcAutoFix` generates a complete `.ps1` remediation script — uses `StringBuilder`, groups by workload, detects PowerShell cmdlet lines via regex (Get-|Set-|New-|Remove-|Add-|Enable-|Disable-|Import-|Connect-|Update-|Invoke-|Install-|Uninstall-) and emits them as executable code; prose lines emitted as comments
- AutoFix scaffold NEVER executes remediation; output script includes `ShouldProcess` guard per finding and requires manual review before execution
- Defender prereq corrected to `ExchangeOnlineManagement` (it reuses the EXO session, not Graph)

**Required Prerequisites:**
- Collaboration assessor: `Connect-MgGraph` with `SharePointTenantSettings.Read.All` (or `Get-SPOTenant` via `Connect-SPOService` as fallback)
- COL-GOV-003 (retention): `Connect-IPPSSession` (optional — returns NotAssessed if absent)
- COL-GOV-004 (Teams): `Import-Module MicrosoftTeams` + `Connect-MicrosoftTeams` (optional — returns NotAssessed if absent)

---

---

### Phase 6 — Pester Test Suite + Console Summary Function (Completed 2026-03-20)

**Files Created/Modified:**

| File | Purpose |
|------|---------|
| `Tests/TtcEngine.Tests.ps1` | Pester 5 unit tests — New-TtcFinding, scoring, Invoke-TtcAutoFix, Test-TtcPrerequisite |
| `Tests/TtcReports.Tests.ps1` | Pester 5 unit tests — Export-TtcCsvReport, Export-TtcHtmlReport, Get-TtcFindingSummary |
| `Public/Get-TtcFindingSummary.ps1` | Quick colour-coded console summary — scores, severity counts, workload table, top findings |
| `TakeItToCloud.Assess.psd1` | Added `Get-TtcFindingSummary` and `Invoke-TtcAutoFix` to FunctionsToExport |

**Test Coverage (TtcEngine.Tests.ps1 — 23 tests):**
| Describe Block | Tests |
|----------------|-------|
| New-TtcFinding | 9 — schema completeness, RiskLevel/RemediationPriority auto-derivation, Timestamp format, explicit value preservation |
| Get-TtcAssessmentScore | 8 — score math with known inputs (83 Security, 98 Health, 100 Governance), floor at 0, Pass/Error/NotAssessed non-deduction, pipeline input, workload breakdown |
| Invoke-TtcAutoFix | 7 — file creation, non-empty output, header content, fixable finding inclusion, manual finding comment section, severity filter, -WhatIf suppression |
| Test-TtcPrerequisite | 3 — return type, no-throw for all workloads |

**Test Coverage (TtcReports.Tests.ps1 — 18 tests):**
| Describe Block | Tests |
|----------------|-------|
| Export-TtcCsvReport | 5 — file exists, non-empty, column headers, finding data, row count |
| Export-TtcHtmlReport | 6 — file exists, non-empty, valid HTML, customer name, finding IDs, no CDN dependencies |
| Get-TtcFindingSummary | 7 — no-throw, pre-computed scores, pipeline, PassThru schema, CriticalFailCount, severity filter, no output without PassThru |

**Get-TtcFindingSummary design:**
- Accepts `$Findings` (pipeline) and optional `$Scores`; calculates scores internally if Scores not provided
- Parameters: `-CustomerName`, `-TopFindingsSeverity High`, `-TopFindingsCount 10`, `-PassThru`
- Colour-coded output: progress bar for Overall score, per-severity finding counts, workload table sorted by score ascending (worst first), top findings with issue text
- -PassThru returns PSCustomObject: TotalFindings, CriticalFailCount, HighFailCount, OverallScore, SecurityScore, HealthScore, GovernanceScore, TopFindings
- Calls Write-TtcLog for audit trail

**How to run tests:**
```powershell
# Requires Pester 5.x
Install-Module Pester -Force -SkipPublisherCheck

# Run all tests
Invoke-Pester -Path .\TakeItToCloud.Assess\Tests\ -Output Detailed

# Run engine tests only
Invoke-Pester -Path .\TakeItToCloud.Assess\Tests\TtcEngine.Tests.ps1 -Output Detailed

# Run with code coverage (requires Pester 5.2+)
Invoke-Pester -Path .\TakeItToCloud.Assess\Tests\ -CodeCoverage .\TakeItToCloud.Assess\Public\*.ps1
```

---

## Current Phase

### Phase 7 — Backlog / Future Work
- **Status**: No phases currently planned
- **Potential scope** (not committed):
  - Additional AD checks (AdminSDHolder, LAPS coverage, tombstone lifetime)
  - Exchange Online compliance checks (DLP policies, message encryption)
  - Defender for Endpoint integration (MDE device compliance)
  - Custom rule pack loading from external paths (`-RulesPath` override)
  - Remediation field population across all existing rules (enables full AutoFix value)

---

## Backlog

---

## Continuation Prompt Template

Paste this at the start of every new Claude conversation:

```
You are continuing development of the TakeItToCloud.Assess PowerShell module.
This is a production-grade Microsoft 365 / hybrid infrastructure assessment framework.

READ THESE FILES FIRST — they define the architecture and current state:
1. PROJECT_SPEC.md — Architecture, data models, conventions, standards. Follow exactly.
2. PHASE_TRACKER.md — What has been built and what to build next.

RULES:
- Continue with the current phase listed in PHASE_TRACKER.md
- Produce complete, production-ready PowerShell code
- All code must integrate with existing files and follow established patterns
- Use the finding object schema from PROJECT_SPEC.md §3 exactly
- Use the function naming convention: Verb-TtcNoun
- Include comment-based help on all public functions
- Include error handling (try/catch) in all assessor functions
- Use Write-TtcLog for all logging
- Use New-TtcFinding for all finding creation
- At the end, provide the UPDATED PHASE_TRACKER.md content reflecting what was completed

ATTACH these files to this message:
- PROJECT_SPEC.md
- PHASE_TRACKER.md
- TakeItToCloud.Assess.psm1 (module loader, for reference)
- Private/New-TtcFinding.ps1 (finding factory, for integration)
- Private/Write-TtcLog.ps1 (logging, for integration)
```

---

*Last updated: 2026-03-20 — Phase 6 complete*
