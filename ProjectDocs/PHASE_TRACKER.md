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
| `Rules/AD.Rules.json` | Sample AD rule pack (placeholder) |
| `Rules/EntraID.Rules.json` | Sample Entra ID rule pack (placeholder) |

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

**Public Functions Delivered:**
- `Invoke-TtcAssessment` — Main entry point
- `Export-TtcCsvReport` — CSV export
- `Export-TtcHtmlReport` — HTML report
- `Get-TtcAssessmentScore` — Scoring
- `New-TtcFindingObject` — Finding constructor

**Private Functions Delivered:**
- `New-TtcFinding` — Internal finding factory
- `Write-TtcLog` — Logging
- `Get-TtcRulePack` — Rule loader
- `Resolve-TtcFrameworkMapping` — Mapping resolver
- `Get-TtcSeverityWeight` — Weight lookup
- `Get-TtcHtmlTemplate` — HTML builder
- `Test-TtcPrerequisite` — Prereq checker

---

## Current Phase

### Phase 3 — Active Directory + Entra ID + Hybrid Identity Assessors
- **Status**: NOT STARTED
- **Scope**:
  - `Assessors/ActiveDirectory/Invoke-TtcAdAssessment.ps1` — AD checks (replication, DNS, FSMO, DC health, privileged groups, password policy, delegation, audit)
  - `Assessors/EntraID/Invoke-TtcEntraAssessment.ps1` — Entra checks (MFA, Conditional Access, role hygiene, risky users, app consent, external collab, audit)
  - `Assessors/HybridIdentity/Invoke-TtcHybridAssessment.ps1` — Hybrid checks (Entra Connect, sync errors, cert expiry, PHS/PTA, break-glass, MFA gaps)
  - `Rules/AD.Rules.json` — Full rule definitions
  - `Rules/EntraID.Rules.json` — Full rule definitions
  - `Rules/HybridIdentity.Rules.json` — Full rule definitions
- **Dependencies**: Core engine (Phase 1+2) must be loaded
- **Integration notes**: Each assessor must return `[PSCustomObject[]]` matching the finding schema in PROJECT_SPEC.md §3. Use `New-TtcFinding` for creation. Use `Write-TtcLog` for all logging. Use `Get-TtcRulePack` to load rule metadata.

---

## Backlog

### Phase 4 — Exchange Online + Defender Assessors
- `Assessors/ExchangeOnline/Invoke-TtcExoAssessment.ps1`
- `Assessors/Defender/Invoke-TtcDefenderAssessment.ps1`
- `Rules/ExchangeOnline.Rules.json`
- `Rules/Defender.Rules.json`

### Phase 5 — Collaboration + Extensibility
- `Assessors/Collaboration/Invoke-TtcCollabAssessment.ps1`
- `Rules/Collaboration.Rules.json`
- Configuration-driven rule pack enable/disable
- Custom rule pack loading from external paths
- Auto-fix scaffolding

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

*Last updated: 2026-03-20 — Phase 1+2 complete*
