# TakeItToCloud.Assess — Project Specification

> **Purpose**: This document is the architectural reference for the TakeItToCloud.Assess PowerShell module.
> Every new Claude conversation must read this file to understand the contracts, conventions, and decisions.
> Do NOT deviate from this spec without updating it.

---

## 1. Module Identity

- **Module Name**: `TakeItToCloud.Assess`
- **Brand**: TakeItToCloud (Carlos's consulting practice)
- **Function Prefix**: `Ttc` (e.g., `Invoke-TtcAssessment`, `New-TtcFinding`)
- **Architecture**: Option A — Single module with subcomponents
- **Target PowerShell**: 5.1+ and 7.x cross-compatible where possible
- **License**: Proprietary

---

## 2. Folder Structure (Locked)

```
TakeItToCloud.Assess/
├── TakeItToCloud.Assess.psd1            # Module manifest
├── TakeItToCloud.Assess.psm1            # Root module loader
├── Public/                              # Exported functions (dot-sourced)
│   ├── Invoke-TtcAssessment.ps1         # Main orchestrator
│   ├── Export-TtcCsvReport.ps1          # CSV export
│   ├── Export-TtcHtmlReport.ps1         # HTML report generation
│   ├── Get-TtcAssessmentScore.ps1       # Scoring engine
│   └── New-TtcFindingObject.ps1         # Public finding constructor
├── Private/                             # Internal helpers (not exported)
│   ├── New-TtcFinding.ps1              # Internal finding factory
│   ├── Write-TtcLog.ps1               # Logging engine
│   ├── Get-TtcRulePack.ps1            # Rule file loader
│   ├── Resolve-TtcFrameworkMapping.ps1 # Framework mapping resolver
│   ├── Get-TtcSeverityWeight.ps1       # Severity-to-weight converter
│   ├── Get-TtcHtmlTemplate.ps1         # HTML template builder
│   └── Test-TtcPrerequisite.ps1        # Prerequisite checker
├── Assessors/                           # Workload assessment engines
│   ├── ActiveDirectory/
│   │   └── Invoke-TtcAdAssessment.ps1
│   ├── ExchangeOnline/
│   │   └── Invoke-TtcExoAssessment.ps1
│   ├── HybridIdentity/
│   │   └── Invoke-TtcHybridAssessment.ps1
│   ├── EntraID/
│   │   └── Invoke-TtcEntraAssessment.ps1
│   ├── Defender/
│   │   └── Invoke-TtcDefenderAssessment.ps1
│   └── Collaboration/
│       └── Invoke-TtcCollabAssessment.ps1
├── Rules/                               # JSON rule definitions
│   ├── AD.Rules.json
│   ├── ExchangeOnline.Rules.json
│   ├── HybridIdentity.Rules.json
│   ├── EntraID.Rules.json
│   ├── Defender.Rules.json
│   └── Collaboration.Rules.json
├── Templates/
│   └── (HTML template is generated in-code, no external file needed)
├── Config/
│   └── DefaultConfig.json               # Default assessment configuration
└── Logs/
    └── (Runtime log files go here)
```

---

## 3. Finding Object Schema (Locked)

Every check in the framework returns one or more `[PSCustomObject]` with this exact schema.
All properties are mandatory. Use empty string `""` for unknown/not-applicable values. Never use `$null`.

```powershell
[PSCustomObject]@{
    FindingId            = [string]  # Format: "{WORKLOAD}-{CATEGORY}-{NNN}" e.g. "AD-SEC-001"
    Workload             = [string]  # ActiveDirectory | ExchangeOnline | HybridIdentity | EntraID | Defender | Collaboration
    Component            = [string]  # Sub-area, e.g. "DNS", "Connectors", "ConditionalAccess"
    CheckName            = [string]  # Human-readable check name
    Category             = [string]  # Health | Configuration | Security | Identity | Compliance | Monitoring | Resilience | Governance
    Severity             = [string]  # Critical | High | Medium | Low | Informational
    Status               = [string]  # Fail | Pass | Warning | Error | NotAssessed
    IssueDetected        = [string]  # One-line summary of what was found
    Explanation          = [string]  # Why this matters (2-3 sentences)
    PossibleSolution     = [string]  # What to do about it (actionable)
    Impact               = [string]  # Business impact if unresolved
    RiskLevel            = [string]  # Critical | High | Medium | Low
    FrameworkMapping     = [string]  # Primary: "NIST-Protect" | "CIS-AccessControl" | "ISO27001-A.9" etc.
    ZeroTrustPillar      = [string]  # Identity | Devices | Applications | Data | Infrastructure | Networks
    SecureScoreMapping   = [string]  # Microsoft Secure Score category or ""
    DataSource           = [string]  # Where the data came from, e.g. "Get-MgUser", "Get-ADDomain"
    Remediation          = [string]  # Detailed remediation steps
    AutoFixAvailable     = [string]  # Yes | No | Partial
    RemediationPriority  = [string]  # P1 | P2 | P3 | P4
    Notes                = [string]  # Additional context
    Timestamp            = [string]  # ISO 8601 format: (Get-Date -Format "o")
}
```

### Finding ID Convention

| Workload         | Prefix | Example     |
|------------------|--------|-------------|
| Active Directory | AD     | AD-SEC-001  |
| Exchange Online  | EXO    | EXO-CFG-003 |
| Hybrid Identity  | HYB    | HYB-IDN-002 |
| Entra ID         | ENT    | ENT-SEC-005 |
| Defender         | DEF    | DEF-MON-001 |
| Collaboration    | COL    | COL-GOV-004 |

Category abbreviations in IDs: SEC (Security), CFG (Configuration), HLT (Health), IDN (Identity), CMP (Compliance), MON (Monitoring), RSL (Resilience), GOV (Governance)

---

## 4. Severity Weights (Locked)

| Severity       | Weight | Description                          |
|----------------|--------|--------------------------------------|
| Critical       | 10     | Immediate exploitation risk          |
| High           | 7      | Significant security/operational gap |
| Medium         | 4      | Notable weakness                     |
| Low            | 1      | Minor improvement opportunity        |
| Informational  | 0      | Best practice note, no risk          |

---

## 5. Scoring Model (Locked)

Three scores, each 0-100 (100 = perfect):

1. **Health Score** — Operational health (Health, Configuration, Resilience categories)
2. **Security Score** — Security posture (Security, Identity, Monitoring categories)
3. **Governance Score** — Maturity/governance (Compliance, Governance categories)

**Formula per score**:
```
Score = MAX(0, 100 - SUM(weight_of_each_failed_finding_in_scope))
```

- Only `Fail` and `Warning` findings count (Warning at 50% weight)
- `Pass`, `Error`, `NotAssessed` do not reduce score
- Per-workload scores use the same formula filtered by workload
- **Overall Environment Score** = weighted average: Security (50%) + Health (30%) + Governance (20%)

---

## 6. Framework Mapping Convention (Locked)

Each finding maps to ONE primary framework using this format:

| Framework    | Format                  | Examples                                |
|--------------|-------------------------|-----------------------------------------|
| NIST CSF     | `NIST-{Function}`       | NIST-Identify, NIST-Protect, NIST-Detect, NIST-Respond, NIST-Recover |
| CIS Controls | `CIS-{Domain}`          | CIS-AccessControl, CIS-SecureConfig, CIS-ContinuousMonitoring, CIS-IncidentResponse |
| ISO 27001    | `ISO27001-A.{number}`   | ISO27001-A.9 (Access), ISO27001-A.12 (Operations), ISO27001-A.18 (Compliance) |

**Zero Trust Pillars**: Identity | Devices | Applications | Data | Infrastructure | Networks

**Secure Score Mapping**: Use Microsoft Secure Score category names where applicable, or empty string.

---

## 7. Authentication Approach

- **On-premises AD**: RSAT cmdlets (ActiveDirectory module), run as domain user
- **Exchange Online**: ExchangeOnlineManagement module (`Connect-ExchangeOnline`)
- **Microsoft Graph**: Microsoft.Graph SDK (`Connect-MgGraph`)
- **Defender**: Microsoft.Graph.Security or Security & Compliance PowerShell
- **No custom auth wrapper** — each assessor handles its own prerequisites

---

## 8. Logging Convention

All logging goes through `Write-TtcLog` (Private function):

```powershell
Write-TtcLog -Level Info -Message "Starting AD assessment"
Write-TtcLog -Level Warning -Message "Cannot reach DC01"
Write-TtcLog -Level Error -Message "Exchange connection failed" -ErrorRecord $_
```

Levels: `Info`, `Warning`, `Error`, `Debug`
Logs write to: Console (via Write-Verbose/Write-Warning) AND `Logs/TtcAssess_{date}.log`

---

## 9. Error Handling Convention

- Every assessor function wrapped in `try/catch`
- On error: log via `Write-TtcLog`, return a finding with `Status = "Error"` and the error in Notes
- Never let an exception kill the entire assessment pipeline
- Use `$ErrorActionPreference = 'Stop'` inside try blocks for predictable catching

---

## 10. Report Outputs

### CSV
- UTF-8 with BOM (for Excel compatibility)
- All finding properties as columns
- One row per finding
- Exported via `Export-Csv -NoTypeInformation`

### HTML
- Fully self-contained (inline CSS + JS)
- No external CDN dependencies
- Sections: Executive Summary → Score Cards → Charts → Findings Table → Remediation
- Filtering by: Severity, Workload, Category, Framework, Status
- Search box for findings table
- Color-coded severity badges
- Responsive layout
- Professional dark navy + green accent theme (TakeItToCloud brand)

---

## 11. Coding Standards

- **Naming**: `Verb-TtcNoun` for all functions
- **Help**: Comment-based help on every public function
- **Parameters**: `[CmdletBinding()]`, `[Parameter()]` with validation
- **Output**: `[OutputType()]` on public functions
- **Pipeline**: Public functions should accept pipeline input where logical
- **No aliases** in module code
- **Strict mode**: Functions should work under `Set-StrictMode -Version Latest`

---

## 12. Config File Schema (DefaultConfig.json)

```json
{
    "AssessmentName": "TakeItToCloud Assessment",
    "Workloads": ["ActiveDirectory", "EntraID", "HybridIdentity", "ExchangeOnline", "Defender", "Collaboration"],
    "ExcludeWorkloads": [],
    "ExcludeChecks": [],
    "SeverityFilter": ["Critical", "High", "Medium", "Low", "Informational"],
    "OutputPath": "./Reports",
    "LogPath": "./Logs",
    "GenerateCsv": true,
    "GenerateHtml": true,
    "EnvironmentMetadata": {
        "CustomerName": "",
        "AssessedBy": "",
        "EngagementId": ""
    }
}
```

---

## 13. Rule Pack Schema (JSON)

Each workload has a `{Workload}.Rules.json` file. Rules define metadata; the actual check logic lives in assessor `.ps1` files.

```json
{
    "RulePackName": "ActiveDirectory",
    "Version": "1.0.0",
    "Rules": [
        {
            "RuleId": "AD-SEC-001",
            "CheckName": "Stale privileged group members",
            "Category": "Security",
            "DefaultSeverity": "High",
            "Enabled": true,
            "FrameworkMapping": "CIS-AccessControl",
            "ZeroTrustPillar": "Identity",
            "SecureScoreMapping": "",
            "Description": "Checks for accounts in privileged groups that have not logged in recently"
        }
    ]
}
```

---

## 14. Workloads & Check Scope

| Workload         | Phase | Check Areas |
|------------------|-------|-------------|
| Active Directory | 3     | Replication, DNS, FSMO, DC health, privileged groups, password policy, delegation, audit policy |
| Hybrid Identity  | 3     | Entra Connect health, sync errors, cert expiry, PHS/PTA/Federation, break-glass, MFA gaps |
| Entra ID         | 3     | MFA posture, Conditional Access, role hygiene, risky users, app consent, external collab, audit |
| Defender         | 4     | Onboarding, threat protection, exposure reduction, device posture, baselines, alerting |
| Exchange Online  | 4     | Mail flow, connectors, legacy auth, anti-malware, DKIM/SPF/DMARC, admin roles, audit |
| Collaboration    | 5     | External sharing, anonymous links, guest access, retention, sensitivity labels |

---

*Last updated: Phase 1+2 build*
