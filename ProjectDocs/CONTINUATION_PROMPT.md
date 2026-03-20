# How to Continue Development in a New Chat

## STEP 1: Copy and paste this prompt into a new Claude conversation

---

You are continuing development of the **TakeItToCloud.Assess** PowerShell module.
This is a production-grade Microsoft 365, Hybrid Identity, and Infrastructure assessment framework built for the TakeItToCloud consulting brand.

**READ THE ATTACHED FILES FIRST** — they define the full architecture and current state:

1. **PROJECT_SPEC.md** — Architecture, finding schema, scoring model, naming conventions, folder structure. Follow exactly. Never deviate without updating the spec.
2. **PHASE_TRACKER.md** — What has been built, what to build next, and key decisions from prior sessions.

**RULES FOR THIS SESSION:**

- Continue with the **current phase** listed in PHASE_TRACKER.md under "Current Phase"
- Produce **complete, production-ready PowerShell code** — no pseudocode, no placeholders
- All code must **integrate with existing files** and follow established patterns
- Use the **finding object schema** from PROJECT_SPEC.md §3 exactly (21 properties, all mandatory, empty string for N/A)
- Use **`New-TtcFinding`** (Private function) to create all finding objects inside assessors
- Use **`Write-TtcLog`** for all logging (levels: Info, Warning, Error, Debug)
- Use **`Get-TtcRulePack`** to load rule metadata from JSON when needed
- Follow **Verb-TtcNoun** naming convention for all functions
- Include **comment-based help** on all public functions
- Include **try/catch error handling** in all assessor functions — errors return Status="Error" findings, never crash the pipeline
- Each assessor function returns **`[PSCustomObject[]]`** — an array of finding objects
- At the end of your response, provide the **UPDATED PHASE_TRACKER.md** content reflecting what was completed, so I can save it for the next session

---

## STEP 2: Attach these files to the message

**Always attach (minimum):**
- `ProjectDocs/PROJECT_SPEC.md`
- `ProjectDocs/PHASE_TRACKER.md`

**Also attach for context (recommended):**
- `TakeItToCloud.Assess/TakeItToCloud.Assess.psm1` — module loader
- `TakeItToCloud.Assess/Private/New-TtcFinding.ps1` — finding factory
- `TakeItToCloud.Assess/Private/Write-TtcLog.ps1` — logging engine

**If the current phase modifies existing files, also attach those files.**

---

## STEP 3: After Claude completes the phase

1. Review the code Claude produced
2. Copy files into your repo at the correct paths
3. **Save the updated PHASE_TRACKER.md** that Claude provides at the end
4. Test by running `Demo-TtcAssessment.ps1` or the real assessor
5. Commit to Git
6. Repeat from Step 1 for the next phase

---

## Quick Reference: What to Attach Per Phase

| Phase | Attach These Extra Files |
|-------|-------------------------|
| Phase 3 (AD/Entra/Hybrid assessors) | Rules/AD.Rules.json, Rules/EntraID.Rules.json, Rules/HybridIdentity.Rules.json |
| Phase 4 (Exchange/Defender) | Rules/ExchangeOnline.Rules.json, Rules/Defender.Rules.json |
| Phase 5 (Collaboration + extensibility) | Rules/Collaboration.Rules.json, Config/DefaultConfig.json |

---

## If You Want to Close This Chat Mid-Phase

If Claude is partway through a phase and you need to stop:

1. Ask Claude: **"Before I close, give me the updated PHASE_TRACKER.md reflecting what was completed and what remains in this phase."**
2. Save that updated PHASE_TRACKER.md
3. In the new chat, Claude will see the partial progress and continue from where you left off
