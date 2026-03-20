# How to Continue Development — Claude in VS Code

Since you're using Claude inside VS Code, your project files are already in the workspace. No need to attach anything.

---

## When Starting a New Chat for the Next Phase

Paste this prompt:

```
You are continuing development of the TakeItToCloud.Assess PowerShell module.
This is a production-grade Microsoft 365, Hybrid Identity, and Infrastructure assessment framework.

Before writing any code, read these files from the workspace:

1. ProjectDocs/PROJECT_SPEC.md — Architecture, finding schema, scoring model, naming conventions. Follow exactly.
2. ProjectDocs/PHASE_TRACKER.md — What has been built and what to build next.
3. TakeItToCloud.Assess/Private/New-TtcFinding.ps1 — Finding factory (use this in all assessors).
4. TakeItToCloud.Assess/Private/Write-TtcLog.ps1 — Logging engine (use this for all logging).
5. TakeItToCloud.Assess/TakeItToCloud.Assess.psm1 — Module loader (for integration context).

RULES:
- Continue with the current phase listed in PHASE_TRACKER.md
- Produce complete, production-ready PowerShell code — no pseudocode
- All code must integrate with existing files and follow established patterns
- Use New-TtcFinding for all finding creation
- Use Write-TtcLog for all logging
- Follow Verb-TtcNoun naming convention
- Include comment-based help on public functions
- Include try/catch error handling — errors return Status="Error" findings, never crash the pipeline
- Each assessor returns [PSCustomObject[]] — an array of finding objects
- At the end, update ProjectDocs/PHASE_TRACKER.md reflecting what was completed
```

That's it. Claude reads the files from your workspace, knows where you are, and continues building.

---

## If You Need to Stop Mid-Phase

Before closing the chat, just say:

```
Update ProjectDocs/PHASE_TRACKER.md to reflect what was completed and what remains in this phase.
```

Claude will edit the file directly in your workspace. Next chat picks up from there.

---

## After Each Phase Is Done

1. Review the code Claude wrote
2. Test by running Demo-TtcAssessment.ps1 or the real assessor
3. Go to Source Control (Ctrl+Shift+G) → Stage → Commit → Push
4. Start a new chat, paste the prompt above, keep building

---

## Quick Reference: Phase Roadmap

| Phase | What Gets Built | Status |
|-------|----------------|--------|
| 1+2 | Core engine, scoring, CSV export, HTML report | DONE |
| 3 | AD + Entra ID + Hybrid Identity assessors (real checks) | NEXT |
| 4 | Exchange Online + Defender assessors | Backlog |
| 5 | Collaboration (SPO/Teams) + rule pack extensibility | Backlog |
