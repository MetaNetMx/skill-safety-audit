# How to Install and Use Skill Safety Audit

## Install this auditor

Place the `skill-safety-audit` folder in the Codex skills directory so the final path is:

```text
~/.codex/skills/skill-safety-audit/SKILL.md
```

On Windows, the equivalent is normally:

```text
C:\Users\YOUR_USER\.codex\skills\skill-safety-audit\SKILL.md
```

Open a new Codex/ChatGPT turn after installation. Do not place an unaudited candidate inside the active skills directory; keep it in a separate review folder.

### Install from GitHub on macOS or Linux

```bash
git clone https://github.com/MetaNetMx/skill-safety-audit.git \
  ~/.codex/skills/skill-safety-audit
```

### Install from GitHub on Windows PowerShell

```powershell
git clone https://github.com/MetaNetMx/skill-safety-audit.git `
  "$env:USERPROFILE\.codex\skills\skill-safety-audit"
```

For reproducibility, audit and pin a specific commit rather than permanently trusting the moving `main` branch.

## Simplest invocation

```text
Use $skill-safety-audit to audit this skill before installation: <GitHub URL, ZIP, or folder>.
Do not execute it. Give me an evidence-based verdict and mandatory controls.
```

## Professional invocation

```text
Use $skill-safety-audit in static, read-only mode.
Pin the candidate to an immutable revision, inventory and hash every shipped file,
review instructions, scripts, dependencies, lifecycle hooks, MCP/tool permissions,
secrets, network destinations, binaries, archives, workflows, and update paths.
Map reachable capabilities and data flows. Do not install or execute candidate code.
Return APPROVE WITH CONTROLS, HOLD / REVIEW REQUIRED, REJECT, or INCONCLUSIVE,
with evidence, confidence, limitations, controls, and re-audit triggers.
```

## Local scanner

From the installed skill directory:

```bash
python3 scripts/audit_skill.py /path/to/candidate \
  --format markdown \
  --output /path/outside/candidate/audit-report.md
```

For machine-readable evidence:

```bash
python3 scripts/audit_skill.py /path/to/candidate \
  --format json \
  --output /path/outside/candidate/audit-report.json
```

For an update/delta review:

```bash
python3 scripts/audit_skill.py /path/to/new-version \
  --format json \
  --baseline /path/to/previous-audit-report.json \
  --output /path/outside/candidate/new-audit-report.json
```

The scanner accepts a directory or ZIP. It does not install, import, build, test, or execute candidate code. Its disposition is preliminary; a human/agent review must apply the methodology before approval.

## Interpreting outcomes

- `STATIC GATES PASSED — MANUAL REVIEW REQUIRED`: automation found no material lead, but approval gates remain.
- `HOLD / REVIEW REQUIRED`: sensitive or ambiguous capability needs manual resolution.
- `INCONCLUSIVE`: inventory or evidence is incomplete.
- A final `APPROVE WITH CONTROLS` or `REJECT` comes only after contextual evidence review.

## Safe installation after approval

Install only the exact reviewed version. Start with minimum permissions, isolated data, scoped credentials, confirmation for external writes, and restricted network access. Record the approved hash and re-audit on every update.
