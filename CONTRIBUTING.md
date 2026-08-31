# Contributing

Contributions should improve evidence quality, reduce blind spots, or make the audit workflow easier to reproduce without expanding unsafe authority.

## Requirements

- Keep candidate inspection read-only by default.
- Do not add automatic installation or execution of untrusted candidate code.
- Do not add offensive payloads, credential validation, exploit execution, or third-party scanning.
- Redact sensitive values; reports may retain only non-reversible correlation fingerprints.
- Give every new material rule a stable rule ID, severity rationale, and remediation.
- Distinguish capability detection from malicious intent and runtime reachability.
- Add or update a synthetic regression test for behavioral changes.

## Validate a change

```bash
python3 -B scripts/self_test.py
python3 -B scripts/audit_skill.py . --format json --output ../skill-safety-audit-self-review.json
```

Review the generated findings manually. The scanner's conservative disposition is not a substitute for the methodology in `references/methodology.md`.

## Pull requests

Explain the security problem, evidence, affected audit domain, limitations, test coverage, and expected impact on false positives and false negatives. Keep unrelated changes separate.
