# T3MP3ST-Inspired Defensive Adaptation

This skill adapts selected governance concepts from [T3MP3ST](https://github.com/elder-plinius/T3MP3ST) without copying its source code or enabling offensive tooling. T3MP3ST is AGPL-3.0; the integration here is limited to high-level defensive process ideas from its public documentation.

## Adopted controls

- **Scope receipt:** bind every review to a named target, immutable revision, allowed action class, and operator.
- **Tool gates:** separate read-only inspection, approval-gated lab execution, and approval-gated installation.
- **Evidence ledger:** require reproducible tool/file evidence before promoting a model assertion.
- **Finding ledger:** separate claim, impact, reachability, evidence, confidence, limitation, remediation, and retest status.
- **Retest:** keep unverified claims as hypotheses; re-run the audit when the candidate changes.
- **Human-reviewed learning:** never convert one approval into permanent trust of a publisher or future version.

## Deliberately excluded capabilities

This skill does not perform reconnaissance against remote targets, exploit vulnerabilities, harvest credentials, establish persistence, evade detection, generate payloads, scan third-party systems, or interact with a candidate MCP server. Its target is only the user-supplied skill package or repository snapshot.

## GitHub review procedure

1. Record owner/repository, immutable commit SHA or signed release, acquisition date, and claimed publisher.
2. Inspect the full tree, not only `SKILL.md` or README files. Include scripts, workflows, submodules, Git LFS pointers, manifests, locks, release artifacts, MCP declarations, and update/bootstrap paths.
3. Compare declared behavior with reachable code and requested authority.
4. Treat lifecycle hooks, downloadable executables, moving branches, unpinned actions/dependencies, and opaque generated artifacts as review gates.
5. Do not run verification, build, or test commands until their definitions and dependencies have passed static review and controlled execution is explicitly authorized.
6. Bind any approval to the reviewed commit/content hash. A later commit is a new candidate.
