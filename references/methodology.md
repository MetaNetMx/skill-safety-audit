Warning: truncated output (original token count: 1315)
Total output lines: 98

# Professional Pre-Installation Audit Methodology

## 1. Assurance statement

This process provides evidence-based confidence, not certainty. Static analysis cannot prove the absence of malicious behavior, time-delayed behavior, compromised upstream infrastructure, or future updates. Approval therefore binds to one exact version or content hash and a stated permission set.

## 2. Audit receipt

Record before inspection:

- candidate name and claimed purpose;
- source location and publisher;
- immutable commit, signed release, or archive SHA-256;
- acquisition timestamp;
- authorized audit mode;
- intended runtime and requested tools/permissions;
- reviewer and known limitations.

## 3. Audit modes and gates

| Mode | Permitted work | Gate |
| --- | --- | --- |
| Static | Read files and metadata; hash, parse, classify, and reason about declared behavior. | Default; no candidate code execution. |
| Controlled dynamic | Run a reviewed artifact in a disposable lab with synthetic data, snapshot/revert, no reusable credentials, and deny-by-default egress. | Explicit approval and written test plan. |
| Installation | Place or enable the approved revision with stated controls. | Separate explicit approval after verdict. |

## 4. Evidence model

| Label | Meaning | Can support approval? |
| --- | --- | --- |
| `observed` | Direct file content, metadata, hash, signature, or controlled test output. | Yes, with context. |
| `derived` | Reproducible technical conclusion from cited observations. | Yes, with assumptions stated. |
| `suspected` | Plausible hypothesis not yet verified. | No. |
| `unknown` | Missing, opaque, unreachable, or untested information. | No when material. |

Model prose is analysis, not evidence. Scanner findings are leads until a reviewer establishes reachability, purpose, and effect.

## 5. Required review domains

1. **Instruction integrity** — hidden directives, authority conflicts, prompt injection, audit bypass, self-modification, deceptive claims.
…315 tokens truncated…Critical | Verified or directly instructed unauthorized secret exfiltration, destructive action, or broad privilege compromise. |
| High | Reachable sensitive capability can create material data or system impact without adequate control. |
| Medium | Elevated or ambiguous capability requires restriction, clarification, or controlled testing. |
| Low | Limited, justified capability with bounded impact and clear controls. |
| Informational | Inventory or context with no independent security impact. |

Never promote keyword matches directly to Critical or High without contextual review.

## 7. Approval gates

All must pass before **APPROVE WITH CONTROLS**:

- Provenance: exact source and revision are reproducible.
- Completeness: all shipped files are inventoried; opaque or skipped content is resolved.
- Instruction integrity: no instruction can override higher authority or hide material behavior.
- Permission minimization: each requested capability is necessary and bounded.
- Data flow: sensitive sources and every external destination are understood.
- Execution: scripts, hooks, binaries, dynamic loading, and persistence paths are justified.
- Supply chain: dependencies are locked or otherwise integrity-controlled.
- Operations: controls, rollback, monitoring, and re-audit triggers are documented.

## 8. Required report

```text
Executive decision and confidence
Audit receipt
Scope and limitations
Artifact inventory and tree digest
Instruction and permission map
Data-flow and network-destination map
Execution, lifecycle, binary, and persistence review
Supply-chain and provenance review
Findings: ID, evidence label, severity, confidence, reachability, evidence, impact, control
Unresolved questions
Verdict and mandatory controls
Re-audit triggers
```

## 9. Re-audit triggers

Re-audit after any changed commit/hash, dependency or lockfile, permission, tool/MCP declaration, endpoint, install/update hook, binary, generated artifact, publisher/signature, or runtime policy.
