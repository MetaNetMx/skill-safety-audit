# Skill Safety Audit — Mental Map

```mermaid
mindmap
  root((Skill Safety Audit))
    Trust boundary
      Candidate is untrusted data
      No execution during static review
      No real secrets
      Separate install approval
    Evidence
      Immutable source
      SHA-256 inventory
      Rule and line references
      Observed vs derived
    Capability review
      Instructions and prompts
      Tools and MCP
      Files and credentials
      Network destinations
      Scripts and lifecycle hooks
      Dependencies and updates
      Platform artifacts
        Windows and macOS
        Linux and containers
        Android and iOS
    Decision
      Approve with controls
      Hold for review
      Reject verified harm
      Inconclusive evidence
    Operations
      Least privilege
      Isolated first use
      Monitor external effects
      Re-audit every change
```

The central idea is a chain of proof:

```mermaid
flowchart TD
    A[Candidate snapshot] --> B[Inventory and hashes]
    B --> C[Instructions and capabilities]
    C --> D[Data flows and external effects]
    D --> E[Evidence-backed findings]
    E --> F{Approval gates}
    F -->|All pass| G[Approve with controls]
    F -->|Risk unresolved| H[Hold or inconclusive]
    F -->|Verified harm| I[Reject]
    G --> J[Install exact revision]
    J --> K[Monitor and re-audit changes]
```

“No alert” is not the same as “safe.” Trust comes from complete evidence, bounded capability, explicit controls, and a version-specific decision.
