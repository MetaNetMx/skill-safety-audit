# Security Policy

## Supported version

Security review and fixes target the latest commit on the `main` branch. Audit and installation decisions must still be pinned to an exact commit or content hash.

## Report a vulnerability

Use GitHub's private vulnerability reporting or a private Security Advisory for this repository when available. Do not disclose an exploitable scanner bypass, secret leak, archive-handling flaw, or unsafe execution path in a public issue before maintainers can assess it.

A useful report includes:

- affected commit and file;
- impact and realistic preconditions;
- minimal, non-destructive reproduction using synthetic data;
- expected versus observed behavior;
- recommended mitigation, if known.

Do not include real credentials, private keys, personal data, malicious live endpoints, or weaponized payloads.

## Scope

In scope:

- candidate code execution caused by the static scanner;
- traversal or unsafe extraction behavior;
- raw secret disclosure in reports;
- incomplete inventory presented as complete;
- incorrect approval or evidence semantics;
- material permission, network, or supply-chain blind spots.

Out of scope:

- malicious behavior in a third-party skill that this project merely reports;
- unsupported guarantees that static analysis can prove absolute safety;
- attacks requiring unauthorized testing of third-party systems.

## Response principle

Unverified findings remain hypotheses. Fixes should include a safe regression test and preserve the read-only candidate boundary.
