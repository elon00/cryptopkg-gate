# Cryptopkg Gate — local artifact integrity prototype

This repository is the **tests** component of QMOOSA-1000 Batch 177
(QMOOSA-0885). It currently provides a limited **local SHA-256 package
artifact checker**, not a package registry, package signing system, post-quantum
cryptography implementation, deployment gate, or production certification.

## Run locally

Python 3.11+ is required. Provide an existing directory and a JSON manifest:

\`\`\`json
{"schema_version":1,"artifacts":[{"path":"release.bin","sha256":"<64 lowercase hex characters>"}]}
\`\`\`

\`\`\`bash
python package_integrity_gate.py --root ./artifacts --manifest ./manifest.json
python -m compileall -q package_integrity_gate.py tests
python -m unittest discover -s tests -p 'test_*.py' -v
cargo test --offline
\`\`\`

The checker rejects malformed paths, missing files, duplicate paths, symlinks,
oversized artifacts and hash mismatches. Tests use real temporary filesystem
objects and real Python subprocesses, including adversarial negative cases.
No network, paid resource, blockchain deployment or secret is required.

## Limits and release blockers

SHA-256 **integrity is not authenticity**: an attacker who controls both the
artifact and manifest can replace both. The local path checks are not hardened
against adversarial concurrent filesystem modification (TOCTOU), and do not
provide signature provenance, transparency logs, reproducible builds or registry
access controls. Independent security review and a complete registry
implementation are required before any deployment-ready decision.

Do not interpret a green CI run, local regression tests, README or architecture
scorecard as a FIPS validation, audited cryptographic implementation,
security approval or production-readiness certificate. No such approval is
claimed here.
