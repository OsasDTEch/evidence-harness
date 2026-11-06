# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes     |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email **omonswisdom.ict@gmail.com** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Any suggested mitigations

You will receive an acknowledgement within 48 hours and a resolution timeline within 7 days.

## Security Model

evidence-harness is a local evidence-recording tool. Its security properties are:

- **Tamper-evident, not tamper-proof.** Records are sealed with SHA-256 and made read-only. Any modification breaks a hash that `verify` detects. An attacker with full disk access could rewrite the store consistently — use an object store with a retention lock (S3 Object Lock, Azure immutable blobs, GCS bucket lock) or the included GitHub Actions sentinel for tamper-proof guarantees.
- **API keys are never stored.** Authorization headers are redacted to `[REDACTED]` before any record is written. A test asserts this.
- **No network calls except to the configured provider.** The harness makes no telemetry or analytics calls.
- **No dependencies.** The harness uses only the Python standard library, eliminating third-party supply-chain risk.
