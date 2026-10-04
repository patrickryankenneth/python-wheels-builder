# python-wheels-builder

A zero-trust, SLSA-aligned reference architecture for compiling deterministic, cryptographically attested Python wheels for hardened and air-gapped environments.

[![CI & Policy Verifier](https://github.com/patrickryankenneth/python-wheels-builder/actions/workflows/build-environment-image.yml/badge.svg)](https://github.com/patrickryankenneth/python-wheels-builder/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![SLSA Level 3](https://img.shields.io/badge/SLSA-Level_3_Principles-green.svg)](https://slsa.dev)

---

## Threat Model & Motivation

Standard Python packaging workflows often rely on implicit trust: pulling unverified binary wheels or compiling natively inside unhardened runners with full internet access and mutable action tags. In regulated domains (defense, financial systems, healthcare, and critical infrastructure), this creates critical supply-chain exposure:

1. **Unvetted Transitive Dependencies:** Build-time tools (like compilation caches) pulling in full HTTP/cloud networking stacks and unmonitored runtime dependencies.
2. **Assertion Rot in CI/CD:** Security assertions in build scripts that quietly decay or fail open over time.
3. **Asset Tampering & Missing Provenance:** Unsigned release assets and unpinned build inputs that allow silent drift.

This repository enforces **deterministic immutability, least-privilege tool compilation, and verifiable cryptographic attestations** from commit to artifact release.

---

## Architecture & Security Controls

```text
                        ┌────────────────────────────────────────┐
                        │   Developer Workstation (Signed GPG)   │
                        └──────────────────┬─────────────────────┘
                                           │ PR (Fast-forward only)
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ GitHub Actions: Zero-Trust Isolation                                                  │
│                                                                                        │
│  [Job: Gates] (No code checkout)                                                       │
│   ├── Parse OpenPGP signature packets (issuer fpr v4 allowlist)                        │
│   └── Compare API ancestor & linear history enforcement                                │
│                                                                                        │
│  [Job: Hermetic Container Build]                                                       │
│   ├── Multi-arch Alpine musl (x86_64 / aarch64) pinned to content-addressable digests  │
│   ├── sccache built with --no-default-features (local disk cache only, 0 network)      │
│   ├── Embedded dependency tracking via cargo-auditable                                 │
│   └── Build-time assertion gate with automated mutation testing                       │
│                                                                                        │
│  [Job: Policy Verification & Cryptographic Attestation]                                │
│   ├── Syft SBOM generation (CycloneDX / SPDX)                                          │
│   ├── OpenVEX exploitability documentation matching exact pinned crate hashes          │
│   ├── GitHub OIDC / Sigstore Keyless Attestation (actions/attest)                      │
│   └── Machine-verifiable Policy Check (IMG-1 through IMG-11)                           │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1. Minimal-Privilege Toolchain Hardening
* **Sccache Surface Reduction:** Mozilla’s `sccache` default feature set pulls in AWS, Azure, Google Cloud, and Redis SDKs via Apache OpenDAL and `reqwest`. We compile `sccache` with `--no-default-features` for local disk caching only, mathematically eliminating the network stack from the compiler wrapper.
* **Embedded Binaries via `cargo-auditable`:** Instead of persisting the full Cargo registry in the final image layer, dependencies are embedded directly into the ELF `.dep-v0` section. Scanners (Syft, Trivy) read the binary directly, preserving 100% SBOM visibility without layer bloat.
* **Runtime Assertions:** Container builds execute an in-tree assertion script (`assert-sccache-build.sh`) that halts compilation if network crates or un-VEXed crate versions are detected.

### 2. Mutation-Tested Verification Gates
Security scripts often suffer from false-positive confidence. Our test harness (`tests/`) implements **mutation testing** against our assertion gates:
* Systematically neuters each `assert_*` function to return `0` and verifies that the test suite catches the slipped violation.
* Enforces bidirectional synchronization: the OpenVEX statement and the pinned crate assertions cannot drift without failing unit tests.
* Full integration test suite verifies real multi-arch container builds against intentional pin-drift mutations.

### 3. Formal Policy Engine (`policy/builder-image/`)
Releases are governed by a machine-verifiable policy schema (`policy.json`) evaluated by `verify_builder_policy.py`:
* **Enforced Rules (`IMG-1` to `IMG-11`):** Cryptographic attestation verification, pinned action commit SHAs, digest-pinned base images, SBOM/VEX parity, and annotated Gitsign signatures.
* **Explicit Trust Roots (`TRU-1` to `TRU-4`):** Transparently defines the boundaries of the threat model (e.g., trust in Alpine signing keys and GitHub runner infrastructure).

---

## Verifying Release Artifacts

Every published builder container and release asset includes a Sigstore cryptographic attestation linked to this repository's OIDC workflow identity.

### Verify Image Provenance
```bash
gh attestation verify oci://ghcr.io/patrickryankenneth/python-wheels-builder-alpine:<digest> \
  --owner patrickryankenneth
```

### Run Policy Verification Locally
```bash
python3 .github/scripts/verify_builder_policy.py \
  --policy policy/builder-image/policy.json \
  --tag <release-tag> \
  --tag-sha <commit-sha> \
  --artifacts-dir /path/to/downloaded/assets \
  --vex environments/alpine-3.24-musl/vex/builder.openvex.json \
  --assets-file /path/to/assets.txt
```

---

## Running the Test Suite

### Unit & Gate Mutation Tests (Fast)
```bash
pytest tests -q
```

### End-to-End Container Integration Tests (Includes real container builds)
```bash
pytest tests -q --integration
```

---

## Compliance & Standards Alignment

This project is built as an educational and operational reference for:
* **NIST SP 800-218:** Secure Software Development Framework (SSDF)
* **SLSA (Supply-chain Levels for Software Artifacts):** Level 3 Build Invariants
* **OpenVEX Specification:** Transparent Vulnerability Exploitability Exchange

---

## Maintainer

**Patrick Ryan**
