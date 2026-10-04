# Policy builder-image v1

<!-- Generated from policy.json by policy_tool.py render-md. Do not edit. -->

- Scope: `builder-image`
- Enforcement mode: **enforced**
- Hash: sha256 of the exact `policy.json` bytes, published as `policy.json.sha256` and as the release asset digest. This file cannot contain its own hash.

Enforcing policy for the Alpine/musl builder image (ghcr.io/patrickryankenneth/python-wheels-builder-alpine). The release workflow loads this file, checks its sha256, runs one verifier function per enforced rule, and refuses to produce a release if any fails. Declared rules are trust roots: evidence is recorded and nothing is verified. Changing a promise means publishing a new version.

## Rules

### IMG-1 - Built by the named workflow from main at the tagged commit

- Status: `enforced`
- Check: `check_image_attested`
- Implemented by: build-environment-image.yml + GitHub build-provenance attestation; verify_builder_policy.py

For both architectures, the image digest has a GitHub attestation produced by the named workflow, from refs/heads/main, at exactly the commit the release tag points to, and builder-inputs.json records that same commit as source_commit.

Parameters:

```json
{
  "image": "ghcr.io/patrickryankenneth/python-wheels-builder-alpine",
  "repo": "patrickryankenneth/python-wheels-builder",
  "signer_workflow": "patrickryankenneth/python-wheels-builder/.github/workflows/build-environment-image.yml",
  "source_ref": "refs/heads/main"
}
```

### IMG-2 - The build gate ran, at this version

- Status: `enforced`
- Check: `check_gate_script_hash`
- Implemented by: Containerfile (gate runs in the build); builder-inputs.json assert_script_sha256; verify_builder_policy.py

builder-inputs.json records the sha256 of the sccache build gate script, and it equals the sha256 of that script at the tagged commit. The Containerfile runs the gate during the build and the build fails if it fails.

Parameters:

```json
{
  "script_path": "environments/alpine-3.24-musl/assert-sccache-build.sh"
}
```

### IMG-3 - Pinned crates are exact

- Status: `enforced`
- Check: `check_pinned_crates`
- Implemented by: assert-sccache-build.sh (build); verify_builder_policy.py against each SBOM

Each architecture's SBOM lists exactly these crate versions and no other version of these crates.

Parameters:

```json
{
  "crates": {
    "bytes": "1.10.1",
    "rand": "0.8.5",
    "tar": "0.4.40"
  }
}
```

### IMG-4 - No network-stack crates

- Status: `enforced`
- Check: `check_no_network_crates`
- Implemented by: assert-sccache-build.sh (build); verify_builder_policy.py against each SBOM

Neither architecture's SBOM contains any crate on this denylist. The list is the one the build gate (assert-sccache-build.sh FORBIDDEN_CRATES) rejects in the dependency tree.

Parameters:

```json
{
  "denylist": [
    "hyper-rustls",
    "opendal",
    "openssl",
    "reqwest",
    "rustls",
    "rustls-webpki"
  ]
}
```

### IMG-5 - Zero deb components

- Status: `enforced`
- Check: `check_zero_deb`
- Implemented by: verify_builder_policy.py against each SBOM

Neither architecture's SBOM contains a deb component.

### IMG-6 - Build inputs are recorded

- Status: `enforced`
- Check: `check_inputs_recorded`
- Implemented by: build-environment-image.yml writes builder-inputs.<arch>.json; verify_builder_policy.py

For both architectures, builder-inputs.json has every required field as a non-empty string, a runner object with every runner field non-empty, and a runner.arch matching the architecture. This records the unpinned inputs; recording them does not pin them.

Parameters:

```json
{
  "required_fields": [
    "apk_lock_sha256",
    "assert_script_sha256",
    "base_image_index_digest",
    "base_image_ref",
    "base_platform",
    "base_platform_manifest_digest",
    "builder_image",
    "cargo_auditable_version",
    "requirements_builder_sha256",
    "rust_version",
    "rustup_sha256",
    "rustup_version",
    "sccache_version",
    "source_commit"
  ],
  "runner_arch": {
    "aarch64": "ARM64",
    "x86_64": "X64"
  },
  "runner_fields": [
    "arch",
    "buildx_version",
    "docker_version",
    "image_os",
    "image_version"
  ]
}
```

### IMG-7 - SBOM and VEX are present and well-formed

- Status: `enforced`
- Check: `check_sbom_and_vex`
- Implemented by: sbom-image.yml; vex/builder.openvex.json; verify_builder_policy.py

Both architectures have a non-trivial CycloneDX SBOM and an SPDX SBOM that agree on cargo and deb components. The VEX is OpenVEX with valid statuses, and the listed components are marked affected (the maintainer does not claim them unaffected).

Parameters:

```json
{
  "min_cargo_components": 1,
  "vex_must_be_affected": [
    "pkg:cargo/bytes@1.10.1"
  ]
}
```

### IMG-8 - Release tag is annotated and signed by the named identity

- Status: `enforced`
- Check: `check_tag_signed`
- Implemented by: gitsign; release workflow; verify_builder_policy.py

The release tag is annotated, points at the commit the image was built from, and its gitsign signature verifies against this identity and issuer.

Parameters:

```json
{
  "identity": "patrickryankenneth@gmail.com",
  "issuer": "https://github.com/login/oauth"
}
```

### IMG-9 - Workflow actions are pinned to commit SHAs

- Status: `enforced`
- Check: `check_actions_pinned`
- Implemented by: verify_builder_policy.py over .github/workflows at the tagged commit

Every non-local `uses:` in every workflow at the tagged commit is pinned to a full 40-character commit SHA (docker:// references to a sha256 digest). This replaces the legacy declared-only ACT-1.

### IMG-10 - Release carries exactly the expected assets

- Status: `enforced`
- Check: `check_release_assets`
- Implemented by: release workflow; verify_builder_policy.py on the draft release

The draft release's asset set equals this list. SHA256SUMS and its Sigstore bundle are added by the maintainer when signing, after this check, and are checked by the publish guard.

Parameters:

```json
{
  "expected_assets": [
    "builder-inputs.aarch64.json",
    "builder-inputs.x86_64.json",
    "builder.openvex.json",
    "image.digest.aarch64",
    "image.digest.x86_64",
    "sbom.aarch64.cdx.json",
    "sbom.aarch64.spdx.json",
    "sbom.x86_64.cdx.json",
    "sbom.x86_64.spdx.json"
  ]
}
```

### IMG-11 - Base image is pinned by digest

- Status: `enforced`
- Check: `check_base_image_pinned`
- Implemented by: Containerfile FROM line; builder-inputs.json; verify_builder_policy.py reads the Containerfile at the tagged commit

Every external FROM in the Containerfile at the tagged commit is pinned to a sha256 digest, and the digest it pins is the base image index digest recorded in builder-inputs.json for both architectures. Both architectures were built from the same index. This is a content-addressed input.

Parameters:

```json
{
  "containerfile_path": "environments/alpine-3.24-musl/Containerfile"
}
```

### TRU-1 - GitHub-hosted runner

- Status: `declared`
- Implemented by: GitHub-hosted runner images
- Evidence recorded, not verified: builder-inputs.json runner object (image_os, image_version, arch, docker_version, buildx_version)

The runner image is trusted, not pinned. Its identity is recorded; it is not verified against a known-good value.

### TRU-2 - Alpine APK packages

- Status: `declared`
- Implemented by: Alpine repository signatures
- Evidence recorded, not verified: apk.lock.<arch> (name+version) and the SBOM

Packages are trusted through Alpine's repository signatures. The lock records names and versions, not content hashes.

### TRU-3 - Rust toolchain archives

- Status: `declared`
- Implemented by: rustup manifest and archive verification
- Evidence recorded, not verified: exact rust and rustup versions, rustup-init sha256

Toolchain archives are trusted through rustup's own verification. They are not independently pinned by hash.

### TRU-4 - Cargo crate tarballs

- Status: `declared`
- Implemented by: registry integrity checks and cargo --locked
- Evidence recorded, not verified: exact versions in the SBOM and .deps.txt

Crate tarballs are trusted through the registry's checksums and the locked dependency graph. They are not independently pinned by hash.

## Not guaranteed

- The image is not reproducible, and apk packages, rustup archives and crate tarballs have no content-hash pins.
- The runner image is unpinned; its identity is recorded, not checked.
- An attestation shows where and how the image was built, not that its contents are free of vulnerabilities. No vulnerability scan is part of this policy.
- The VEX is the maintainer's assertion, not an independent finding.
- Enforcement happens at release time, not at pull time. Consumers must verify the attestation and this policy themselves.
- The sccache build gate covers sccache only, not other tools in the image.
- The local gh guard is a convenience for one maintainer and is not enforcement.
- The number of cargo components is recorded in the SBOM and deliberately not a rule.
- builder-inputs.json is written by the build workflow but is not itself attested or signed; the image attestation binds only the image digest. IMG-6 checks its shape, and IMG-1, IMG-2 and IMG-11 cross-check parts of it against the attestation and git, but its authenticity beyond that rests on the workflow run that produced it.
- The SBOMs and the VEX are not individually attested. They are release assets, and IMG-7 checks that they are well-formed and consistent, not who produced them.
