# Policy builder-image v2.1

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
- Implemented by: release.yml (Syft SBOMs); environments/alpine-3.24-musl/vex/builder.openvex.json; verify_builder_policy.py

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

### IMG-8 - Release tag is annotated, signed, and GitHub-verified

- Status: `enforced`
- Check: `check_tag_signed`
- Implemented by: GPG-signed tag; release workflow; verify_builder_policy.py (GitHub verification API)

The release tag is annotated, points at the commit the image was built from, names this identity as tagger, and GitHub reports its signature as verified (reason valid). The signing key is not pinned: GitHub verifies against a key registered to the tagger's account.

Parameters:

```json
{
  "identity": "patrickryankenneth@gmail.com",
  "repo": "patrickryankenneth/python-wheels-builder"
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
    "assert-image.aarch64.json",
    "assert-image.x86_64.json",
    "build-log.aarch64.txt.gz",
    "build-log.x86_64.txt.gz",
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

### IMG-12 - Build inputs are attested

- Status: `enforced`
- Check: `check_inputs_attested`
- Implemented by: build-environment-image.yml (actions/attest, custom predicate on the image digest); verify_builder_policy.py

For both architectures, the image digest has a second GitHub attestation of the named predicate type, produced by the named workflow from refs/heads/main at exactly the commit the release tag points to, and its predicate is identical to the builder-inputs.json released for that architecture. This binds the recorded inputs to the build that produced the image; it does not make the unpinned inputs trustworthy.

Parameters:

```json
{
  "image": "ghcr.io/patrickryankenneth/python-wheels-builder-alpine",
  "predicate_type": "https://github.com/patrickryankenneth/python-wheels-builder/predicate/builder-inputs/v1",
  "repo": "patrickryankenneth/python-wheels-builder",
  "signer_workflow": "patrickryankenneth/python-wheels-builder/.github/workflows/build-environment-image.yml",
  "source_ref": "refs/heads/main"
}
```

### IMG-13 - SBOMs are attested

- Status: `enforced`
- Check: `check_sbom_attested`
- Implemented by: release.yml (actions/attest sbom-path on the image digest); verify_builder_policy.py

For both architectures, the image digest has GitHub attestations for a CycloneDX and an SPDX SBOM, produced by the named workflow from the release tag at exactly the commit the tag points to, and each attested predicate is identical to the SBOM released for that architecture. This shows which workflow produced the SBOMs from the image digest; it does not show that they are complete.

Parameters:

```json
{
  "cyclonedx_predicate_type": "https://cyclonedx.org/bom",
  "image": "ghcr.io/patrickryankenneth/python-wheels-builder-alpine",
  "repo": "patrickryankenneth/python-wheels-builder",
  "signer_workflow": "patrickryankenneth/python-wheels-builder/.github/workflows/release.yml",
  "source_ref_template": "refs/tags/{tag}",
  "spdx_predicate_type_prefix": "https://spdx.dev/Document/v"
}
```

### IMG-14 - VEX is attested

- Status: `enforced`
- Check: `check_vex_attested`
- Implemented by: release.yml (actions/attest custom OpenVEX predicate on the image digest); verify_builder_policy.py

For both architectures, the image digest has a GitHub attestation of the OpenVEX predicate type, produced by the named workflow from the release tag at exactly the commit the tag points to, and its predicate is identical to the released builder.openvex.json. This shows which workflow and commit published the VEX, not that its statements are true.

Parameters:

```json
{
  "image": "ghcr.io/patrickryankenneth/python-wheels-builder-alpine",
  "predicate_type": "https://openvex.dev/ns/v0.2.0",
  "repo": "patrickryankenneth/python-wheels-builder",
  "signer_workflow": "patrickryankenneth/python-wheels-builder/.github/workflows/release.yml",
  "source_ref_template": "refs/tags/{tag}"
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

### IMG-15 - Image assertions ran and passed

- Status: `enforced`
- Check: `check_assert_image_passed`
- Implemented by: release.yml runs .github/scripts/assert-image.sh on each image digest before attesting and records the results in assert-image.<arch>.json; verify_builder_policy.py

For both architectures, assert-image.<arch>.json names this image digest, the tagged commit and the sha256 of the released CycloneDX SBOM, lists exactly the required checks, and every check is PASS. The checks are the ones assert-image.sh runs against the image and its SBOM, including the facts the VEX statements rely on.

Parameters:

```json
{
  "image": "ghcr.io/patrickryankenneth/python-wheels-builder-alpine",
  "required_checks": [
    "control: sccache binary exists in image",
    "no sccache-dist binary",
    "control: SBOM has >=100 cargo components",
    "no network-stack crates in SBOM",
    "pinned tar@0.4.40 present",
    "pinned bytes@1.10.1 present",
    "pinned rand@0.8.5 present",
    "SCCACHE_MAX_FRAME_LENGTH set in image",
    "server seen on loopback; no other listeners"
  ]
}
```

### IMG-16 - Image assertion results are attested

- Status: `enforced`
- Check: `check_assert_attested`
- Implemented by: release.yml (actions/attest, custom predicate on the image digest); verify_builder_policy.py

For both architectures, the image digest has a GitHub attestation of the assert-image predicate type, produced by the named workflow from the release tag at exactly the commit the tag points to, and its predicate is identical to the released assert-image.<arch>.json. This shows which workflow and commit produced the results, not that the checks are sufficient.

Parameters:

```json
{
  "image": "ghcr.io/patrickryankenneth/python-wheels-builder-alpine",
  "predicate_type": "https://github.com/patrickryankenneth/python-wheels-builder/predicate/assert-image/v1",
  "repo": "patrickryankenneth/python-wheels-builder",
  "signer_workflow": "patrickryankenneth/python-wheels-builder/.github/workflows/release.yml",
  "source_ref_template": "refs/tags/{tag}"
}
```

### IMG-17 - Build log is attested

- Status: `enforced`
- Check: `check_build_log_attested`
- Implemented by: build-environment-image.yml (build log, actions/attest with the log file as subject); verify_builder_policy.py

For both architectures, the release carries build-log.<arch>.txt.gz, a non-empty gzip that mentions the image digest, and the file itself has a GitHub attestation from the named workflow, from refs/heads/main, at exactly the commit the release tag points to. The log is what the build workflow printed; it lets the build be inspected after Actions logs expire.

Parameters:

```json
{
  "image": "ghcr.io/patrickryankenneth/python-wheels-builder-alpine",
  "repo": "patrickryankenneth/python-wheels-builder",
  "signer_workflow": "patrickryankenneth/python-wheels-builder/.github/workflows/build-environment-image.yml",
  "source_ref": "refs/heads/main"
}
```

## Not guaranteed

- The image is not reproducible, and apk packages, rustup archives and crate tarballs have no content-hash pins.
- The runner image is unpinned; its identity is recorded, not checked.
- An attestation shows where and how the image was built, not that its contents are free of vulnerabilities. No vulnerability scan is part of this policy.
- The VEX is the maintainer's assertion, not an independent finding.
- Enforcement happens at release time, not at pull time. Consumers must verify the attestation and this policy themselves.
- The sccache build gate covers sccache only, not other tools in the image.
- The local gh guard is a convenience for one maintainer and is not enforcement.
- The number of cargo components is recorded in the SBOM and deliberately not a rule.
- builder-inputs.json is attested (IMG-12) as produced by the build workflow, but it is the workflow's own record of what ran. The unpinned inputs it records (runner, APK packages, rustup archives, crate tarballs) are recorded, not verified.
- The SBOMs and the VEX are attested (IMG-13, IMG-14) as produced by release.yml at the release tag. That shows who produced them, not that they are correct: the SBOMs record what Syft found in the image, and the VEX remains the maintainer's assertion.
- The assert-image results show that the listed checks passed on the image and its SBOM at release time. They check those properties only and are not a security review of the image.
- The build log is the build workflow's own output, attested as produced by that workflow. It is evidence for later inspection, not an independent record, and it is not a complete log of the release workflow run.
