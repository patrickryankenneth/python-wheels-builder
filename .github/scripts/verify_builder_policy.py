#!/usr/bin/env python3
"""
verify_builder_policy.py - checks a builder-image release against policy.json.

Every enforced rule in the policy names one `check_*` function here
(policy_tool.py lint keeps the two in sync in both directions). A check
takes (ctx, params) and returns a list of failure strings; empty means pass.
`params` is the rule's `parameters` object from the policy, so the numbers
and lists the policy publishes are the ones enforced.

Fail closed: a check that raises, a missing input, or an unknown check name
is a failure, never a skip.

Inputs (all on disk). --artifacts-dir is the download of the SBOM workflow run;
it holds one `sbom-<arch>/` directory per architecture containing
  builder-inputs.<arch>.json, image.digest.<arch>,
  sbom.<arch>.cdx.json (CycloneDX) and sbom.<arch>.spdx.json (SPDX).
  --vex         the OpenVEX file (vex/builder.openvex.json)
  --assets-file newline-separated names of the draft release's assets (IMG-10)
  --tag / --tag-sha  the release tag and the commit it must point at
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ARCHES = ("x86_64", "aarch64")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^\s'\"#]+)")


class Ctx:
    def __init__(self, *, root, tag, tag_sha, inputs, digests, sboms, vex,
                 spdx=None, assets=None, run=None, git_show=None):
        self.root = Path(root)
        self.tag = tag
        self.tag_sha = tag_sha
        self.inputs = inputs      # arch -> builder-inputs dict
        self.digests = digests    # arch -> "sha256:..."
        self.sboms = sboms        # arch -> parsed CycloneDX SBOM (primary)
        self.spdx = spdx or {}    # arch -> parsed SPDX SBOM (must agree with CycloneDX)
        self.vex = vex            # parsed OpenVEX
        self.assets = assets      # list[str] | None
        self.run = run or _run
        self.git_show = git_show or _git_show(self.root, tag_sha, self.run)


def _run(argv):
    r = subprocess.run(argv, text=True, capture_output=True)
    return r.returncode, r.stdout


def _git_show(root, sha, _run_unused):
    def show(path):
        r = subprocess.run(["git", "-C", str(root), "show", f"{sha}:{path}"], capture_output=True)
        if r.returncode != 0:
            raise RuntimeError(f"git show {sha}:{path} failed")
        return r.stdout
    return show


# ---------- SBOM helpers ----------

def _walk(o):
    if isinstance(o, dict):
        p = o.get("purl")
        if isinstance(p, str):
            yield p
        if o.get("referenceType") == "purl" and isinstance(o.get("referenceLocator"), str):
            yield o["referenceLocator"]
        for v in o.values():
            yield from _walk(v)
    elif isinstance(o, list):
        for v in o:
            yield from _walk(v)


def parse_purl(p):
    """pkg:type/[namespace/]name@version[?q][#s] -> (type, name, version|None)"""
    if not p.startswith("pkg:"):
        return None
    body = re.split(r"[?#]", p[4:], maxsplit=1)[0]
    typ, _, rest = body.partition("/")
    if not rest:
        return None
    name, at, ver = rest.rpartition("@")
    if not at:
        return typ, unquote(rest), None
    return typ, unquote(name), unquote(ver)


def purl_set(sbom):
    return {t for t in (parse_purl(p) for p in set(_walk(sbom))) if t}


def cargo_pairs(sbom):
    return {(n, v) for t, n, v in purl_set(sbom) if t == "cargo"}


def _per_arch(ctx, getter, label):
    out, errs = {}, []
    for a in ARCHES:
        v = getter(a)
        if v is None:
            errs.append(f"{label} missing for {a}")
        else:
            out[a] = v
    return out, errs


# ---------- checks (one per enforced rule) ----------

def check_image_attested(ctx, params):
    errs = []
    for a in ARCHES:
        d = ctx.digests.get(a)
        if not (isinstance(d, str) and DIGEST_RE.match(d)):
            errs.append(f"{a}: image digest missing or malformed: {d!r}")
            continue
        sc = (ctx.inputs.get(a) or {}).get("source_commit")
        if sc != ctx.tag_sha:
            errs.append(f"{a}: builder-inputs source_commit {sc!r} != tag commit {ctx.tag_sha}")
        rc, _ = ctx.run([
            "gh", "attestation", "verify", f"oci://{params['image']}@{d}",
            "--repo", params["repo"],
            "--signer-workflow", params["signer_workflow"],
            "--source-ref", params["source_ref"],
            "--source-digest", ctx.tag_sha,
        ])
        if rc != 0:
            errs.append(f"{a}: gh attestation verify failed for {d}")
    return errs


def _digest_ok(ctx, a, errs):
    d = ctx.digests.get(a)
    if isinstance(d, str) and DIGEST_RE.match(d):
        return d
    errs.append(f"{a}: image digest missing or malformed: {d!r}")
    return None


def _attested_predicates(ctx, a, d, params, ptype, source_ref, errs):
    """gh attestation verify the image digest for one predicate type; return the list of
    verified predicates (empty list if none), or None after recording an error."""
    rc, out = ctx.run([
        "gh", "attestation", "verify", f"oci://{params['image']}@{d}",
        "--repo", params["repo"],
        "--signer-workflow", params["signer_workflow"],
        "--source-ref", source_ref,
        "--source-digest", ctx.tag_sha,
        "--predicate-type", ptype,
        "--format", "json",
    ])
    if rc != 0:
        errs.append(f"{a}: gh attestation verify failed for {ptype} on {d}")
        return None
    try:
        results = json.loads(out)
    except ValueError:
        errs.append(f"{a}: gh attestation verify output is not JSON ({ptype})")
        return None
    preds = []
    for r in results if isinstance(results, list) else []:
        stmt = ((r or {}).get("verificationResult") or {}).get("statement") or {}
        preds.append(stmt.get("predicate"))
    if not preds:
        errs.append(f"{a}: no {ptype} attestation returned for {d}")
        return None
    return preds


def _predicate_equals(ctx, a, d, params, ptype, source_ref, doc, label, errs):
    if not isinstance(doc, dict):
        errs.append(f"{a}: released {label} missing")
        return
    preds = _attested_predicates(ctx, a, d, params, ptype, source_ref, errs)
    if preds is not None and doc not in preds:
        errs.append(f"{a}: released {label} differs from the attested predicate on {d}")


def check_inputs_attested(ctx, params):
    """builder-inputs.<arch>.json is the predicate of a verified attestation on that arch's
    image digest (named workflow, main, tagged commit, named predicate type)."""
    errs = []
    for a in ARCHES:
        d = _digest_ok(ctx, a, errs)
        if d:
            _predicate_equals(ctx, a, d, params, params["predicate_type"], params["source_ref"],
                              ctx.inputs.get(a), "builder-inputs.json", errs)
    return errs


def check_sbom_attested(ctx, params):
    """The released CycloneDX and SPDX SBOMs are the predicates of verified attestations on the
    image digest, made by the release workflow from the release tag."""
    errs = []
    sref = params["source_ref_template"].format(tag=ctx.tag)
    for a in ARCHES:
        d = _digest_ok(ctx, a, errs)
        if not d:
            continue
        cdx, spdx = ctx.sboms.get(a), ctx.spdx.get(a)
        _predicate_equals(ctx, a, d, params, params["cyclonedx_predicate_type"], sref, cdx, "CycloneDX SBOM", errs)
        ver = str((spdx or {}).get("spdxVersion", "")).partition("-")[2]
        if not ver:
            errs.append(f"{a}: SPDX SBOM missing or has no spdxVersion")
            continue
        _predicate_equals(ctx, a, d, params, params["spdx_predicate_type_prefix"] + ver, sref, spdx, "SPDX SBOM", errs)
    return errs


def check_vex_attested(ctx, params):
    """The released OpenVEX file is the predicate of a verified attestation on each image digest."""
    errs = []
    sref = params["source_ref_template"].format(tag=ctx.tag)
    for a in ARCHES:
        d = _digest_ok(ctx, a, errs)
        if d:
            _predicate_equals(ctx, a, d, params, params["predicate_type"], sref, ctx.vex, "builder.openvex.json", errs)
    return errs


def check_gate_script_hash(ctx, params):
    import hashlib
    want = hashlib.sha256(ctx.git_show(params["script_path"])).hexdigest()
    errs = []
    for a in ARCHES:
        got = (ctx.inputs.get(a) or {}).get("assert_script_sha256")
        if got != want:
            errs.append(f"{a}: assert_script_sha256 {got!r} != sha256 of {params['script_path']} at {ctx.tag_sha[:12]} ({want})")
    return errs


def check_pinned_crates(ctx, params):
    sboms, errs = _per_arch(ctx, ctx.sboms.get, "SBOM")
    for a, s in sboms.items():
        pairs = cargo_pairs(s)
        for crate, ver in params["crates"].items():
            versions = {v for n, v in pairs if n == crate}
            if ver not in versions:
                errs.append(f"{a}: {crate} {ver} not in SBOM (found {sorted(versions) or 'none'})")
            elif versions - {ver}:
                errs.append(f"{a}: {crate} also present at {sorted(versions - {ver})}")
    return errs


def check_no_network_crates(ctx, params):
    deny = set(params["denylist"])
    if not deny:
        return ["policy denylist is empty"]
    sboms, errs = _per_arch(ctx, ctx.sboms.get, "SBOM")
    for a, s in sboms.items():
        hit = sorted({n for n, _ in cargo_pairs(s)} & deny)
        if hit:
            errs.append(f"{a}: denylisted crates in SBOM: {hit}")
    return errs


def check_zero_deb(ctx, params):
    sboms, errs = _per_arch(ctx, ctx.sboms.get, "SBOM")
    for a, s in sboms.items():
        n = sum(1 for t, _, _ in purl_set(s) if t == "deb")
        if n:
            errs.append(f"{a}: {n} deb components in SBOM")
    return errs


def check_inputs_recorded(ctx, params):
    errs = []
    for a in ARCHES:
        inp = ctx.inputs.get(a)
        if not isinstance(inp, dict):
            errs.append(f"{a}: builder-inputs missing")
            continue
        for f in params["required_fields"]:
            v = inp.get(f)
            if not (isinstance(v, str) and v.strip()):
                errs.append(f"{a}: builder-inputs.{f} missing or empty")
        runner = inp.get("runner")
        if not isinstance(runner, dict):
            errs.append(f"{a}: builder-inputs.runner is not an object")
            continue
        for f in params["runner_fields"]:
            v = runner.get(f)
            if not (isinstance(v, str) and v.strip()):
                errs.append(f"{a}: runner.{f} missing or empty")
        want = params["runner_arch"].get(a)
        if runner.get("arch") != want:
            errs.append(f"{a}: runner.arch {runner.get('arch')!r} != {want!r}")
    return errs


FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE)


def check_base_image_pinned(ctx, params):
    """The Containerfile at the tagged commit pins every external FROM by digest, and the
    digest it pins is the one builder-inputs recorded for both architectures."""
    errs, recorded = [], set()
    for a in ARCHES:
        inp = ctx.inputs.get(a) or {}
        for name in ("base_image_index_digest", "base_platform_manifest_digest"):
            d = inp.get(name)
            if not (isinstance(d, str) and DIGEST_RE.match(d)):
                errs.append(f"{a}: {name} missing or not a sha256 digest: {d!r}")
        if isinstance(inp.get("base_image_index_digest"), str):
            recorded.add(inp["base_image_index_digest"])
    if len(recorded) > 1:
        errs.append(f"arches were built from different base image indexes: {sorted(recorded)}")
    text = ctx.git_show(params["containerfile_path"]).decode()
    stages, external = set(), []
    for line in text.splitlines():
        m = FROM_RE.match(line)
        if not m:
            continue
        image, alias = m.group(1), m.group(2)
        if image not in stages and image.lower() != "scratch":
            external.append(image)
        if alias:
            stages.add(alias)
    if not external:
        return errs + [f"no external FROM found in {params['containerfile_path']}"]
    pinned = set()
    for image in external:
        name, at, digest = image.partition("@")
        if "$" in image:
            errs.append(f"FROM {image} uses a variable; the pin cannot be verified")
        elif not (at and DIGEST_RE.match(digest)):
            errs.append(f"FROM {image} is not pinned by sha256 digest")
        else:
            pinned.add(digest)
            for a in ARCHES:
                ref = (ctx.inputs.get(a) or {}).get("base_image_ref")
                if ref is not None and ref not in {i.partition("@")[0] for i in external}:
                    errs.append(f"{a}: base_image_ref {ref!r} is not a FROM in the Containerfile")
    for d in recorded:
        if d not in pinned:
            errs.append(f"recorded base index digest {d} is not the digest the Containerfile pins")
    return sorted(set(errs), key=errs.index)


def check_sbom_and_vex(ctx, params):
    sboms, errs = _per_arch(ctx, ctx.sboms.get, "SBOM")
    for a, s in sboms.items():
        n = len(cargo_pairs(s))
        if n < params["min_cargo_components"]:
            errs.append(f"{a}: SBOM has {n} cargo components, need >= {params['min_cargo_components']} (empty or wrong SBOM?)")
        sp = ctx.spdx.get(a)
        if sp is None:
            errs.append(f"SPDX SBOM missing for {a}")
        else:
            keep = lambda x: {t for t in purl_set(x) if t[0] in ("cargo", "deb")}
            only_cdx, only_spdx = keep(s) - keep(sp), keep(sp) - keep(s)
            if only_cdx or only_spdx:
                errs.append(f"{a}: CycloneDX and SPDX disagree on cargo/deb components "
                            f"({len(only_cdx)} only in CycloneDX, {len(only_spdx)} only in SPDX)")
    vex = ctx.vex
    if not isinstance(vex, dict):
        return errs + ["VEX missing or not an object"]
    if not str(vex.get("@context", "")).startswith("https://openvex.dev/ns"):
        errs.append("VEX @context is not an OpenVEX namespace")
    stmts = vex.get("statements")
    if not (isinstance(stmts, list) and stmts):
        return errs + ["VEX has no statements"]
    for i, st in enumerate(stmts):
        if st.get("status") not in ("not_affected", "affected", "fixed", "under_investigation"):
            errs.append(f"VEX statement {i}: invalid status {st.get('status')!r}")
    for purl in params["vex_must_be_affected"]:
        hits = [st for st in stmts if purl in json.dumps(st)]
        if not hits:
            errs.append(f"VEX has no statement for {purl}")
        for st in hits:
            if st.get("status") != "affected":
                errs.append(f"VEX marks {purl} {st.get('status')!r}; policy requires 'affected'")
    return errs


def check_tag_signed(ctx, params):
    ref = f"refs/tags/{ctx.tag}"
    rc, out = ctx.run(["git", "cat-file", "-t", ref])
    if rc != 0 or out.strip() != "tag":
        return [f"{ctx.tag} is not an annotated tag"]
    rc, out = ctx.run(["git", "rev-parse", f"{ref}^{{commit}}"])
    if rc != 0 or out.strip() != ctx.tag_sha:
        return [f"{ctx.tag} points at {out.strip()!r}, expected {ctx.tag_sha}"]
    rc, _ = ctx.run(["gitsign", "verify-tag",
                     "--certificate-identity", params["identity"],
                     "--certificate-oidc-issuer", params["issuer"], ctx.tag])
    return [] if rc == 0 else [f"gitsign verify-tag failed for {ctx.tag} (identity {params['identity']})"]


def check_actions_pinned(ctx, params):
    errs, seen = [], 0
    wf = ctx.root / ".github" / "workflows"
    files = sorted(list(wf.glob("*.yml")) + list(wf.glob("*.yaml")))
    if not files:
        return ["no workflow files found"]
    for f in files:
        for n, line in enumerate(f.read_text().splitlines(), 1):
            m = USES_RE.match(line)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith("./"):
                continue
            seen += 1
            if ref.startswith("docker://"):
                ok = "@sha256:" in ref
            else:
                ok = bool(SHA40_RE.match(ref.rpartition("@")[2])) and "@" in ref
            if not ok:
                errs.append(f"{f.name}:{n}: not pinned to a full SHA: {ref}")
    if seen == 0:
        errs.append("found no `uses:` lines at all (parser broken?)")
    return errs


def check_release_assets(ctx, params):
    if ctx.assets is None:
        return ["asset list not provided"]
    got, want = sorted(ctx.assets), sorted(params["expected_assets"])
    if got == want:
        return []
    return [f"asset set mismatch: missing {sorted(set(want) - set(got))}, unexpected {sorted(set(got) - set(want))}"]


# ---------- driver ----------

def run_rule(rule, ctx):
    fn = globals().get(rule["check"])
    if not callable(fn):
        return [f"check {rule['check']} not found"]
    try:
        return fn(ctx, rule.get("parameters", {}))
    except Exception as e:  # fail closed
        return [f"{rule['check']} raised {type(e).__name__}: {e}"]


def load_ctx(a):
    def jload(p):
        return json.loads(Path(p).read_text()) if Path(p).exists() else None

    def f(arch, name):
        return a.artifacts_dir / f"sbom-{arch}" / name
    inputs = {x: jload(f(x, f"builder-inputs.{x}.json")) for x in ARCHES}
    digests = {}
    for x in ARCHES:
        p = f(x, f"image.digest.{x}")
        digests[x] = p.read_text().strip() if p.exists() else None
    cdx = {x: jload(f(x, f"sbom.{x}.cdx.json")) for x in ARCHES}
    spdx = {x: jload(f(x, f"sbom.{x}.spdx.json")) for x in ARCHES}
    assets = a.assets_file.read_text().split() if a.assets_file else None
    return Ctx(root=a.root, tag=a.tag, tag_sha=a.tag_sha, inputs=inputs, digests=digests,
               sboms={k: v for k, v in cdx.items() if v is not None},
               spdx={k: v for k, v in spdx.items() if v is not None},
               vex=jload(a.vex), assets=assets)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--policy", type=Path, required=True)
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--tag", required=True)
    p.add_argument("--tag-sha", required=True)
    p.add_argument("--artifacts-dir", type=Path, required=True)
    p.add_argument("--vex", type=Path, required=True)
    p.add_argument("--assets-file", type=Path)
    p.add_argument("--only", help="run a single rule id")
    a = p.parse_args()
    policy = json.loads(a.policy.read_text())
    ctx = load_ctx(a)
    failed = 0
    for rule in policy["rules"]:
        if a.only and rule["id"] != a.only:
            continue
        if rule["status"] == "declared":
            print(f"DECLARED {rule['id']}  {rule['title']} (trust root, not verified)")
            continue
        errs = run_rule(rule, ctx)
        if errs:
            failed += 1
            print(f"FAIL     {rule['id']}  {rule['title']}")
            for e in errs:
                print(f"::error::{rule['id']}: {e}")
        else:
            print(f"PASS     {rule['id']}  {rule['title']}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()