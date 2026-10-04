import copy, hashlib, importlib.util, json
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("vbp", ROOT / ".github/scripts/verify_builder_policy.py")
v = importlib.util.module_from_spec(spec); spec.loader.exec_module(v)
POLICY = json.loads((ROOT / "policy/builder-image/policy.json").read_text())
RULES = {r["id"]: r for r in POLICY["rules"] if r["status"] == "enforced"}
SHA = "a" * 40
SCRIPT = b"#!/bin/sh\necho gate\n"


def P(rid): return RULES[rid].get("parameters", {})


class FakeRun:
    """by_key maps (image digest, predicate type) -> the predicate gh would return."""
    def __init__(self, fail=(), by_key=None):
        self.fail, self.calls, self.by_key = fail, [], by_key or {}
        self.tagger = "tagger Patrick <patrickryankenneth@gmail.com> 1 +0000"
        self.verified = "true valid"
    def __call__(self, argv):
        self.calls.append(argv)
        if any(argv[:len(f)] == list(f) for f in self.fail): return 1, ""
        if argv[:2] == ["gh", "attestation"] and "--format" in argv:
            dg = next(x for x in argv if x.startswith("oci://")).rpartition("@")[2]
            p = self.by_key.get((dg, argv[argv.index("--predicate-type") + 1]))
            return 0, json.dumps([] if p is None else [{"verificationResult": {"statement": {"predicate": p}}}])
        if argv[:3] == ["git", "cat-file", "tag"]: return 0, "object x\ntype commit\n" + self.tagger + "\n"
        if argv[:2] == ["git", "cat-file"]: return 0, "tag\n"
        if argv[:2] == ["gh", "api"]: return 0, self.verified + "\n"
        if argv[:2] == ["git", "rev-parse"]: return 0, SHA + "\n"
        return 0, ""


def sbom():
    crates = dict(P("IMG-3")["crates"]); crates["serde"] = "1.0.0"
    return {"components": [{"purl": f"pkg:cargo/{n}@{x}"} for n, x in crates.items()]}


def inputs(a):
    d = {f: "x" for f in P("IMG-6")["required_fields"]}
    d.update({"source_commit": SHA, "assert_script_sha256": hashlib.sha256(SCRIPT).hexdigest(),
              "base_image_index_digest": "sha256:" + "e" * 64,
              "base_platform_manifest_digest": "sha256:" + "f" * 64,
              "base_image_ref": "docker.io/library/alpine:3.24"})
    return {**d,
            "runner": {"image_os": "ubuntu24", "image_version": "1", "arch": P("IMG-6")["runner_arch"][a],
                       "docker_version": "28", "buildx_version": "v0"}}


CONTAINERFILE = ("# base\nFROM docker.io/library/alpine:3.24@sha256:" + "e" * 64 + " AS base\n"
                 "FROM base AS final\nRUN true\n").encode()


def fake_show(path):
    return CONTAINERFILE if path.endswith("Containerfile") else SCRIPT


def good(tmp_path, run=None):
    wf = tmp_path / ".github/workflows"; wf.mkdir(parents=True)
    (wf / "a.yml").write_text(f"jobs:\n  x:\n    steps:\n      - uses: actions/checkout@{'b'*40} # v7\n      - uses: ./local\n")
    vex = {"@context": "https://openvex.dev/ns/v0.2.0",
           "statements": [{"vulnerability": {"name": "X"}, "products": [{"@id": "pkg:cargo/bytes@1.10.1"}], "status": "affected"}]}
    ins = {a: inputs(a) for a in v.ARCHES}
    digs = {"x86_64": "sha256:" + "c" * 64, "aarch64": "sha256:" + "d" * 64}
    cdx = {a: sbom() for a in v.ARCHES}
    spdx = {a: {**sbom(), "spdxVersion": "SPDX-2.3"} for a in v.ARCHES}
    run = run or FakeRun()
    t12, t13, t14 = P("IMG-12")["predicate_type"], P("IMG-13"), P("IMG-14")["predicate_type"]
    run.by_key = {}
    for a in v.ARCHES:
        run.by_key[(digs[a], t12)] = copy.deepcopy(ins[a])
        run.by_key[(digs[a], t13["cyclonedx_predicate_type"])] = copy.deepcopy(cdx[a])
        run.by_key[(digs[a], t13["spdx_predicate_type_prefix"] + "2.3")] = copy.deepcopy(spdx[a])
        run.by_key[(digs[a], t14)] = copy.deepcopy(vex)
    return v.Ctx(root=tmp_path, tag="v1", tag_sha=SHA,
                 inputs=ins, digests=digs,
                 sboms=cdx, spdx=spdx, vex=vex,
                 assets=list(P("IMG-10")["expected_assets"]),
                 run=run, git_show=fake_show)


def test_every_rule_has_a_check_and_a_bad_fixture():
    assert set(BAD) == {r["check"] for r in RULES.values()}
    assert {r["check"] for r in RULES.values()} == {n for n in dir(v) if n.startswith("check_")}


@pytest.mark.parametrize("rid", sorted(RULES))
def test_good_fixture_passes(tmp_path, rid):
    assert v.run_rule(RULES[rid], good(tmp_path)) == []


def b_attest(c): c.run = FakeRun(fail=[("gh", "attestation")])
def b_commit(c): c.inputs["x86_64"]["source_commit"] = "d" * 40
def b_gate(c): c.inputs["aarch64"]["assert_script_sha256"] = "0" * 64
def b_pins(c): c.sboms["x86_64"]["components"][0]["purl"] = "pkg:cargo/bytes@9.9.9"
def b_net(c): c.sboms["aarch64"]["components"].append({"purl": f"pkg:cargo/{P('IMG-4')['denylist'][0]}@1.0.0"})
def b_deb(c): c.sboms["x86_64"]["components"].append({"purl": "pkg:deb/debian/libc6@2.36"})
def b_inputs(c): del c.inputs["aarch64"]["runner"]["docker_version"]
def b_base(c): c.git_show = lambda p: b"FROM docker.io/library/alpine:3.24\n" if p.endswith("Containerfile") else SCRIPT
def b_base3(c):
    for a in v.ARCHES: c.inputs[a]["base_image_index_digest"] = "sha256:" + "1" * 64
def b_base4(c): c.git_show = lambda p: b"ARG B=x\nFROM $B\n" if p.endswith("Containerfile") else SCRIPT
def b_base2(c): c.inputs["aarch64"]["base_image_index_digest"] = "sha256:" + "1" * 64
def b_spdx(c): c.spdx["x86_64"]["components"].append({"purl": "pkg:cargo/extra@1.0.0"})
def b_nospdx(c): del c.spdx["aarch64"]
def b_vex(c): c.vex["statements"][0]["status"] = "not_affected"
def b_tag(c): c.run = FakeRun(fail=[("gh", "api")])
def b_tag_unverified(c): c.run.verified = "false unsigned"
def b_tagger(c): c.run.tagger = "tagger X <evil@example.com> 1 +0000"
def b_pin(c): (c.root / ".github/workflows/a.yml").write_text("      - uses: actions/checkout@v4\n")
def b_assets(c): c.assets.pop()
def K(c, arch, ptype): return (c.digests[arch], ptype)
T12 = lambda: P("IMG-12")["predicate_type"]
def b_ia_mismatch(c): c.run.by_key[K(c, "aarch64", T12())]["rust_version"] = "9.9.9"
def b_ia_none(c): c.run.by_key.pop(K(c, "x86_64", T12()))
def b_ia_nodigest(c): c.digests["x86_64"] = None
def b_ia_swapped(c):
    m, x, a = c.run.by_key, K(c, "x86_64", T12()), K(c, "aarch64", T12())
    m[x], m[a] = m[a], m[x]
def b_sb_cdx(c): c.run.by_key[K(c, "aarch64", P("IMG-13")["cyclonedx_predicate_type"])]["components"].append({"purl": "pkg:cargo/extra@1.0.0"})
def b_sb_spdx_none(c): c.run.by_key.pop(K(c, "x86_64", P("IMG-13")["spdx_predicate_type_prefix"] + "2.3"))
def b_sb_nover(c): del c.spdx["x86_64"]["spdxVersion"]
def b_sb_ver(c): c.spdx["aarch64"]["spdxVersion"] = "SPDX-2.2"
def b_sb_nospdx(c): del c.spdx["aarch64"]
def b_vx_mismatch(c): c.run.by_key[K(c, "x86_64", P("IMG-14")["predicate_type"])]["statements"][0]["status"] = "not_affected"
def b_vx_none(c): c.run.by_key.pop(K(c, "aarch64", P("IMG-14")["predicate_type"]))
def b_vx_ctx(c): c.vex = None

BAD = {"check_image_attested": [b_attest, b_commit],
       "check_inputs_attested": [b_attest, b_ia_mismatch, b_ia_none, b_ia_nodigest, b_ia_swapped],
       "check_sbom_attested": [b_attest, b_ia_nodigest, b_sb_cdx, b_sb_spdx_none, b_sb_nover, b_sb_ver, b_sb_nospdx],
       "check_vex_attested": [b_attest, b_ia_nodigest, b_vx_mismatch, b_vx_none, b_vx_ctx], "check_gate_script_hash": [b_gate],
       "check_pinned_crates": [b_pins], "check_no_network_crates": [b_net], "check_zero_deb": [b_deb],
       "check_inputs_recorded": [b_inputs], "check_base_image_pinned": [b_base, b_base2, b_base3, b_base4], "check_sbom_and_vex": [b_vex, b_spdx, b_nospdx],
       "check_tag_signed": [b_tag, b_tag_unverified, b_tagger], "check_actions_pinned": [b_pin], "check_release_assets": [b_assets]}


@pytest.mark.parametrize("check,mutator", [(k, m) for k, ms in BAD.items() for m in ms])
def test_bad_fixture_fails(tmp_path, check, mutator):
    c = good(tmp_path); mutator(c)
    rule = next(r for r in RULES.values() if r["check"] == check)
    assert v.run_rule(rule, c), f"{check} accepted {mutator.__name__}"


def test_empty_sbom_fails_closed(tmp_path):
    c = good(tmp_path); c.sboms["x86_64"] = {}
    assert v.run_rule(RULES["IMG-7"], c)


def test_missing_sbom_fails_closed(tmp_path):
    c = good(tmp_path); del c.sboms["aarch64"]
    for rid in ("IMG-3", "IMG-4", "IMG-5", "IMG-7"):
        assert v.run_rule(RULES[rid], c), rid


def test_check_that_raises_is_a_failure(tmp_path):
    c = good(tmp_path); c.inputs = None
    assert v.run_rule(RULES["IMG-6"], c)
    assert v.run_rule({"check": "check_nope"}, c)


def test_attest_uses_tag_sha_and_main(tmp_path):
    run = FakeRun(); c = good(tmp_path, run)
    v.check_image_attested(c, P("IMG-1"))
    argv = next(x for x in run.calls if x[:2] == ["gh", "attestation"])
    assert argv[argv.index("--source-digest") + 1] == SHA
    assert argv[argv.index("--source-ref") + 1] == "refs/heads/main"

def test_inputs_attestation_asks_for_the_policy_predicate(tmp_path):
    run = FakeRun(); c = good(tmp_path, run)
    assert v.check_inputs_attested(c, P("IMG-12")) == []
    argv = next(x for x in run.calls if "--predicate-type" in x)
    assert argv[argv.index("--predicate-type") + 1] == P("IMG-12")["predicate_type"]
    assert argv[argv.index("--source-digest") + 1] == SHA
    assert argv[argv.index("--source-ref") + 1] == "refs/heads/main"


def test_build_workflow_attests_the_policy_predicate_type():
    wf = (ROOT / ".github/workflows/build-environment-image.yml").read_text()
    assert P("IMG-12")["predicate_type"] in wf
    assert "predicate-path: builder-inputs." in wf


def test_release_attestations_use_tag_ref_and_release_workflow(tmp_path):
    run = FakeRun(); c = good(tmp_path, run)
    assert v.check_sbom_attested(c, P("IMG-13")) == []
    assert v.check_vex_attested(c, P("IMG-14")) == []
    calls = [x for x in run.calls if "--predicate-type" in x]
    assert len(calls) == 6   # (cdx, spdx, vex) x 2 arches
    for argv in calls:
        assert argv[argv.index("--source-ref") + 1] == "refs/tags/v1"
        assert argv[argv.index("--source-digest") + 1] == SHA
        assert argv[argv.index("--signer-workflow") + 1].endswith("/.github/workflows/release.yml")


def test_release_workflow_matches_policy():
    wf = (ROOT / ".github/workflows/release.yml").read_text()
    assert hashlib.sha256((ROOT / "policy/builder-image/policy.json").read_bytes()).hexdigest() in wf
    assert P("IMG-13")["cyclonedx_predicate_type"] != P("IMG-14")["predicate_type"]
    assert P("IMG-14")["predicate_type"] in wf
    assert "sbom-path: out/sbom.${{ matrix.arch }}.cdx.json" in wf
    assert "sbom-path: out/sbom.${{ matrix.arch }}.spdx.json" in wf


def test_repo_workflows_are_pinned():
    import types
    assert v.check_actions_pinned(types.SimpleNamespace(root=ROOT), {}) == []