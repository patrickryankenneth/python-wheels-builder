import copy, importlib.util, json
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("policy_tool", ROOT / ".github/scripts/policy_tool.py")
pt = importlib.util.module_from_spec(spec); spec.loader.exec_module(pt)
POLICY = json.loads((ROOT / "policy/builder-image/policy.json").read_text())
VERIFIER = ROOT / ".github/scripts/verify_builder_policy.py"


def errs(p): return pt.validate(p, VERIFIER)


def test_shipped_policy_is_valid_and_canonical():
    raw = (ROOT / "policy/builder-image/policy.json").read_bytes()
    assert errs(POLICY) == [] and raw == pt.canonical(POLICY)
    md = (ROOT / "policy/builder-image/POLICY.md").read_text()
    assert md == pt.render(POLICY)


def mut(fn):
    p = copy.deepcopy(POLICY); fn(p); return p


def rule(p, rid): return next(r for r in p["rules"] if r["id"] == rid)


@pytest.mark.parametrize("name,fn", [
    ("enforced without check", lambda p: rule(p, "IMG-1").pop("check")),
    ("check names missing function", lambda p: rule(p, "IMG-1").update(check="check_nope")),
    ("declared with check", lambda p: rule(p, "TRU-1").update(check="check_zero_deb")),
    ("declared without evidence", lambda p: rule(p, "TRU-1").pop("evidence")),
    ("enforced with evidence", lambda p: rule(p, "IMG-5").update(evidence="x")),
    ("orphan verifier function", lambda p: p["rules"].remove(rule(p, "IMG-5"))),
    ("descriptive mode", lambda p: p.update(enforcement_mode="descriptive")),
    ("bad scope", lambda p: p.update(scope="Builder Image")),
    ("unknown field", lambda p: rule(p, "IMG-1").update(extra=1)),
    ("duplicate id", lambda p: rule(p, "IMG-2").update(id="IMG-1")),
    ("legacy status", lambda p: rule(p, "IMG-1").update(status="performed-at-build")),
    ("empty not_guaranteed", lambda p: p.update(not_guaranteed=[])),
])
def test_bad_policy_rejected(name, fn):
    assert errs(mut(fn)), name


def test_schema1_rejected():
    assert errs(mut(lambda p: p.update(schema=1)))


def test_tag_name():
    assert f"policy-{POLICY['scope']}-{POLICY['policy_version']}" == "policy-builder-image-v2.1"