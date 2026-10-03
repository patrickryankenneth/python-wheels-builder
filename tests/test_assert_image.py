"""Tests for the post-build audit (.github/scripts/assert-image.sh).

podman is replaced by a stub on PATH, so these run in milliseconds. The point is
the lesson from the vacuous-SBOM bug: a negative assertion ("no reqwest") must FAIL
when reqwest is present, and a SBOM with no evidence at all must not look clean.
"""
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / ".github" / "scripts" / "assert-image.sh"
SH = shlex.split(os.environ.get("TEST_SH", "sh"))

pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="jq not installed")

PODMAN_STUB = """#!/bin/sh
case "$*" in
  *"image inspect"*)
    echo "PATH=/usr/bin"
    [ "${STUB_FRAME:-1}" = 1 ] && echo "SCCACHE_MAX_FRAME_LENGTH=8388608"
    exit 0 ;;
  *"test -e /opt/cargo/bin/sccache-dist"*) [ "${STUB_DIST:-0}" = 1 ] && exit 0; exit 1 ;;
  *"test -x /opt/cargo/bin/sccache"*)      [ "${STUB_SCCACHE:-1}" = 1 ] && exit 0; exit 1 ;;
  *"/listen-check.sh"*)                    [ "${STUB_LISTEN:-1}" = 1 ] && exit 0; exit 1 ;;
esac
exit 3
"""

PINS = ["tar@0.4.40", "bytes@1.10.1", "rand@0.8.5"]
NETWORK_CRATES = ["opendal", "reqwest", "rustls", "openssl", "hyper-rustls"]


def sbom(extra=(), drop=(), filler=120):
    purls = [f"pkg:cargo/filler{i}@1.0.0" for i in range(filler)]
    purls += [f"pkg:cargo/{p}" for p in PINS if p not in drop]
    purls += [f"pkg:cargo/{p}" for p in extra]
    return {"components": [{"type": "library", "purl": p} for p in purls]}


def run_harness(tmp_path, sbom_doc, **stub_env):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "podman"
    stub.write_text(PODMAN_STUB)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    f = tmp_path / "sbom.json"
    f.write_text(json.dumps(sbom_doc))
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", **{k: str(v) for k, v in stub_env.items()}}
    return subprocess.run(SH + [str(HARNESS), "localhost/stub:image", str(f)],
                          capture_output=True, text=True, env=env, timeout=60)


def harness_checks() -> list[str]:
    return re.findall(r'^check "([^"]+)"', HARNESS.read_text(), flags=re.M)


# (id, the check that must report FAIL, how to build the bad input)
VIOLATIONS = [
    ("sccache-binary-missing", "control: sccache binary exists in image", dict(sbom_doc=sbom(), STUB_SCCACHE=0)),
    ("dist-binary-present", "no sccache-dist binary", dict(sbom_doc=sbom(), STUB_DIST=1)),
    ("sbom-has-no-cargo-evidence", "control: SBOM has >=100 cargo components", dict(sbom_doc={"components": []})),
    ("sbom-nearly-empty", "control: SBOM has >=100 cargo components", dict(sbom_doc=sbom(filler=5))),
    *[(f"network-crate-{c}", "no network-stack crates in SBOM", dict(sbom_doc=sbom(extra=[f"{c}@1.0.0"])))
      for c in NETWORK_CRATES],
    ("tar-pin-missing", "pinned tar@0.4.40 present", dict(sbom_doc=sbom(drop=["tar@0.4.40"]))),
    ("bytes-pin-missing", "pinned bytes@1.10.1 present", dict(sbom_doc=sbom(drop=["bytes@1.10.1"]))),
    ("rand-pin-missing", "pinned rand@0.8.5 present", dict(sbom_doc=sbom(drop=["rand@0.8.5"]))),
    ("frame-env-missing", "SCCACHE_MAX_FRAME_LENGTH set in image", dict(sbom_doc=sbom(), STUB_FRAME=0)),
    ("unexpected-listener", "server seen on loopback; no other listeners", dict(sbom_doc=sbom(), STUB_LISTEN=0)),
]


def test_good_image_and_sbom_pass_every_check(tmp_path):
    r = run_harness(tmp_path, sbom())
    assert r.returncode == 0, r.stdout
    assert r.stdout.count("PASS  ") == len(harness_checks()) and "FAIL" not in r.stdout


@pytest.mark.parametrize("vid,check,kwargs", VIOLATIONS, ids=[v[0] for v in VIOLATIONS])
def test_each_violation_fails_exactly_the_intended_check(tmp_path, vid, check, kwargs):
    r = run_harness(tmp_path, **kwargs)
    assert r.returncode != 0, "violation was NOT rejected"
    assert f"FAIL  {check}" in r.stdout, r.stdout


def test_every_harness_check_has_a_violation_case():
    assert set(harness_checks()) == {v[1] for v in VIOLATIONS}


def test_empty_sbom_is_not_mistaken_for_clean(tmp_path):
    """The original bug: 'no reqwest' passes on an SBOM with no cargo components at all.
    That negative check still passes vacuously here; only the control check saves us."""
    r = run_harness(tmp_path, {"components": []})
    assert "PASS  no network-stack crates in SBOM" in r.stdout  # vacuous pass, by design
    assert "FAIL  control: SBOM has >=100 cargo components" in r.stdout
    assert r.returncode != 0