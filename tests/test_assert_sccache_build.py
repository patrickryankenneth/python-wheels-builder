"""Tests for the build-time gate (assert-sccache-build.sh) and its wiring.

Three layers:
  1. Gate tests: the good fixture passes; every deliberate violation is rejected
     for the intended reason.
  2. Meta tests: disable each assert_* function in turn; the suite must notice
     (some violation slips through). Every assert_* must have violation cases.
  3. Wiring tests: the Containerfile/workflow actually run the gate, in the right
     place, and the VEX file matches the pins. Real image builds are opt-in
     (pytest --integration).
"""
import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENV_DIR = ROOT / "environments" / "alpine-3.24-musl"
SCRIPT = ENV_DIR / "assert-sccache-build.sh"
CONTAINERFILE = ENV_DIR / "Containerfile"
VEX = ENV_DIR / "vex" / "builder.openvex.json"
WORKFLOW = ROOT / ".github" / "workflows" / "build-environment-image.yml"
VERSION = "0.18.0"
# Production runs the gate under Alpine busybox ash, so CI should also run:
#   TEST_SH="busybox sh" pytest tests
SH = shlex.split(os.environ.get("TEST_SH", "sh"))

GOOD_TREE = """\
sccache v0.18.0
addr2line v0.25.1
aho-corasick v1.1.5
aho-corasick v1.1.5 (*)
bytes v1.10.1
bytes v1.10.1 (*)
rand v0.8.5
tar v0.4.40
"""
GOOD_CARGO_TOML = """\
[package]
edition = "2018"
name = "sccache"
version = "0.18.0"

[[bin]]
name = "sccache-dist"
required-features = ["dist-server"]
"""
GOOD_INSTALLS = {"installs": {
    "sccache 0.18.0 (registry+https://github.com/rust-lang/crates.io-index)": {
        "version_req": "=0.18.0", "bins": ["sccache"], "features": [], "all_features": False,
        "no_default_features": True, "profile": "release", "target": "x86_64-unknown-linux-musl",
        "rustc": "rustc 1.98.1"}}}
FORBIDDEN_CRATES = ["opendal", "reqwest", "rustls", "rustls-webpki", "openssl", "hyper-rustls"]


class Fixture:
    def __init__(self, base: Path):
        self.base = base
        self.src = base / "sccache-src"
        self.bin = base / "bin"
        self.out = base / "out"
        self.cargo_home = base / "cargo"
        self.tree = base / "tree.txt"
        (self.src / "src" / "bin" / "sccache-dist").mkdir(parents=True)
        self.bin.mkdir()
        (self.src / "Cargo.toml").write_text(GOOD_CARGO_TOML)
        (self.src / "src" / "lib.rs").write_text("pub fn ok() {}\n")
        (self.src / "src" / "bin" / "sccache-dist" / "main.rs").write_text("use tar::Archive;\n")
        (self.bin / "sccache").write_text("")
        self.tree.write_text(GOOD_TREE)
        self.cargo_home.mkdir()
        (self.cargo_home / ".crates2.json").write_text(json.dumps(GOOD_INSTALLS))

    def run(self, script: Path = SCRIPT, version: str = VERSION):
        return subprocess.run(
            SH + [str(script), version, "--tree-file", str(self.tree), "--src-dir", str(self.src),
                  "--bin-dir", str(self.bin), "--out-dir", str(self.out),
                  "--cargo-home", str(self.cargo_home)],
            capture_output=True, text=True, timeout=60)


@dataclass
class Case:
    id: str
    guard: str  # the assert_* function that must catch it
    mutate: Callable[[Fixture], None]
    expect: str  # substring that must appear in stderr


def _tree(fx, old, new):
    text = fx.tree.read_text()
    assert old in text, old
    fx.tree.write_text(text.replace(old, new))


def _cargo(fx, old, new):
    text = (fx.src / "Cargo.toml").read_text()
    assert old in text, old
    (fx.src / "Cargo.toml").write_text(text.replace(old, new))


def _install(fx, **changes):
    data = json.loads((fx.cargo_home / ".crates2.json").read_text())
    rec = next(iter(data["installs"].values()))
    rec.update(changes)
    (fx.cargo_home / ".crates2.json").write_text(json.dumps(data))


def _append_src(fx, rel, line):
    p = fx.src / rel
    p.write_text(p.read_text() + line + "\n")


CASES = [
    Case("sccache-version-drift", "assert_version_matches",
         lambda fx: _cargo(fx, 'version = "0.18.0"', 'version = "0.18.1"'), "expected 0.18.0"),
    Case("tar-version-drift", "assert_pinned_crates",
         lambda fx: _tree(fx, "tar v0.4.40", "tar v0.4.41"), "review the VEX"),
    Case("bytes-version-drift", "assert_pinned_crates",
         lambda fx: _tree(fx, "bytes v1.10.1", "bytes v1.11.0"), "review the VEX"),
    Case("rand-version-drift", "assert_pinned_crates",
         lambda fx: _tree(fx, "rand v0.8.5", "rand v0.9.0"), "review the VEX"),
    Case("pinned-crate-missing", "assert_pinned_crates",
         lambda fx: _tree(fx, "rand v0.8.5\n", ""), "review the VEX"),
    *[Case(f"network-crate-{c}", "assert_no_network_crates",
           (lambda c: lambda fx: fx.tree.write_text(GOOD_TREE + f"{c} v1.0.0\n"))(c),
           f"dependency tree: {c}") for c in FORBIDDEN_CRATES],
    Case("dist-server-gating-removed", "assert_dist_gated",
         lambda fx: _cargo(fx, 'required-features = ["dist-server"]', ""), "no longer gated"),
    Case("tar-archive-used-outside-dist", "assert_tar_confined_to_dist",
         lambda fx: _append_src(fx, "src/lib.rs", "use tar::Archive;"), "outside sccache-dist"),
    Case("tar-archive-gone-from-dist-control", "assert_tar_confined_to_dist",
         lambda fx: (fx.src / "src/bin/sccache-dist/main.rs").write_text("fn main() {}\n"), "control:"),
    Case("thread-rng-introduced", "assert_no_thread_rng",
         lambda fx: _append_src(fx, "src/lib.rs", "let r = rand::thread_rng();"), "rand pattern found"),
    Case("thread-rng-new-api", "assert_no_thread_rng",
         lambda fx: _append_src(fx, "src/lib.rs", "let r = rand::rng();"), "rand pattern found"),
    Case("custom-logger-set", "assert_no_custom_logger",
         lambda fx: _append_src(fx, "src/lib.rs", "log::set_logger(&L).unwrap();"), "custom-logger pattern"),
    Case("custom-log-impl", "assert_no_custom_logger",
         lambda fx: _append_src(fx, "src/lib.rs", "impl log::Log for L {}"), "custom-logger pattern"),
    Case("installed-with-default-features", "assert_install_flags",
         lambda fx: _install(fx, no_default_features=False), "WITHOUT --no-default-features"),
    Case("installed-with-dist-server-feature", "assert_install_flags",
         lambda fx: _install(fx, features=["dist-server"]), "extra features"),
    Case("installed-with-all-features", "assert_install_flags",
         lambda fx: _install(fx, all_features=True), "extra features"),
    Case("dist-binary-recorded-as-installed", "assert_install_flags",
         lambda fx: _install(fx, bins=["sccache", "sccache-dist"]), "unexpected installed binaries"),
    Case("install-record-missing", "assert_install_flags",
         lambda fx: (fx.cargo_home / ".crates2.json").unlink(), "cannot read cargo install record"),
    Case("sccache-dist-binary-present", "assert_no_dist_binary",
         lambda fx: (fx.bin / "sccache-dist").write_text(""), "binary present"),
]


def script_guards() -> list[str]:
    return re.findall(r"^(assert_\w+)\(\)", SCRIPT.read_text(), flags=re.M)


# ---------- 1. gate tests ----------

def test_good_input_passes_and_records_tree(tmp_path):
    fx = Fixture(tmp_path)
    r = fx.run()
    assert r.returncode == 0, r.stderr
    assert "sccache build assertions passed" in r.stdout
    assert (fx.out / f"sccache-{VERSION}.deps.txt").read_text().startswith("addr2line")


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_violation_is_rejected_for_the_intended_reason(tmp_path, case):
    fx = Fixture(tmp_path)
    case.mutate(fx)
    r = fx.run()
    assert r.returncode != 0, "violation was NOT rejected"
    assert case.expect in r.stderr, r.stderr


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_restoring_the_condition_passes_again(tmp_path, case):
    fx = Fixture(tmp_path)
    case.mutate(fx)
    assert fx.run().returncode != 0
    shutil.rmtree(fx.base)
    assert Fixture(fx.base).run().returncode == 0


# ---------- 2. meta tests: removing an assertion must be noticed ----------

def test_every_assert_function_has_violation_cases():
    assert set(script_guards()) == {c.guard for c in CASES}, \
        "an assert_* function has no violation case (or a case names a missing function)"


def test_script_ends_with_main_call():
    assert SCRIPT.read_text().rstrip("\n").splitlines()[-1] == "main"


@pytest.mark.parametrize("guard", sorted({c.guard for c in CASES}))
def test_disabling_a_guard_lets_a_violation_through(tmp_path, guard):
    """If someone deletes or neuters an assert_*, a violation test above starts
    failing. Prove it: neuter the guard and require that its violation slips through."""
    lines = SCRIPT.read_text().rstrip("\n").splitlines()
    mutant = tmp_path / "mutant.sh"
    mutant.write_text("\n".join(lines[:-1] + [f"{guard}() {{ return 0; }}", "main"]) + "\n")
    slipped = []
    for i, case in enumerate(c for c in CASES if c.guard == guard):
        fx = Fixture(tmp_path / f"case{i}")
        case.mutate(fx)
        if fx.run(script=mutant).returncode == 0:
            slipped.append(case.id)
    assert slipped, f"neutering {guard} changed nothing; its violation cases prove nothing"


# ---------- 3. wiring tests ----------

def instructions(text: str) -> list[str]:
    """Containerfile instructions with line continuations joined."""
    out, cur = [], ""
    for line in text.splitlines():
        if not cur and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if line.rstrip().endswith("\\"):
            cur += line.rstrip()[:-1] + " "
            continue
        out.append((cur + line).strip())
        cur = ""
    return out


COPY_LINE = "COPY assert-sccache-build.sh /tmp/assert-sccache-build.sh"
GATE_CALL = 'sh /tmp/assert-sccache-build.sh "${SCCACHE_VERSION}"'


def containerfile_problems(text: str) -> list[str]:
    problems = []
    ins = instructions(text)
    copy_idx = [i for i, x in enumerate(ins) if x == COPY_LINE]
    installs = [i for i, x in enumerate(ins) if x.startswith("RUN") and "cargo auditable install sccache" in x]
    if not copy_idx:
        problems.append("script is not COPY'd into the image build")
    if len(installs) != 1:
        problems.append("expected exactly one RUN that installs sccache")
    else:
        run = ins[installs[0]]
        if copy_idx and copy_idx[0] > installs[0]:
            problems.append("script is COPY'd after the sccache install")
        inst = run.find("cargo auditable install sccache")
        gate = run.find(GATE_CALL)
        rm = run.find("/opt/cargo/registry")
        # The gate must run in the SAME RUN (layer) as the install, so the crate
        # sources, cargo's install record and the binaries it inspects exist.
        if gate == -1:
            problems.append("gate is not run in the same RUN as the sccache install")
        else:
            if gate < inst:
                problems.append("gate runs before sccache is installed")
            if rm == -1 or gate > rm:
                problems.append("gate runs after the cargo registry is deleted")
        cmd = re.search(r"cargo auditable install sccache[^;]*", run).group(0)
        if "--no-default-features" not in cmd:
            problems.append("sccache install lacks --no-default-features")
        if "--features" in cmd or "--all-features" in cmd:
            problems.append("sccache install enables extra features")
        if "--locked" not in cmd:
            problems.append("sccache install lacks --locked")
    if not re.search(r"^\s*SCCACHE_MAX_FRAME_LENGTH=\d+", text, flags=re.M):
        problems.append("SCCACHE_MAX_FRAME_LENGTH not set in ENV")
    return problems


def test_containerfile_wires_the_gate():
    assert containerfile_problems(CONTAINERFILE.read_text()) == []


def _move_gate_to_own_layer(t):
    t = t.replace('    ' + GATE_CALL + '; \\\n', "")
    return t.replace("ENV RUSTC_WRAPPER", "RUN " + GATE_CALL + "\nENV RUSTC_WRAPPER", 1)


@pytest.mark.parametrize("name,mutate", [
    ("copy-removed", lambda t: t.replace(COPY_LINE + "\n", "")),
    ("gate-call-removed", lambda t: t.replace('    ' + GATE_CALL + '; \\\n', "")),
    ("gate-moved-to-another-layer", _move_gate_to_own_layer),
    ("frame-env-removed", lambda t: re.sub(r"^\s*SCCACHE_MAX_FRAME_LENGTH=\d+ \\\n", "", t, flags=re.M)),
    ("gate-after-registry-delete", lambda t: t.replace('    ' + GATE_CALL + '; \\\n', "").replace(
        "    sccache --version", '    ' + GATE_CALL + '; \\\n    sccache --version')),
    ("no-default-features-removed", lambda t: t.replace(" --no-default-features", "")),
    ("extra-feature-added", lambda t: t.replace("--no-default-features", "--no-default-features --features dist-server")),
    ("locked-removed", lambda t: t.replace('"${SCCACHE_VERSION}" --locked', '"${SCCACHE_VERSION}"')),
])
def test_wiring_check_detects_breakage(name, mutate):
    text = CONTAINERFILE.read_text()
    broken = mutate(text)
    assert broken != text, "mutation did not change the Containerfile"
    assert containerfile_problems(broken), name


def test_ci_rebuilds_when_the_script_changes():
    wf = WORKFLOW.read_text()
    full = "environments/alpine-3.24-musl/assert-sccache-build.sh"
    paths_block = wf.split("paths:", 1)[1].split("workflow_dispatch", 1)[0]
    assert full in paths_block, "script missing from on.push.paths"
    assert re.search(r"hashFiles\([^)]*" + re.escape(full), wf), "script missing from the recipe tag hash"
    assert '$CONTEXT/assert-sccache-build.sh' in wf, "script hash not recorded in builder-inputs"


# ---------- VEX <-> pins, both directions ----------

def script_pins() -> dict[str, str]:
    block = re.search(r"PINNED_CRATES='([^']*)'", SCRIPT.read_text()).group(1)
    return dict(line.split() for line in block.split("\n"))


def vex_problems(vex_text: str, pins: dict[str, str]) -> list[str]:
    problems = []
    for name, ver in pins.items():
        found = set(re.findall(rf"\b{re.escape(name)}@([0-9][\w.+-]*)", vex_text))
        if ver not in found:
            problems.append(f"VEX has no statement for {name}@{ver}")
        for stale in sorted(found - {ver}):
            problems.append(f"VEX mentions {name}@{stale} but the pin is {ver}")
    return problems


def test_vex_matches_pins_exactly():
    assert vex_problems(VEX.read_text(), script_pins()) == []


def test_vex_check_detects_missing_stale_and_wrong_versions():
    pins = {"tar": "0.4.40", "bytes": "1.10.1"}
    good = '"pkg:cargo/tar@0.4.40" "pkg:cargo/bytes@1.10.1"'
    assert vex_problems(good, pins) == []
    assert vex_problems('"pkg:cargo/tar@0.4.40"', pins)                         # missing
    assert vex_problems(good + ' "pkg:cargo/bytes@1.9.0"', pins)                # stale extra
    assert vex_problems('"pkg:cargo/tar@0.4.39" "pkg:cargo/bytes@1.10.1"', pins)  # wrong
    assert vex_problems(good + ' "pkg:cargo/rand_core@0.6.4"', pins) == []      # other crates ignored


# ---------- integration (pytest --integration): the real Containerfile, real builds ----------

def _build(ctx: Path, tag: str):
    return subprocess.run(["podman", "build", "-f", "Containerfile", "-t", tag, "."],
                          cwd=ctx, capture_output=True, text=True)


def _mutated_context(tmp_path: Path, file: str, old: str, new: str) -> Path:
    ctx = tmp_path / "ctx"
    shutil.copytree(ENV_DIR, ctx)
    f = ctx / file
    text = f.read_text()
    assert old in text, old
    f.write_text(text.replace(old, new))
    return ctx


@pytest.mark.integration
def test_real_build_passes_the_gate():
    r = _build(ENV_DIR, "builder:pytest")
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    assert "sccache build assertions passed" in r.stdout + r.stderr


@pytest.mark.integration
@pytest.mark.parametrize("name,file,old,new", [
    ("pin-drift", "assert-sccache-build.sh", "bytes 1.10.1", "bytes 9.9.9"),
    ("default-features-enabled", "Containerfile", " --locked --no-default-features;", " --locked;"),
    ("dist-server-enabled", "Containerfile", "--locked --no-default-features;",
     "--locked --no-default-features --features dist-server;"),
])
def test_real_build_fails_at_the_gate(tmp_path, name, file, old, new):
    """Each of these is a real change to the real build; it must stop at ASSERT FAIL
    (not at some unrelated compile error, and not later at the legacy grep guard)."""
    r = _build(_mutated_context(tmp_path, file, old, new), f"builder:pytest-{name}")
    out = r.stdout + r.stderr
    assert r.returncode != 0, "mutated build SUCCEEDED"
    assert "ASSERT FAIL" in out, out[-3000:]