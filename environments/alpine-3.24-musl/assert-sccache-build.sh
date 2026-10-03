#!/bin/sh
# Build-time gate for the sccache install. Runs in the same layer as the
# install, before the cargo registry is deleted. Exit non-zero => no image.
#
# The VEX statements in vex/builder.openvex.json depend on these facts:
# change a pin, review the VEX (tests/ checks the two stay in sync).
#
# Each check is its own assert_* function so tests/ can prove every one of
# them rejects a deliberate violation. The Containerfile passes only the
# version; the --*-dir/--tree-file flags exist for the tests.
set -eu

usage() {
  echo "usage: $0 <sccache-version> [--tree-file F] [--src-dir D] [--bin-dir D] [--out-dir D] [--cargo-home D]" >&2
  exit 2
}
[ $# -ge 1 ] || usage
V="$1"; shift
TREE_FILE=""; SRC_DIR=""; BIN_DIR=/opt/cargo/bin; OUT_DIR=/usr/share/builder; CARGO_HOME_DIR=/opt/cargo
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --tree-file) TREE_FILE="$2" ;;
    --src-dir)   SRC_DIR="$2" ;;
    --bin-dir)   BIN_DIR="$2" ;;
    --out-dir)   OUT_DIR="$2" ;;
    --cargo-home) CARGO_HOME_DIR="$2" ;;
    *) usage ;;
  esac
  shift 2
done

# crate version: the VEX file must mention each as <crate>@<version>.
PINNED_CRATES='tar 0.4.40
bytes 1.10.1
rand 0.8.5'
FORBIDDEN_CRATES='opendal reqwest rustls rustls-webpki openssl hyper-rustls'

fail() { echo "ASSERT FAIL: $*" >&2; exit 1; }

load_inputs() {
  if [ -n "$TREE_FILE" ]; then
    TREE=$(sort -u "$TREE_FILE")
  fi
  if [ -z "$SRC_DIR" ]; then
    SRC_DIR=$(ls -d /opt/cargo/registry/src/*/sccache-"$V" 2>/dev/null) \
      || fail "sccache $V sources not found in the cargo registry"
  fi
  [ -d "$SRC_DIR" ] || fail "source dir missing: $SRC_DIR"
  cd "$SRC_DIR"
  if [ -z "$TREE_FILE" ]; then
    TREE=$(cargo tree --locked --no-default-features -e normal --prefix none | sort -u)
  fi
  [ -n "$TREE" ] || fail "empty dependency tree"
  SRC=$(find src -name '*.rs')
  [ -n "$SRC" ] || fail "no .rs files found under src/"
}

# The dependency tree below is computed with --no-default-features. That only
# describes the real binary if the install used the same flags, so verify what
# cargo recorded for the actual install (not what the Containerfile says).
assert_install_flags() {
  msg=$(python3 - "$CARGO_HOME_DIR/.crates2.json" "$V" <<'PYEOF'
import json, sys
path, v = sys.argv[1:3]
try:
    installs = json.load(open(path))["installs"]
except Exception as e:
    print(f"cannot read cargo install record {path}: {e}")
    sys.exit(1)
keys = [k for k in installs if k.startswith(f"sccache {v} ")]
if len(keys) != 1:
    print(f"expected exactly one install record for sccache {v}, found {len(keys)}")
    sys.exit(1)
r = installs[keys[0]]
if r.get("no_default_features") is not True:
    print("sccache was installed WITHOUT --no-default-features")
    sys.exit(1)
if r.get("features") != [] or r.get("all_features") is not False:
    print(f"sccache was installed with extra features: {r.get('features')} all={r.get('all_features')}")
    sys.exit(1)
if r.get("bins") != ["sccache"]:
    print(f"unexpected installed binaries: {r.get('bins')}")
    sys.exit(1)
PYEOF
  ) || fail "install flags: $msg"
}

assert_version_matches() {
  found=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
  [ "$found" = "$V" ] || fail "Cargo.toml version is '$found', expected $V"
}

assert_no_network_crates() {
  for c in $FORBIDDEN_CRATES; do
    if echo "$TREE" | grep -q "^$c "; then fail "network-stack crate in dependency tree: $c"; fi
  done
}

assert_pinned_crates() {
  while read -r name ver; do
    [ -n "$name" ] || continue
    ver_re=$(printf '%s' "$ver" | sed 's/\./\\./g')
    echo "$TREE" | grep -Eq "^$name v$ver_re( |\$)" \
      || fail "expected $name v$ver in tree; review the VEX before changing pins"
  done <<EOF2
$PINNED_CRATES
EOF2
}

assert_tar_confined_to_dist() {
  grep -l 'tar::Archive' $SRC | grep -q '^src/bin/sccache-dist/' \
    || fail "control: expected tar::Archive in src/bin/sccache-dist"
  other=$(grep -l 'tar::Archive' $SRC | grep -v '^src/bin/sccache-dist/' || true)
  [ -z "$other" ] || fail "tar::Archive used outside sccache-dist: $other"
}

assert_dist_gated() {
  grep -q 'required-features = \["dist-server"\]' Cargo.toml \
    || fail "sccache-dist no longer gated by dist-server"
}

assert_no_thread_rng() {
  hits=$(grep -n -E 'thread_rng|rand::rng\(|ThreadRng' $SRC || true)
  [ -z "$hits" ] || fail "thread-local rand pattern found: $hits"
}

assert_no_custom_logger() {
  hits=$(grep -n -E 'set_logger|set_boxed_logger|impl[^{]*Log for' $SRC || true)
  [ -z "$hits" ] || fail "custom-logger pattern found: $hits"
}

assert_no_dist_binary() {
  [ ! -e "$BIN_DIR/sccache-dist" ] || fail "sccache-dist binary present"
}

write_deps_record() {
  mkdir -p "$OUT_DIR"
  echo "$TREE" > "$OUT_DIR/sccache-$V.deps.txt"
}

main() {
  load_inputs
  assert_install_flags
  assert_version_matches
  assert_no_network_crates
  assert_pinned_crates
  assert_tar_confined_to_dist
  assert_dist_gated
  assert_no_thread_rng
  assert_no_custom_logger
  assert_no_dist_binary
  write_deps_record
  echo "sccache build assertions passed"
}

main