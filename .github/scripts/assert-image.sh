#!/bin/sh
# usage: assert-image.sh <image> <cyclonedx-sbom.json>
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
IMG="$1"; SBOM="$2"; fail=0
check() { d=$1; shift; if "$@"; then echo "PASS  $d"; else echo "FAIL  $d"; fail=1; fi; }
count_purl() { jq --arg p "$1" '[.components[]|select((.purl//"")|startswith($p))]|length' "$SBOM"; }

have_sccache()  { podman run --rm --entrypoint sh "$IMG" -c 'test -x /opt/cargo/bin/sccache'; }
no_dist_bin()   { ! podman run --rm --entrypoint sh "$IMG" -c 'test -e /opt/cargo/bin/sccache-dist'; }
sbom_has_cargo(){ [ "$(count_purl pkg:cargo/)" -ge 100 ]; }
no_netstack()   { for c in opendal reqwest rustls openssl hyper-rustls; do [ "$(count_purl "pkg:cargo/$c")" = 0 ] || return 1; done; }
pinned()        { [ "$(count_purl "pkg:cargo/$1")" -ge 1 ]; }
frame_env()     { podman image inspect "$IMG" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -q '^SCCACHE_MAX_FRAME_LENGTH='; }
listen_ok()     { podman run --rm -v "$HERE/listen-check.sh:/listen-check.sh:ro" --entrypoint sh "$IMG" /listen-check.sh; }

check "control: sccache binary exists in image"           have_sccache
check "no sccache-dist binary"                            no_dist_bin
check "control: SBOM has >=100 cargo components"          sbom_has_cargo
check "no network-stack crates in SBOM"                   no_netstack
check "pinned tar@0.4.40 present"                         pinned tar@0.4.40
check "pinned bytes@1.10.1 present"                       pinned bytes@1.10.1
check "pinned rand@0.8.5 present"                         pinned rand@0.8.5
check "SCCACHE_MAX_FRAME_LENGTH set in image"             frame_env
check "server seen on loopback; no other listeners"       listen_ok
exit $fail
