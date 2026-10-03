#!/bin/sh
# runs inside the image: start sccache on a known port, list TCP listeners
export SCCACHE_SERVER_PORT=4777 SCCACHE_DIR=/tmp/c
sccache --start-server >/dev/null 2>&1
sleep 1
awk '$4=="0A" {print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null > /tmp/listeners
sccache --stop-server >/dev/null 2>&1
grep -q '^0100007F:12A9$' /tmp/listeners || { echo "control failed: no loopback listener on 4777 seen"; exit 2; }
if grep -v -E '^(0100007F:|00000000000000000000000001000000:)' /tmp/listeners | grep -q .; then
  echo "non-loopback listener(s):"; grep -v -E '^(0100007F:|00000000000000000000000001000000:)' /tmp/listeners; exit 1
fi
