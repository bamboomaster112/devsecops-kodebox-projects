#!/usr/bin/env bash
# Run the hardened app, act like an intruder inside it, and check our Falco saw each step.
#
#   ./simulate.sh
#
# Every action is harmless (reading a file, copying ls, one HTTPS connection) and runs
# only inside the throwaway kbx-target container.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
TARGET=kbx-target
IMAGE="${TARGET_IMAGE:-sample-app:after}"

docker ps --format '{{.Names}}' | grep -qx kbx-falco || { echo "Run ./falco-up.sh first" >&2; exit 1; }
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Building $IMAGE from project 01"
  docker build -q -t "$IMAGE" "$ROOT/01-image-hardening/hardened" >/dev/null
fi

docker rm -f "$TARGET" >/dev/null 2>&1 || true
docker run -d --name "$TARGET" -p 127.0.0.1:18000:8000 "$IMAGE" >/dev/null
for _ in $(seq 1 20); do curl -fsS -o /dev/null http://127.0.0.1:18000/healthz && break; sleep 0.5; done
echo "Target app is up: $(curl -fsS http://127.0.0.1:18000/)"
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sleep 1

act() { printf '\033[1;36m--> %s\033[0m\n' "$1"; shift; "$@" >/dev/null 2>&1 || true; sleep 1; }
act "1. Open a shell in the app container"            docker exec "$TARGET" sh -c 'id'
act "2. Read /etc/shadow (as root, like after an escalation)" docker exec --user 0 "$TARGET" cat /etc/shadow
act "3. Run the package manager at runtime"           docker exec "$TARGET" apt-get --version
act "4. Write into /usr/local/bin"                     docker exec --user 0 "$TARGET" touch /usr/local/bin/kbx-implant
act "5. Drop a binary and run it"                      docker exec --user 0 "$TARGET" cp /bin/ls /tmp/kbx-dropped
docker exec "$TARGET" /tmp/kbx-dropped /tmp >/dev/null 2>&1 || true; sleep 1
act "6. Call out to the internet from the app"        docker exec "$TARGET" python -c \
  "import socket; socket.create_connection(('1.1.1.1', 443), timeout=3).close()"
sleep 3

alerts="$(docker logs kbx-falco --since "$since" 2>&1 | grep '^{' || true)"
echo
echo "Alerts raised by kbx-falco:"
jq -r '"    \(.priority | ascii_upcase | .[0:8])  \(.rule)"' <<<"$alerts" | sort | uniq -c | sed 's/^ */  /'

printf '\n\033[1m%-6s %s\033[0m\n' RESULT "EXPECTED RULE"
fails=0
for rule in "KBX Shell Spawned In App Container" "KBX Sensitive File Read In App Container" \
            "KBX Package Manager In App Container" "KBX Write Below Binary Dir In App Container" \
            "KBX Executable Not In Image" "KBX Unexpected Outbound Connection From App Container"; do
  if jq -e --arg r "$rule" 'select(.rule == $r)' <<<"$alerts" >/dev/null 2>&1; then s=PASS; else s=FAIL; fails=$((fails+1)); fi
  printf '%-6s %s\n' "$s" "$rule"
done
echo
echo "One full alert, as JSON (what you would ship to a SIEM):"
jq -c 'select(.rule == "KBX Sensitive File Read In App Container") | {time, priority, rule, output_fields}' <<<"$alerts" | head -1
docker rm -f "$TARGET" >/dev/null
exit "$fails"
