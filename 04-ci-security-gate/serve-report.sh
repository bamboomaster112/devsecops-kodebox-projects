#!/usr/bin/env bash
# Publish the gate's HTML report on port 80 of the KodeBox.
#
#   ./serve-report.sh          # start (or restart) the report server
#   ./serve-report.sh stop
#
# The server itself is hardened the same way the projects teach: unprivileged nginx,
# read-only root filesystem, every Linux capability dropped, no privilege escalation,
# and the report mounted read-only.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITE="${SITE:-$HERE/out/site}"
NAME=kbx-report
IMAGE="${REPORT_IMAGE:-nginxinc/nginx-unprivileged:stable-alpine}"

if [[ "${1:-}" == "stop" ]]; then
  docker rm -f "$NAME" >/dev/null 2>&1 && echo "$NAME stopped"
  exit 0
fi
[[ -f "$SITE/index.html" ]] || { echo "No report yet: run ./gate.sh first" >&2; exit 1; }

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --restart unless-stopped \
  -p 80:8080 \
  --read-only --tmpfs /tmp:rw,size=8m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --memory 64m --pids-limit 64 \
  -v "$SITE:/usr/share/nginx/html:ro" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 20); do curl -fsS -o /dev/null http://127.0.0.1/ && break; sleep 0.5; done
ip="$(curl -fsS --max-time 5 https://checkip.amazonaws.com 2>/dev/null || echo '<box public IP>')"
echo "Report served at http://${ip}/  (port 80 is open to everyone in the KodeBox firewall;"
echo "restrict that rule to your own IP if the report should stay private)"
