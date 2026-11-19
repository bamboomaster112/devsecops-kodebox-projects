#!/usr/bin/env bash
# Start our own Falco in a container, loading ONLY rules/kbx_rules.yaml.
#
#   ./falco-up.sh          # start (or restart)
#   ./falco-up.sh stop
#
# KodeKloud runs its own Falco on this box (falco-modern-bpf.service) to guard the
# platform. This lab never touches that service or /etc/falco: it runs a second,
# independent Falco instance in Docker with the modern eBPF probe.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME=kbx-falco
FALCO_IMAGE="${FALCO_IMAGE:-falcosecurity/falco:0.45.2}"

if [[ "${1:-}" == "stop" ]]; then
  docker rm -f "$NAME" >/dev/null 2>&1 && echo "$NAME stopped"; exit 0
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
# Our rules file is mounted over the image's default ruleset, so this Falco loads
# nothing else and only alerts on the lab's target container.
docker run -d --name "$NAME" \
  --privileged --pid=host \
  -v /var/run/docker.sock:/host/var/run/docker.sock:ro \
  -v /proc:/host/proc:ro \
  -v "$HERE/rules/kbx_rules.yaml:/etc/falco/falco_rules.yaml:ro" \
  "$FALCO_IMAGE" \
  falco -o engine.kind=modern_ebpf -o json_output=true -o priority=notice >/dev/null

printf 'Waiting for Falco to load its rules'
for _ in $(seq 1 60); do
  if docker logs "$NAME" 2>&1 | grep -qiE 'starting .*engine|opening .*modern'; then echo " ready"; break; fi
  printf '.'; sleep 1
done
docker logs "$NAME" 2>&1 | grep -iE 'loading rules|rules file|modern|error' | head -5 | sed 's/^/    /'
