#!/usr/bin/env bash
# Run a private OCI registry on the box (127.0.0.1:5000 only, not exposed to the internet).
#   ./registry.sh up | down | status
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/common.sh"

case "${1:-up}" in
  up)
    if docker ps --format '{{.Names}}' | grep -qx "$REGISTRY_NAME"; then
      echo "$REGISTRY_NAME already running"
    else
      docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
      docker run -d --name "$REGISTRY_NAME" --restart unless-stopped \
        -p 127.0.0.1:5000:5000 -v kbx-registry-data:/var/lib/registry \
        "$REGISTRY_IMAGE" >/dev/null
      for _ in $(seq 1 20); do curl -fsS "http://$REGISTRY_HOST/v2/" >/dev/null 2>&1 && break; sleep 0.5; done
      echo "$REGISTRY_NAME running at $REGISTRY_HOST"
    fi ;;
  down)   docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 && echo "$REGISTRY_NAME removed (data kept in volume kbx-registry-data)" ;;
  status) curl -fsS "http://$REGISTRY_HOST/v2/_catalog" | jq . ;;
  *)      echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac
