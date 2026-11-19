#!/usr/bin/env bash
# Run a private OCI registry on the box: HTTPS with a lab CA, bound to 127.0.0.1 only.
#   ./registry.sh up | down | status | reset
#   reset = remove the registry, its data volume and its certificate, then start fresh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/common.sh"

up() {
  ensure_registry_tls
  if docker ps --format '{{.Names}}' | grep -qx "$REGISTRY_NAME"; then
    echo "$REGISTRY_NAME already running"
    return
  fi
  docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$REGISTRY_NAME" --restart unless-stopped \
    -p 127.0.0.1:5000:5000 \
    -v kbx-registry-data:/var/lib/registry \
    -v "$TLS_DIR:/certs:ro" \
    -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry.crt \
    -e REGISTRY_HTTP_TLS_KEY=/certs/registry.key \
    "$REGISTRY_IMAGE" >/dev/null
  for _ in $(seq 1 20); do
    curl -fsS --cacert "$REGISTRY_CA" "https://$REGISTRY_HOST/v2/" >/dev/null 2>&1 && break
    sleep 0.5
  done
  # If the kind cluster from project 05 exists, keep the registry on its network.
  docker network inspect kind >/dev/null 2>&1 && docker network connect kind "$REGISTRY_NAME" 2>/dev/null || true
  echo "$REGISTRY_NAME running at https://$REGISTRY_HOST (CA: $REGISTRY_CA)"
}

case "${1:-up}" in
  up)     up ;;
  down)   docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 && echo "$REGISTRY_NAME removed (data kept in volume kbx-registry-data)" ;;
  status) curl -fsS --cacert "$REGISTRY_CA" "https://$REGISTRY_HOST/v2/_catalog" | jq . ;;
  reset)
    docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
    docker volume rm kbx-registry-data >/dev/null 2>&1 || true
    rm -rf "$TLS_DIR"
    up ;;
  *)      echo "usage: $0 up|down|status|reset" >&2; exit 2 ;;
esac
