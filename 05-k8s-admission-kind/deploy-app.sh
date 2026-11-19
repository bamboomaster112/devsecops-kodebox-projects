#!/usr/bin/env bash
# Deploy the signed sample app, pinned to the digest project 03 signed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
source "$ROOT/03-sbom-and-signing/common.sh"

host_ref="$(digest_ref "$REGISTRY_HOST/kbx/sample-app:1.0.0")"     # localhost:5000/...@sha256:...
digest="${host_ref#*@}"
image="kbx-registry:5000/kbx/sample-app:1.0.0@${digest}"
step "Deploying $image"
sed -E "s#kbx-registry:5000/kbx/sample-app:1\.0\.0@sha256:[0-9a-f]{64}#${image}#" "$HERE/manifests/allowed/app.yaml" \
  | kubectl apply -f -
kubectl -n kbx-apps rollout status deploy/kbx-app --timeout=120s
kubectl -n kbx-apps get pods -o custom-columns='POD:.metadata.name,STATUS:.status.phase,IMAGE:.spec.containers[0].image' | cut -c1-140
step "curl http://127.0.0.1:30080/"
for _ in $(seq 1 20); do curl -fsS http://127.0.0.1:30080/ && break; sleep 1; done
