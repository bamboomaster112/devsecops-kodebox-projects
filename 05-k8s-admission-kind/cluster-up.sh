#!/usr/bin/env bash
# Create the kind cluster and wire it to the local registry from project 03.
#   ./cluster-up.sh          (safe to re-run)
#   kind delete cluster --name kbx     to remove it
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
source "$ROOT/03-sbom-and-signing/common.sh"
CLUSTER=kbx

"$ROOT/03-sbom-and-signing/registry.sh" up

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  step "kind cluster '$CLUSTER' already exists"
else
  step "Creating kind cluster '$CLUSTER' (about a minute)"
  kind create cluster --config "$HERE/kind-config.yaml" --wait 180s
fi

step "Connecting $REGISTRY_NAME to the kind network"
docker network connect kind "$REGISTRY_NAME" 2>/dev/null || echo "    already connected"

# Inside the cluster the registry is kbx-registry:5000 (its container name on the kind
# network). Tell containerd on every node to pull from it over plain HTTP.
step "Configuring containerd on the node(s) for kbx-registry:5000"
for node in $(kind get nodes --name "$CLUSTER"); do
  docker exec "$node" mkdir -p /etc/containerd/certs.d/kbx-registry:5000
  printf 'server = "http://kbx-registry:5000"\n\n[host."http://kbx-registry:5000"]\n  capabilities = ["pull", "resolve"]\n' \
    | docker exec -i "$node" cp /dev/stdin /etc/containerd/certs.d/kbx-registry:5000/hosts.toml
done

# Standard way to advertise a local registry to tools (KEP-1755).
kubectl apply -f - >/dev/null <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:5000"
    hostFromContainerRuntime: "kbx-registry:5000"
    hostFromClusterNetwork: "kbx-registry:5000"
YAML

kubectl get nodes -o wide | cut -c1-110
