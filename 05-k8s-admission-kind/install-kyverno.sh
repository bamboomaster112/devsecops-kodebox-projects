#!/usr/bin/env bash
# Install Kyverno, trimmed to fit a 2 vCPU / 4 GB box.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KYVERNO_CHART_VERSION="${KYVERNO_CHART_VERSION:-3.10.0}"   # Kyverno v1.20.0

helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update >/dev/null
# - one admission controller replica, no background or cleanup controllers (not used here)
# - caCertificates: the lab registry CA, so Kyverno can fetch signatures and attestations
#   from https://kbx-registry:5000. This value REPLACES Kyverno's trust store, which is
#   fine here (it only talks to the lab registry). The full system bundle is too big for
#   a Helm value (Helm stores releases in a 1 MB Secret); in production mount a bundle
#   with admissionController.caCertificates.volume instead.
ROOT="$(cd "$HERE/.." && pwd)"
source "$ROOT/03-sbom-and-signing/common.sh"
[[ -f "$REGISTRY_CA" ]] || { echo "No lab CA yet: run 03-sbom-and-signing/registry.sh up" >&2; exit 1; }
helm upgrade --install kyverno kyverno/kyverno \
  --namespace kyverno --create-namespace \
  --version "$KYVERNO_CHART_VERSION" \
  --set admissionController.replicas=1 \
  --set backgroundController.enabled=false \
  --set cleanupController.enabled=false \
  --set reportsController.enabled=false \
  --set-file admissionController.caCertificates.data="$REGISTRY_CA" \
  --wait --timeout 5m
kubectl -n kyverno get pods
