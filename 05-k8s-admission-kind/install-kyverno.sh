#!/usr/bin/env bash
# Install Kyverno, trimmed to fit a 2 vCPU / 4 GB box.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KYVERNO_CHART_VERSION="${KYVERNO_CHART_VERSION:-__CHART__}"   # Kyverno __APP__

helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update >/dev/null
# - one admission controller replica, no background or cleanup controllers (not used here)
# - allowInsecureRegistry: the lab registry speaks plain HTTP inside the kind network
helm upgrade --install kyverno kyverno/kyverno \
  --namespace kyverno --create-namespace \
  --version "$KYVERNO_CHART_VERSION" \
  --set admissionController.replicas=1 \
  --set backgroundController.enabled=false \
  --set cleanupController.enabled=false \
  --set reportsController.enabled=false \
  --set admissionController.container.extraArgs.allowInsecureRegistry=true \
  --wait --timeout 5m
kubectl -n kyverno get pods
