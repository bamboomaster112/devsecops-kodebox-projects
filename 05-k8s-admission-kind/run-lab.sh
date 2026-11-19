#!/usr/bin/env bash
# Project 05 end to end: cluster, Kyverno, policies, a good deployment, then every
# bad manifest in manifests/denied against the admission chain.
#
#   ./run-lab.sh              # needs project 03's registry content and cosign key
#   kind delete cluster --name kbx    # clean up afterwards (frees about 1 GB of RAM)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
banner() { printf '\n\033[1;35m=== %s ===\033[0m\n' "$*"; }

banner "1. kind cluster wired to the local registry";  "$HERE/cluster-up.sh"
banner "2. Kyverno";                                    "$HERE/install-kyverno.sh"
banner "3. Policies";                                   "$HERE/apply-policies.sh"
banner "4. Deploy the signed app";                      "$HERE/deploy-app.sh"
banner "5. Try every manifest that should be rejected"; "$HERE/test-policies.sh"
