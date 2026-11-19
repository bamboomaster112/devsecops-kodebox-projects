#!/usr/bin/env bash
# Refresh the Trivy and Grype vulnerability databases before a lab.
#
# Grype refuses to scan with a database older than 5 days and downloads a new one
# first, which can take several minutes on a 2 vCPU box. Running this once at the
# start keeps the scans in the projects fast and predictable.
set -euo pipefail

echo "==> Trivy DB"
trivy image --download-db-only --quiet
trivy version 2>/dev/null | sed -n '/Vulnerability DB/,/DownloadedAt/p' | sed 's/^/    /'

echo "==> Grype DB"
if grype db check >/dev/null 2>&1; then
  echo "    already current"
else
  echo "    downloading a newer database (this is the slow part)"
  grype db update
fi
grype db status 2>/dev/null | grep -E 'Built|Status' | sed 's/^/    /'
