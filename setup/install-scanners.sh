#!/usr/bin/env bash
# Install the KodeBox toolkit scanners at the same versions as the KodeBox image, on any
# Linux x86_64 machine. Used by the GitHub Actions workflow; not needed on the KodeBox.
# Every download is checked against the checksum file published with its release.
set -euo pipefail

TRIVY_VERSION="${TRIVY_VERSION:-0.76.0}"
GRYPE_VERSION="${GRYPE_VERSION:-0.120.1}"
SYFT_VERSION="${SYFT_VERSION:-1.54.1}"
HADOLINT_VERSION="${HADOLINT_VERSION:-2.15.1}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
DOCKLE_VERSION="${DOCKLE_VERSION:-0.4.15}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT; cd "$tmp"
gh() { echo "https://github.com/$1/releases/download/$2"; }

# fetch_tar <repo> <tag> <tarball> <checksums-file> <binary>
fetch_tar() {
  local base; base="$(gh "$1" "$2")"
  curl -fsSLO "$base/$3"
  curl -fsSL "$base/$4" | grep -E "[[:space:]]\*?$3\$" | sha256sum -c --quiet
  tar xzf "$3" "$5"
  sudo install -m 0755 "$5" "$BIN_DIR/$5"
  echo "installed $5 ($2)"
}

fetch_tar aquasecurity/trivy  "v$TRIVY_VERSION"    "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"   "trivy_${TRIVY_VERSION}_checksums.txt"   trivy
fetch_tar anchore/grype       "v$GRYPE_VERSION"    "grype_${GRYPE_VERSION}_linux_amd64.tar.gz"   "grype_${GRYPE_VERSION}_checksums.txt"   grype
fetch_tar anchore/syft        "v$SYFT_VERSION"     "syft_${SYFT_VERSION}_linux_amd64.tar.gz"     "syft_${SYFT_VERSION}_checksums.txt"     syft
fetch_tar gitleaks/gitleaks   "v$GITLEAKS_VERSION" "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" gitleaks
fetch_tar goodwithtech/dockle "v$DOCKLE_VERSION"   "dockle_${DOCKLE_VERSION}_Linux-64bit.tar.gz" "dockle_${DOCKLE_VERSION}_checksums.txt" dockle

base="$(gh hadolint/hadolint "v$HADOLINT_VERSION")"
curl -fsSLO "$base/hadolint-linux-x86_64"
curl -fsSL "$base/checksums.sha256" | grep -E "[[:space:]]\*?hadolint-linux-x86_64\$" | sha256sum -c --quiet
sudo install -m 0755 hadolint-linux-x86_64 "$BIN_DIR/hadolint"
echo "installed hadolint (v$HADOLINT_VERSION)"
