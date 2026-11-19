#!/usr/bin/env bash
# Install the extra tools these projects need on top of the KodeBox DevSecOps toolkit.
#
#   kubectl, kind, Helm            -> /usr/local/bin (downloads are SHA-256 verified)
#   pre-commit, Semgrep, Checkov,
#   Bandit, git-filter-repo        -> Python venv at ~/.venvs/devsecops (pinned versions)
#
# Safe to re-run: a tool already at the pinned version is skipped.
set -euo pipefail

KUBECTL_VERSION="${KUBECTL_VERSION:-v1.37.2}"
KIND_VERSION="${KIND_VERSION:-v0.33.0}"
HELM_VERSION="${HELM_VERSION:-v4.3.2}"
VENV="${VENV:-$HOME/.venvs/devsecops}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
skip() { printf '    %s already at %s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

for bin in docker curl jq sha256sum python3; do
  have "$bin" || { echo "missing required command: $bin" >&2; exit 1; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

# --- kubectl ---------------------------------------------------------------
current="$(kubectl version --client -o json 2>/dev/null | jq -r '.clientVersion.gitVersion' || true)"
if [[ "$current" == "$KUBECTL_VERSION" ]]; then
  skip kubectl "$current"
else
  log "Installing kubectl $KUBECTL_VERSION"
  base="https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64"
  curl -fsSLO "$base/kubectl"
  echo "$(curl -fsSL "$base/kubectl.sha256")  kubectl" | sha256sum -c --quiet
  sudo install -m 0755 kubectl /usr/local/bin/kubectl
fi

# --- kind ------------------------------------------------------------------
current="$(kind version 2>/dev/null | awk '{print $2}' || true)"
if [[ "$current" == "$KIND_VERSION" ]]; then
  skip kind "$current"
else
  log "Installing kind $KIND_VERSION"
  base="https://kind.sigs.k8s.io/dl/${KIND_VERSION}"
  curl -fsSLo kind "$base/kind-linux-amd64"
  echo "$(curl -fsSL "$base/kind-linux-amd64.sha256sum" | cut -d' ' -f1)  kind" | sha256sum -c --quiet
  sudo install -m 0755 kind /usr/local/bin/kind
fi

# --- Helm ------------------------------------------------------------------
current="$(helm version --short 2>/dev/null | cut -d+ -f1 || true)"
if [[ "$current" == "$HELM_VERSION" ]]; then
  skip helm "$current"
else
  log "Installing Helm $HELM_VERSION"
  tarball="helm-${HELM_VERSION}-linux-amd64.tar.gz"
  curl -fsSLO "https://get.helm.sh/${tarball}"
  echo "$(curl -fsSL "https://get.helm.sh/${tarball}.sha256sum" | cut -d' ' -f1)  ${tarball}" | sha256sum -c --quiet
  tar xzf "$tarball"
  sudo install -m 0755 linux-amd64/helm /usr/local/bin/helm
fi

# --- Python tools in a venv --------------------------------------------------
if [[ ! -x "$VENV/bin/python" ]]; then
  log "Creating venv $VENV"
  if ! python3 -m venv "$VENV" 2>/dev/null; then
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv >/dev/null
    python3 -m venv "$VENV"
  fi
fi
log "Installing pinned Python tools into $VENV (Semgrep and Checkov take a minute)"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r "$HERE/requirements-tools.txt"

# Put the venv on PATH for future shells, once.
if ! grep -q 'venvs/devsecops/bin' "$HOME/.bashrc"; then
  echo 'export PATH="$HOME/.venvs/devsecops/bin:$PATH"   # devsecops-kodebox-projects' >> "$HOME/.bashrc"
  log "Added $VENV/bin to PATH in ~/.bashrc (run: source ~/.bashrc)"
fi

log "Done. Run setup/check-env.sh to see every tool and version."
