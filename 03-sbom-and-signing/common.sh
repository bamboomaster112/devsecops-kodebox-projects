# Shared settings for project 03 (sourced, not run).
REGISTRY_NAME="${REGISTRY_NAME:-kbx-registry}"
REGISTRY_HOST="${REGISTRY_HOST:-localhost:5000}"      # how the box reaches the registry
REGISTRY_IMAGE="${REGISTRY_IMAGE:-registry:3}"
KEY_DIR="${KEY_DIR:-$HOME/.kbx/cosign}"               # outside the repo, never committed
VULN_PREDICATE_TYPE="https://github.com/bamboomaster112/devsecops-kodebox-projects/vuln-summary/v1"

step() { printf '\033[1;36m--> %s\033[0m\n' "$*"; }

# Cosign key pair for the lab. The private key is encrypted with a random password
# kept next to it (mode 600). In production use a KMS key or keyless signing instead.
ensure_keys() {
  mkdir -p "$KEY_DIR" && chmod 700 "$KEY_DIR"
  if [[ ! -f "$KEY_DIR/cosign.key" ]]; then
    step "Generating a cosign key pair in $KEY_DIR"
    (umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > "$KEY_DIR/password")
    COSIGN_PASSWORD="$(cat "$KEY_DIR/password")" \
      cosign generate-key-pair --output-key-prefix "$KEY_DIR/cosign" >/dev/null
  fi
  export COSIGN_PASSWORD
  COSIGN_PASSWORD="$(cat "$KEY_DIR/password")"
  COSIGN_KEY="$KEY_DIR/cosign.key"
  COSIGN_PUB="$KEY_DIR/cosign.pub"
}

# Resolve a pushed tag (localhost:5000/repo:tag) to an immutable repo@sha256 reference
# by asking the registry for the manifest digest, exactly what a deploy tool would do.
digest_ref() {
  local tagged="$1"
  local repo="${tagged%:*}" tag="${tagged##*:}"
  local host="${repo%%/*}" path="${repo#*/}"
  local digest
  digest="$(curl -fsSI \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    "http://${host}/v2/${path}/manifests/${tag}" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:" {print $2}')"
  [[ -n "$digest" ]] || { echo "could not resolve $tagged" >&2; return 1; }
  echo "${repo}@${digest}"
}
