# Project 05: Kubernetes admission control with kind and Kyverno

**Tools:** kind (Kubernetes v1.37), Kyverno 1.20 with CEL policies, Pod Security Admission, Cosign &nbsp;|&nbsp; **Time:** 60 minutes &nbsp;|&nbsp; **Run time:** about 4 minutes

Projects 01 to 04 decide what is allowed to ship. This project enforces that decision at
the last door: the Kubernetes API server. Only signed images from your registry, with a
clean signed vulnerability summary, pinned to a digest, with limits set and no root, get
to run. Everything else is rejected before a container is created.

**Prerequisite:** run `03-sbom-and-signing/pipeline.sh` first. This project uses its
registry, its lab CA, its cosign key and the images it pushed and signed.

## What you will learn

- How to wire kind to a private TLS registry with its own CA (containerd `hosts.toml`).
- Built-in **Pod Security Admission** (`restricted`) versus policy-engine rules, and why
  you want both.
- Kyverno 1.20's CEL-based **ValidatingPolicy** and **ImageValidatingPolicy**. (Kyverno
  1.20 no longer accepts the old `kyverno.io/v1 ClusterPolicy`; the API server rejects
  create and update requests for it.)
- How to verify cosign signatures and in-toto attestations at admission, and read fields
  from the attestation in a CEL expression.
- How to test policies safely with server-side dry runs.

## Run it

```bash
cd ~/devsecops-kodebox-projects
./05-k8s-admission-kind/run-lab.sh
kind delete cluster --name kbx          # when you are done: frees about 1.6 GB of RAM
```

`run-lab.sh` runs five scripts in order. You can also run them one by one.

## Step 1: A cluster that trusts your registry (`cluster-up.sh`)

- Creates a single-node kind cluster from `kind-config.yaml`. The node publishes NodePort
  30080 on `127.0.0.1` only, and its containerd reads per-registry settings from
  `/etc/containerd/certs.d`.
- Connects the `kbx-registry` container to the `kind` Docker network, so pods and the
  node reach it as `kbx-registry:5000`.
- Copies the lab CA into the node and writes a `hosts.toml` for `kbx-registry:5000`.

The registry certificate (from project 03) lists both names it is reached by:
`localhost` from the box, and `kbx-registry` from inside the cluster.

## Step 2: Kyverno, sized for a small box (`install-kyverno.sh`)

Helm chart 3.10.0 (Kyverno v1.20.0) with one admission controller replica and the
background, cleanup and reports controllers turned off. The lab CA goes in through
`admissionController.caCertificates.data` so Kyverno can fetch signatures over HTTPS.

> **Two things that broke during testing, and why.**
> 1. With a plain-HTTP registry and `allowInsecureRegistry: true`, Kyverno still fetched
>    Cosign 3's signatures (stored as OCI referrers) over HTTPS and failed with
>    "http: server gave HTTP response to HTTPS client". The registry now uses TLS with a
>    lab CA, which is also how real private registries run.
> 2. Passing the full system CA bundle as a Helm value failed: Helm stores each release in
>    a Secret, which is capped at 1 MB. The lab passes only its own CA. In production,
>    mount a bundle with `admissionController.caCertificates.volume`.

## Step 3: The policies (`apply-policies.sh`)

| Policy | Kind | Rule |
|---|---|---|
| Pod Security `restricted` | Built in (namespace label) | No privileged, no root, drop all capabilities, seccomp, no privilege escalation |
| `restrict-image-registries` | ValidatingPolicy | Every container image starts with `kbx-registry:5000/` |
| `disallow-latest-tag` | ValidatingPolicy | No `:latest`, including `:latest@sha256:...` after digest pinning |
| `require-resource-limits` | ValidatingPolicy | CPU and memory limits on every container |
| `verify-image-signature` | ImageValidatingPolicy | Signed with the team key, signed vulnerability summary with zero CRITICAL and zero fixable HIGH, rewritten to the verified digest |

All of them are scoped to the `kbx-apps` namespace with a `namespaceSelector`, so nothing
else in the cluster is affected.

The image policy is the heart of the project. Its three CEL checks:

```yaml
validations:
  - expression: >-
      images.containers.map(image, verifyImageSignatures(image, [attestors.teamkey])).all(n, n > 0)
  - expression: >-
      images.containers.map(image,
        verifyAttestationSignatures(image, attestations.vulns, [attestors.teamkey])).all(n, n > 0)
  # extractPayload returns the whole in-toto statement; our summary is its predicate.
  - expression: >-
      images.containers.map(image, extractPayload(image, attestations.vulns)).all(s,
        int(s.predicate.counts.critical) == 0 && int(s.predicate.fixable.high) == 0)
```

The attestor is the cosign public key from `~/.kbx/cosign/cosign.pub`, filled in by
`apply-policies.sh`, with `insecureIgnoreTlog: true` because project 03 signs without the
public transparency log.

**Why `disallow-latest-tag` checks for `:latest@`.** The image policy has
`mutateDigest: true`, so it rewrites `app:latest` to `app:latest@sha256:...` before the
validating policies run. A check for "ends with `:latest`" would quietly stop working.

## Step 4: Deploy the signed app (`deploy-app.sh`)

`manifests/allowed/app.yaml` is the hardened app the way the policies expect it: a
`restricted` namespace, non-root UID 10001, read-only root filesystem with a small
in-memory `/tmp`, all capabilities dropped, seccomp `RuntimeDefault`, probes, requests
and limits, a NodePort Service, and a NetworkPolicy that allows only port 8000 in and
nothing out. The script swaps in the digest project 03 signed.

```text
POD                        STATUS    IMAGE
kbx-app-576df88468-gfr6m   Running   kbx-registry:5000/kbx/sample-app:1.0.0@sha256:dc787b62c461...
--> curl http://127.0.0.1:30080/
Hello from the KodeBox DevSecOps lab (hardened, env=production)
```

## Step 5: Try to get bad workloads in (`test-policies.sh`)

Each file in `manifests/denied/` breaks exactly one rule. The script sends each one with
`kubectl apply --dry-run=server`: the request goes through every admission check, but
nothing is created. It then checks which control rejected it.

```text
RESULT MANIFEST                       VERDICT  DECIDED BY
PASS   01-privileged.yaml             denied   Pod Security Admission
PASS   02-runs-as-root.yaml           denied   Pod Security Admission
PASS   03-latest-tag.yaml             denied   Kyverno disallow-latest-tag
PASS   04-untrusted-registry.yaml     denied   Kyverno restrict-image-registries
PASS   05-no-limits.yaml              denied   Kyverno require-resource-limits
PASS   06-unsigned-image.yaml         denied   Kyverno verify-image-signature
PASS   07-signed-but-vulnerable.yaml  denied   Kyverno verify-image-signature
```

The messages a developer sees:

```text
03  Policy disallow-latest-tag failed: use an explicit version tag, not ':latest'
04  Policy restrict-image-registries failed: images must come from kbx-registry:5000, found: docker.io/nginxinc/nginx-unprivileged:alpine
05  Policy require-resource-limits failed: every container needs resources.limits.cpu and resources.limits.memory
06  Policy verify-image-signature failed: image is not signed with the team key; ... attestor "teamkey": failed to verify cosign signatures: no signatures found
07  Policy verify-image-signature failed: the signed vulnerability summary shows CRITICAL or fixable HIGH findings
```

Case 07 is the one to dwell on. The legacy image **is** properly signed. It is rejected
because of what its own signed attestation says about it.

## Try it yourself

1. Run `VERBOSE=1 ./05-k8s-admission-kind/test-policies.sh` to see every full message.
2. Change `validationActions: [Deny]` to `[Audit]` on one policy and rerun. What changes?
3. Write a ValidatingPolicy that requires the label `app.kubernetes.io/name` on every pod,
   add a manifest under `manifests/denied/` with an `expect-denied-by:` line, and rerun.
4. Re-sign the legacy image after fixing it (hint: project 01's Dockerfile) and watch case
   07 flip.

## Files

| File | Purpose |
|---|---|
| `run-lab.sh` | All five steps |
| `kind-config.yaml` | One node, NodePort 30080 on 127.0.0.1, containerd `config_path` |
| `cluster-up.sh` | Cluster, registry network, lab CA on the node |
| `install-kyverno.sh` | Kyverno 1.20 with the lab CA |
| `apply-policies.sh` | Applies the policies and fills the cosign key into the image policy |
| `policies/` | Three ValidatingPolicies and the ImageValidatingPolicy template |
| `manifests/allowed/app.yaml` | The compliant deployment |
| `manifests/denied/*.yaml` | Seven violations, each with an `expect-denied-by:` line |
| `deploy-app.sh`, `test-policies.sh` | Deploy and test |
