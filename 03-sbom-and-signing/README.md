# Project 03: SBOMs, signatures and attestations for a private registry

**Tools:** Docker, a local OCI registry, Syft, Grype, Cosign 3 &nbsp;|&nbsp; **Time:** 45 minutes &nbsp;|&nbsp; **Run time:** about 2 minutes

Scanning tells you what is in an image today. Signing and attestations let everyone
downstream check, without trusting the network or the registry, that an image is the one
your pipeline built and scanned. In this project you build that chain, then attack it.

## What you will learn

- How to run a private registry on the box and push to it.
- Why you sign a **digest**, never a tag, and how to resolve one from the registry API.
- How to produce an SBOM (CycloneDX and SPDX) and scan the SBOM instead of the image.
- Cosign 3 key-based signing without the public transparency log, using a signing config.
- Signed in-toto attestations: the SBOM and a vulnerability summary attached to the image.
- Policy-as-code at verify time with Rego: "signed" is not the same as "safe".

## Run it

```bash
cd ~/devsecops-kodebox-projects
./03-sbom-and-signing/pipeline.sh
```

It needs project 01's hardened app and `~/devsecops`. It leaves the registry running and
populated, which project 05 relies on.

## Step 1: A private registry

```bash
./03-sbom-and-signing/registry.sh up       # registry:3 on 127.0.0.1:5000 only
./03-sbom-and-signing/registry.sh status   # list repositories
```

It binds to `127.0.0.1`, so it is not exposed through the KodeBox's public IP. Docker,
Cosign and Syft all treat `localhost` registries as plain HTTP automatically.

## Step 2: Push, then pin the digest

```bash
docker build -t localhost:5000/kbx/sample-app:1.0.0 01-image-hardening/hardened
docker push localhost:5000/kbx/sample-app:1.0.0
```

`common.sh` resolves the tag to a digest by asking the registry for the manifest's
`Docker-Content-Digest` header, which is what deploy tooling does:

```text
localhost:5000/kbx/sample-app@sha256:5ebfc655baecd9574696cd5aac9660d2c53d5fb20eb967fe113c571921362a78
```

## Step 3: SBOM, scan, sign, attest

`sign-and-attest.sh <repo@sha256:digest>` does five things:

1. **SBOM** with Syft, in CycloneDX and SPDX JSON. Syft also lists every file with its
   hash, which is why the raw component count is in the thousands while the package
   count is in the low hundreds.
2. **Scan the SBOM** with `grype sbom:sbom.cdx.json`. Scanning the SBOM, not the image,
   is how you re-check old releases against today's CVE data without pulling them.
3. **Vulnerability summary**: a small JSON predicate with counts and fixable counts by
   severity, plus the scanner and database versions.
4. **Sign** the digest with a Cosign key pair kept in `~/.kbx/cosign` (outside the repo,
   private key encrypted with a random password, mode 600).
5. **Attest** twice: the CycloneDX SBOM (`--type cyclonedx`) and the vulnerability
   summary (a custom predicate type URI).

### Cosign 3 and the transparency log

By default Cosign 3 records every signature in Sigstore's **public** Rekor log. For a
private lab registry you usually do not want that. Cosign 3 deprecates
`--tlog-upload=false`; the supported way is a signing config with no services in it:

```bash
cosign signing-config create --out ~/.kbx/cosign/signing-config.json
cosign sign --key cosign.key --signing-config ~/.kbx/cosign/signing-config.json <repo@digest>
cosign verify --key cosign.pub --insecure-ignore-tlog=true <repo@digest>
```

In production, prefer keyless signing (OIDC identity from your CI) with the public log,
or a KMS-held key. A key file on a box is fine for learning, not for a release pipeline.

Cosign 3 stores signatures and attestations as **OCI referrers** next to the image:

```text
📦 Supply Chain Security Related artifacts for an image: localhost:5000/kbx/sample-app@sha256:5ebf...
└── 🔗 https://github.com/bamboomaster112/devsecops-kodebox-projects/vuln-summary/v1 artifacts via OCI referrer
└── 🔗 https://cyclonedx.org/bom artifacts via OCI referrer
└── 🔗 https://sigstore.dev/cosign/sign/v1 artifacts via OCI referrer
```

## Step 4: Verify like an admission controller

`verify.sh <image-ref>` runs three checks and fails if any fails:

```text
--> cosign verify (signature)
    signed digest: sha256:5ebfc655...
    PASS
--> cosign verify-attestation --type cyclonedx (SBOM)
    PASS
--> cosign verify-attestation --policy policy/vuln-summary.rego
    critical=0 fixable-high=0
    PASS
```

The policy is ten lines of Rego (`policy/vuln-summary.rego`): allow only when the signed
summary shows zero CRITICAL and zero fixable HIGH.

## Step 5: Attack the chain

The pipeline then tries three things that should fail:

| Attack | What happens | Why |
|---|---|---|
| Push different bytes under the same tag `:1.0.0` | Rejected | The signature covers the old digest; the tag now points somewhere else. The original digest still verifies. |
| Sign the legacy `~/devsecops` image properly | Rejected by policy | Its signed summary shows 41 critical findings. The signature is valid; the content is not acceptable. |
| Push to the approved registry without signing | Rejected | No signature for that repository and digest. |

```text
PASS   hardened image passes signature, SBOM and vuln policy
PASS   moved tag :1.0.0 is rejected
PASS   original digest still verifies
PASS   restored tag points at the signed digest
PASS   signed legacy image fails the vuln policy
PASS   unsigned image is rejected
```

## Try it yourself

1. Generate a second key pair and verify with it. What error do you get?
2. Change the Rego policy to also require `counts.high < 60` and rerun `verify.sh` on the
   hardened image. Is that a sensible policy? Why or why not?
3. Run `grype sbom:03-sbom-and-signing/out/sample-app-1.0.0/sbom.cdx.json` again in a week
   and compare: same image, new CVEs.

## Files

| File | Purpose |
|---|---|
| `pipeline.sh` | The full flow and the three attacks, with PASS/FAIL checks |
| `sign-and-attest.sh` | SBOM, SBOM scan, summary, sign, two attestations |
| `verify.sh` | Signature, SBOM attestation and Rego policy check |
| `registry.sh` | Start, stop and list the local registry |
| `common.sh` | Shared settings, key handling and digest resolution |
| `policy/vuln-summary.rego` | The release policy |
