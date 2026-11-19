# Template: apply-policies.sh fills in the cosign public key from project 03.
#
# Every image from the internal registry must be signed with the team key and carry a
# signed vulnerability summary with no CRITICAL and no fixable HIGH findings. The image
# reference is rewritten to the verified digest, so the node runs exactly what was checked.
apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: verify-image-signature
spec:
  validationActions: [Deny]
  webhookConfiguration:
    timeoutSeconds: 30
  evaluation:
    background:
      enabled: false
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: kbx-apps
  matchImageReferences:
    - glob: "kbx-registry:5000/*"
  credentials:
    allowInsecureRegistry: true      # the lab registry speaks plain HTTP inside the kind network
  validationConfigurations:
    required: true
    mutateDigest: true
    verifyDigest: true
  attestors:
    - name: teamkey
      cosign:
        key:
          data: |
            __COSIGN_PUBLIC_KEY__
        ctlog:
          insecureIgnoreTlog: true   # signed without the public transparency log (project 03)
          insecureIgnoreSCT: true
  attestations:
    - name: vulns
      intoto:
        type: https://github.com/bamboomaster112/devsecops-kodebox-projects/vuln-summary/v1
  validations:
    - expression: >-
        images.containers.map(image, verifyImageSignatures(image, [attestors.teamkey])).all(n, n > 0)
      message: "image is not signed with the team key"
    - expression: >-
        images.containers.map(image,
          verifyAttestationSignatures(image, attestations.vulns, [attestors.teamkey])).all(n, n > 0)
      message: "image has no signed vulnerability summary"
    - expression: >-
        images.containers.map(image, extractPayload(image, attestations.vulns)).all(p,
          int(p.counts.critical) == 0 && int(p.fixable.high) == 0)
      message: "the signed vulnerability summary shows CRITICAL or fixable HIGH findings"
