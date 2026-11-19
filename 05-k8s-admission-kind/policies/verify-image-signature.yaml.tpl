# Template: apply-policies.sh fills in the cosign public key from project 03.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
  annotations:
    policies.kyverno.io/title: Verify image signature and vulnerability attestation
    policies.kyverno.io/description: >-
      Every image from the internal registry must be signed with the team key, and its
      signed vulnerability summary must show no CRITICAL and no fixable HIGH findings.
      The tag is rewritten to the verified digest, so the node runs exactly what was checked.
spec:
  validationFailureAction: Enforce
  webhookTimeoutSeconds: 30
  background: false
  rules:
    - name: signed-and-not-vulnerable
      match:
        any:
          - resources:
              kinds: ["Pod"]
              namespaces: ["kbx-apps"]
      verifyImages:
        - imageReferences: ["kbx-registry:5000/*"]
          mutateDigest: true
          verifyDigest: true
          required: true
          attestors:
            - entries:
                - keys:
                    publicKeys: |-
                      __COSIGN_PUBLIC_KEY__
                    rekor:
                      ignoreTlog: true
                    ctlog:
                      ignoreSCT: true
          attestations:
            - type: https://github.com/bamboomaster112/devsecops-kodebox-projects/vuln-summary/v1
              attestors:
                - entries:
                    - keys:
                        publicKeys: |-
                          __COSIGN_PUBLIC_KEY__
                        rekor:
                          ignoreTlog: true
                        ctlog:
                          ignoreSCT: true
              conditions:
                - all:
                    - key: "{{ counts.critical }}"
                      operator: Equals
                      value: 0
                      message: "the image has CRITICAL vulnerabilities"
                    - key: "{{ fixable.high }}"
                      operator: Equals
                      value: 0
                      message: "the image has HIGH vulnerabilities that already have a fix"
