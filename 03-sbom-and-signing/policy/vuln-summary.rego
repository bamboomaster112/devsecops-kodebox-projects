# Policy for `cosign verify-attestation --policy`: the image may ship only when its
# signed vulnerability summary reports no CRITICAL and no fixable HIGH findings.
package signature

import rego.v1

default allow := false

allow if {
	input.predicate.counts.critical == 0
	input.predicate.fixable.high == 0
}
