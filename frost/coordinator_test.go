package frost

import (
	"testing"

	"threshold.network/roast/internal/testutils"
)

// This test covers failure paths in the Aggregate function. The happy path is
// covered as a part of the roundtrip test in frost_test.go.
func TestAggregate_Failures(t *testing.T) {
	message := []byte("For even the very wise cannot see all ends")

	signers := createSigners(t)
	publicKey := signers[0].publicKey

	nonces, commitments := executeRound1(t, signers)
	signatureShares := executeRound2(t, signers, message, nonces, commitments)

	coordinator := NewCoordinator(ciphersuite, publicKey, threshold)

	tests := map[string]struct {
		numberOfCommitments     int
		numberOfSignatureShares int
		expectedErr             string
	}{
		"number of commitments and signature shares do not match": {
			numberOfCommitments:     groupSize,
			numberOfSignatureShares: groupSize - 1,
			expectedErr:             "the number of commitments and signature shares do not match; has [100] commitments and [99] signature shares",
		},
		"number of commitments and signature shares below threshold": {
			numberOfCommitments:     threshold - 1,
			numberOfSignatureShares: threshold - 1,
			expectedErr:             "not enough shares; has [50] for threshold [51]",
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			signature, err := coordinator.Aggregate(
				message,
				commitments[:test.numberOfCommitments],
				signatureShares[:test.numberOfSignatureShares],
			)

			testutils.AssertStringsEqual(
				t,
				"aggregate signature share error message",
				test.expectedErr,
				err.Error(),
			)

			if signature != nil {
				t.Error("expected nil signature")
			}
		})
	}
}
