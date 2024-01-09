package frost

import (
	"fmt"
	"math/big"
	"slices"
	"testing"

	"threshold.network/roast/internal/testutils"
)

func TestRound2_ValidationError(t *testing.T) {
	// just a basic test checking if Round2 calls validateGroupCommitments
	signers := createSigners(t)
	nonces, commitments := executeRound1(t, signers)
	commitments[0].bindingNonceCommitment = &Point{big.NewInt(99), big.NewInt(88)}

	signer := signers[1]
	nonce := nonces[1]

	_, err := signer.Round2([]byte("dummy"), nonce, commitments)
	if err == nil {
		t.Fatalf("expected a non-nil error")
	}

	// assert if this is indeed a validation error
	expectedError := "binding nonce commitment from signer [1] is not a valid non-identity point on the curve: [Point[X=0x63, Y=0x58]]"
	testutils.AssertStringsEqual(t, "validation error", expectedError, err.Error())
}

func TestValidateGroupCommitments(t *testing.T) {
	// happy path
	signers := createSigners(t)
	_, commitments := executeRound1(t, signers)

	signer := signers[0]

	validationErrors, participants := signer.validateGroupCommitments(commitments)
	testutils.AssertIntsEqual(t, "number of validation errors", 0, len(validationErrors))
	testutils.AssertIntsEqual(t, "number of participants", groupSize, len(participants))

	for i, p := range participants {
		expected := uint64(i + 1)
		if p != expected {
			testutils.AssertUintsEqual(t, "participant index", expected, p)
		}
	}
}

func TestValidateGroupCommitments_Errors(t *testing.T) {
	tests := map[string]struct {
		modifyCommitments func([]*NonceCommitment) []*NonceCommitment
		expectedErrors    []string
	}{
		"nil in the array": {
			modifyCommitments: func(commitments []*NonceCommitment) []*NonceCommitment {
				commitments[30] = nil
				return commitments
			},
			expectedErrors: []string{
				"commitment at position [30] is nil",
			},
		},
		"commitment from the current signer is missing": {
			modifyCommitments: func(commitments []*NonceCommitment) []*NonceCommitment {
				// the test uses signers[0] so let remove commitment from this signer
				return slices.Delete(commitments, 0, 1)
			},
			expectedErrors: []string{
				"current signer's commitment not found on the list",
			},
		},
		// We don't want to repeat all validateGroupCommitmentsBase errors but we want
		// to ensure this function is called and all sort of errors are detected.
		// Better be safe than sorry.
		"multiple problems": {
			modifyCommitments: func(commitments []*NonceCommitment) []*NonceCommitment {
				// duplicate commitment from signer 5 at positions 4 and 5
				commitments[5] = commitments[4]
				// at the position where we'd expect a commitment from signer 32 we have
				// a commitment from signer 51
				tmp := commitments[31]
				commitments[31] = commitments[50]
				// at the position where we'd expect a commitment from signer 51 we have
				// a commitment from signer 32
				commitments[50] = tmp
				// binding nonce commitment for signer 81 is an invalid curve point
				commitments[80].bindingNonceCommitment = &Point{big.NewInt(100), big.NewInt(200)}
				// hiding nonce commitment for signer 100 is an invalid curve point
				commitments[99].hidingNonceCommitment = &Point{big.NewInt(300), big.NewInt(400)}
				// finally, we'll set the nil commitment at position 97 where we would
				// expect a commitment from signer 98
				commitments[97] = nil
				return commitments
			},
			expectedErrors: []string{
				"commitments not sorted in ascending order: commitments[4].signerIndex=5, commitments[5].signerIndex=5",
				"commitments not sorted in ascending order: commitments[31].signerIndex=51, commitments[32].signerIndex=33",
				"commitments not sorted in ascending order: commitments[49].signerIndex=50, commitments[50].signerIndex=32",
				"binding nonce commitment from signer [81] is not a valid non-identity point on the curve: [Point[X=0x64, Y=0xc8]]",
				"commitment at position [97] is nil",
				"hiding nonce commitment from signer [100] is not a valid non-identity point on the curve: [Point[X=0x12c, Y=0x190]]",
			},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			signers := createSigners(t)
			_, commitments := executeRound1(t, signers)
			signer := signers[0]

			modified := test.modifyCommitments(commitments)
			validationErrors, participants := signer.validateGroupCommitments(modified)

			if participants != nil {
				t.Fatalf("expected nil participants list, has [%v]", participants)
			}

			testutils.AssertIntsEqual(
				t,
				"number of validation errors",
				len(test.expectedErrors),
				len(validationErrors),
			)
			if len(test.expectedErrors) != len(validationErrors) {
				// Using Fatalf directly to not execute the rest of assertions
				t.Fatalf(
					"unexpected number of validation errors\nexpected: %v\nactual:   %v\n",
					len(test.expectedErrors),
					len(validationErrors),
				)
			}

			for i, expectedError := range test.expectedErrors {
				testutils.AssertStringsEqual(
					t,
					fmt.Sprintf("validation error #%d", i),
					expectedError,
					validationErrors[i].Error(),
				)
			}
		})
	}
}
