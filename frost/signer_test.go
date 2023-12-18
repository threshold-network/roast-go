package frost

import (
	"crypto/rand"
	"math/big"
	"testing"

	"threshold.network/roast/internal/testutils"
)

var ciphersuite = NewBip340Ciphersuite()
var groupSize = 100

func TestValidateGroupCommitment(t *testing.T) {
	signers := createSigners(t)
	_, commitments := executeRound1(t, signers)

	signer := signers[0]

	validationErrors := signer.validateGroupCommitment(commitments)
	testutils.AssertIntsEqual(t, "number of validation errors", 0, len(validationErrors))
}

func TestValidateGroupCommitments_Errors(t *testing.T) {
	signers := createSigners(t)
	_, commitments := executeRound1(t, signers)

	tmp := commitments[31]
	// at the position where we'd expect a commitment from signer 32 we have
	// a commitment from signer 51
	commitments[31] = commitments[50]
	// at the position where we'd expect a commitment from signer 51 we have
	// a commitment from signer 32
	commitments[50] = tmp
	// binding nonce commitment for signer 81 is an invalid curve point
	commitments[80].bindingNonceCommitment = &Point{big.NewInt(100), big.NewInt(200)}
	// hiding nonce commitment for signer 100 is an invalid curve point
	commitments[99].hidingNonceCommitment = &Point{big.NewInt(300), big.NewInt(400)}

	signer := signers[0]

	validationErrors := signer.validateGroupCommitment(commitments)

	expectedError1 := "commitments not sorted in ascending order: commitments[31].signerIndex=51, commitments[32].signerIndex=33"
	expectedError2 := "commitments not sorted in ascending order: commitments[49].signerIndex=50, commitments[50].signerIndex=32"
	expectedError3 := "binding nonce commitment from signer [81] is not a valid non-identity point on the curve: [Point[X=0x64, Y=0xc8]]"
	expectedError4 := "hiding nonce commitment from signer [100] is not a valid non-identity point on the curve: [Point[X=0x12c, Y=0x190]]"

	testutils.AssertIntsEqual(t, "number of validation errors", 4, len(validationErrors))
	testutils.AssertStringsEqual(t, "validation error #1", expectedError1, validationErrors[0].Error())
	testutils.AssertStringsEqual(t, "validation error #2", expectedError2, validationErrors[1].Error())
	testutils.AssertStringsEqual(t, "validation error #3", expectedError3, validationErrors[2].Error())
	testutils.AssertStringsEqual(t, "validation error #4", expectedError4, validationErrors[3].Error())
}

func createSigners(t *testing.T) []*Signer {
	var signers []*Signer

	// TODO: replace dummy secret key share with something real
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	secretKeyShare := new(big.Int).SetBytes(buf)

	for i := 1; i <= groupSize; i++ {
		signer := &Signer{
			ciphersuite:    ciphersuite,
			signerIndex:    uint64(i),
			secretKeyShare: secretKeyShare,
		}

		signers = append(signers, signer)
	}

	return signers
}

func executeRound1(t *testing.T, signers []*Signer) ([]*Nonce, []*NonceCommitment) {
	var nonces []*Nonce
	var commitments []*NonceCommitment

	for _, signer := range signers {
		n, c, err := signer.Round1()
		if err != nil {
			t.Fatal(t)
		}

		nonces = append(nonces, n)
		commitments = append(commitments, c)
	}

	return nonces, commitments
}
