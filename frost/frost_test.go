package frost

import (
	"math/big"
	"testing"

	"threshold.network/roast/internal/testutils"
)

var ciphersuite = NewBip340Ciphersuite()
var threshold = 51
var groupSize = 100

func TestFrostRoundtrip(t *testing.T) {
	message := []byte("For even the very wise cannot see all ends")

	signers := createSigners(t)
	publicKey := signers[0].publicKey

	nonces, commitments := executeRound1(t, signers)
	signatureShares := executeRound2(t, signers, message, nonces, commitments)

	coordinator := NewCoordinator(ciphersuite, publicKey)
	signature, err := coordinator.Aggregate(message, commitments, signatureShares)
	if err != nil {
		t.Fatal(err)
	}

	isValid, err := ciphersuite.VerifySignature(signature, publicKey, message)
	testutils.AssertBoolsEqual(t, "signature verification result", true, isValid)
	if err != nil {
		t.Fatalf("unexpected signature verification error: [%v]", err)
	}
}

func createSigners(t *testing.T) []*Signer {
	keyShares, secret := testutils.GenerateKeyShares(
		groupSize,
		threshold,
		ciphersuite.Curve().Order(),
	)
	publicKey := ciphersuite.Curve().EcBaseMul(secret)

	signers := make([]*Signer, groupSize)

	for i := 0; i < groupSize; i++ {
		j := i + 1
		signers[i] = NewSigner(ciphersuite, uint64(j), publicKey, keyShares[i])
	}

	return signers
}

func executeRound1(
	t *testing.T,
	signers []*Signer,
) ([]*Nonce, []*NonceCommitment) {
	nonces := make([]*Nonce, len(signers))
	commitments := make([]*NonceCommitment, len(signers))

	for i, signer := range signers {
		n, c, err := signer.Round1()
		if err != nil {
			t.Fatal(t)
		}

		nonces[i] = n
		commitments[i] = c
	}

	return nonces, commitments
}

func executeRound2(
	t *testing.T,
	signers []*Signer,
	message []byte,
	nonces []*Nonce,
	nonceCommitments []*NonceCommitment,
) []*big.Int {
	signatureShares := make([]*big.Int, len(signers))

	for i, signer := range signers {
		signatureShare, err := signer.Round2(message, nonces[i], nonceCommitments)
		if err != nil {
			t.Fatal(t)
		}

		signatureShares[i] = signatureShare
	}

	return signatureShares
}
