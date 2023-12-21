package frost

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"threshold.network/roast/internal/testutils"
)

var ciphersuite = NewBip340Ciphersuite()
var groupSize = 100

func TestRound2_ValidationError(t *testing.T) {
	// just a basic test checking if Round2 calls validateGroupCommitments
	signers := createSigners(t)
	_, commitments := executeRound1(t, signers)
	commitments[0].bindingNonceCommitment = &Point{big.NewInt(99), big.NewInt(88)}

	signer := signers[1]

	_, err := signer.Round2([]byte("dummy"), commitments)
	if err == nil {
		t.Fatalf("expected a non-nil error")
	}
	// assert if this is indeed a validation error
	expectedError := "binding nonce commitment from signer [1] is not a valid non-identity point on the curve: [Point[X=0x63, Y=0x58]]"
	testutils.AssertStringsEqual(t, "validation error", expectedError, err.Error())
}

func TestValidateGroupCommitments(t *testing.T) {
	signers := createSigners(t)
	_, commitments := executeRound1(t, signers)

	signer := signers[0]

	validationErrors := signer.validateGroupCommitments(commitments)
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

	validationErrors := signer.validateGroupCommitments(commitments)

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

func TestEncodeGroupCommitments(t *testing.T) {
	hidingNonceCommitments := [][]string{
		{"d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a", "a9f34ffdc815e0d7a8b64537e17bd81579238c5dd9a86d526b051b13f4062327"}, // G*12
		{"f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8", "ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81"},  // G*13
		{"499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4", "cac2f6c4b54e855190f044e4a7b3d464464279c27a3f95bcc65f40d403a13f5b"}, // G*14
	}

	bindingNonceCommitments := [][]string{
		{"136933174bc388a74ebd6746e13afe0eef5d66580c8e23d33464c342dc0080", "27015dc47dbfe781689f232541c0410560ac69c82044e8e5906e54680127ff92"},   // G*246
		{"9e2158f0d7c0d5f26c3791efefa79597654e7a2b2464f52b1ee6c1347769ef57", "712fcdd1b9053f09003a3481fa7762e9ffd7c8ef35a38509e2fbf2629008373"},  // G*247
		{"22213b78f3dcfbdfeb76cc1731c1ba318b2b0c32f081e206f50618fa7eaf5aa3", "dd81b694ec3a60bad2a203d8eedc863fe476add5cf7391740d86e5c8718a3051"}, //G*248
	}

	// note all data types occupy the same byte length and are left-padded, if necessary
	expectedEncoded := "" +
		"0000000000000001" + // signer[0] index
		"04d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85aa9f34ffdc815e0d7a8b64537e17bd81579238c5dd9a86d526b051b13f4062327" + // hiding nonce [0]
		"0400136933174bc388a74ebd6746e13afe0eef5d66580c8e23d33464c342dc008027015dc47dbfe781689f232541c0410560ac69c82044e8e5906e54680127ff92" + // binding nonce [0]
		"0000000000000002" + // signer [1] index
		"04f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa80ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81" + // hiding nonce [1]
		"049e2158f0d7c0d5f26c3791efefa79597654e7a2b2464f52b1ee6c1347769ef570712fcdd1b9053f09003a3481fa7762e9ffd7c8ef35a38509e2fbf2629008373" + // binding nonce [1]
		"0000000000000003" + // signer [2] index
		"04499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4cac2f6c4b54e855190f044e4a7b3d464464279c27a3f95bcc65f40d403a13f5b" + // hiding nonce [2]
		"0422213b78f3dcfbdfeb76cc1731c1ba318b2b0c32f081e206f50618fa7eaf5aa3dd81b694ec3a60bad2a203d8eedc863fe476add5cf7391740d86e5c8718a3051" // binding nonce [2]

	var commitments []*NonceCommitment
	for i, c := range hidingNonceCommitments {
		hnx, _ := new(big.Int).SetString(c[0], 16)
		hny, _ := new(big.Int).SetString(c[1], 16)

		bnx, _ := new(big.Int).SetString(bindingNonceCommitments[i][0], 16)
		bny, _ := new(big.Int).SetString(bindingNonceCommitments[i][1], 16)

		commitments = append(commitments, &NonceCommitment{
			signerIndex:            uint64(i + 1),
			hidingNonceCommitment:  &Point{hnx, hny},
			bindingNonceCommitment: &Point{bnx, bny},
		})
	}

	signer := createSigners(t)[0]
	encoded := signer.encodeGroupCommitment(commitments)

	testutils.AssertStringsEqual(
		t,
		"encoded data",
		expectedEncoded,
		hex.EncodeToString(encoded),
	)
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
