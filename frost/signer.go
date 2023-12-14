package frost

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Signer represents a single participant of the [FROST] signing protocol.
type Signer struct {
	ciphersuite Ciphersuite

	signerIndex    uint64   // i in [FROST]
	secretKeyShare *big.Int // sk_i in [FROST]
}

// Nonce is a message produced in Round One of [FROST].
type Nonce struct {
	hidingNonce  *big.Int
	bindingNonce *big.Int
}

// NonceCommitment is a message produced in Round One of [FROST].
type NonceCommitment struct {
	signerIndex            uint64
	hidingNonceCommitment  *Point
	bindingNonceCommitment *Point
}

func (s *Signer) Round1() (*Nonce, *NonceCommitment, error) {
	//	From [FROST]:
	//
	//	5.1.  Round One - Commitment
	//
	//	  Round one involves each participant generating nonces and their
	//	  corresponding public commitments.  A nonce is a pair of Scalar
	//	  values, and a commitment is a pair of Element values. Each
	//	  participant's behavior in this round is described by the commit
	//	  function below.  Note that this function invokes nonce_generate
	//	  twice, once for each type of nonce produced.  The output of this
	//	  function is a pair of secret nonces (hiding_nonce, binding_nonce)
	//	  and their corresponding public commitments (hiding_nonce_commitment,
	//	  binding_nonce_commitment).
	//
	//	  Inputs:
	//	    - sk_i, the secret key share, a Scalar.
	//
	//	  Outputs:
	//	    - (nonce, comm), a tuple of nonce and nonce commitment pairs,
	//		  where each value in the nonce pair is a Scalar and each value in
	//		  the nonce commitment pair is an Element.

	// hiding_nonce = nonce_generate(sk_i)
	hn, err := s.generateNonce(s.secretKeyShare.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("hiding nonce generation failed: [%v]", err)
	}
	// binding_nonce = nonce_generate(sk_i)
	bn, err := s.generateNonce(s.secretKeyShare.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("binding nonce generation failed: [%v]", err)
	}

	// hiding_nonce_commitment = G.ScalarBaseMult(hiding_nonce)
	hnc := s.ciphersuite.Curve().EcBaseMul(hn)
	// binding_nonce_commitment = G.ScalarBaseMult(binding_nonce)
	bnc := s.ciphersuite.Curve().EcBaseMul(bn)

	// nonces = (hiding_nonce, binding_nonce)
	// comms = (hiding_nonce_commitment, binding_nonce_commitment)
	// return (nonces, comms)
	return &Nonce{hn, bn}, &NonceCommitment{s.signerIndex, hnc, bnc}, nil
}

func (s *Signer) generateNonce(secret []byte) (*big.Int, error) {
	//random_bytes = random_bytes(32)
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	// secret_enc = G.SerializeScalar(secret)
	// return H3(random_bytes || secret_enc)
	return s.ciphersuite.H3(b, secret), nil
}
