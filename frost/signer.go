package frost

import (
	"crypto/rand"
	"encoding/binary"
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

// TODO: check if nonce commitment is a valid point on the curve
// TODO: check if it is not an identity element
// TODO: check if the commitment list is sorted
func (s *Signer) encodeGroupCommitment(commitments []NonceCommitment) []byte {
	// From [FROST]:
	//
	// 4.3.  List Operations
	//
	//   This section describes helper functions that work on lists of values
	//   produced during the FROST protocol.  The following function encodes a
	//   list of participant commitments into a byte string for use in the
	//   FROST protocol.
	//
	//   Inputs:
	//     - commitment_list = [(i, hiding_nonce_commitment_i,
	//       binding_nonce_commitment_i), ...], a list of commitments issued by
	//       each participant, where each element in the list indicates a
	//       NonZeroScalar identifier i and two commitment Element values
	//       (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list
	//       MUST be sorted in ascending order by identifier.
	//
	//   Outputs:
	//     - encoded_group_commitment, the serialized representation of
	//       commitment_list, a byte string.

	curve := s.ciphersuite.Curve()
	ecPointLength := curve.SerializedPointLength()

	// preallocate the necessary space to avoid waste:
	// 8 bytes for signerIndex (uint64)
	// ecPointLength for hidingNonceCommitment
	// ecPointLength for bindingNonceCommitment
	b := make([]byte, 0, (8+2*ecPointLength)*len(commitments))

	// encoded_group_commitment = nil
	// for (identifier, hiding_nonce_commitment,
	//      binding_nonce_commitment) in commitment_list:
	for _, c := range commitments {
		// encoded_commitment = (
		//     G.SerializeScalar(identifier) ||
		//     G.SerializeElement(hiding_nonce_commitment) ||
		//     G.SerializeElement(binding_nonce_commitment))
		// encoded_group_commitment = (
		//     encoded_group_commitment ||
		//     encoded_commitment)
		b = binary.BigEndian.AppendUint64(b, c.signerIndex)
		b = append(b, curve.SerializePoint(c.hidingNonceCommitment)...)
		b = append(b, curve.SerializePoint(c.bindingNonceCommitment)...)
	}

	// return encoded_group_commitment
	return b
}
