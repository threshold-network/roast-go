package frost

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// Signer represents a single participant of the [FROST] signing protocol.
type Signer struct {
	Participant

	signerIndex    uint64   // i in [FROST]
	secretKeyShare *big.Int // sk_i in [FROST]
}

// Nonce is a message produced in Round One of [FROST].
type Nonce struct {
	hidingNonce  *big.Int
	bindingNonce *big.Int
}

// NewSigner creates a new [FROST] Signer instance.
func NewSigner(
	ciphersuite Ciphersuite,
	signerIndex uint64,
	publicKey *Point,
	secretKeyShare *big.Int,
) *Signer {
	return &Signer{
		Participant: Participant{
			ciphersuite: ciphersuite,
			publicKey:   publicKey,
		},
		signerIndex:    signerIndex,
		secretKeyShare: secretKeyShare,
	}
}

// Round1 implements the Round One - Commitment phase from [FROST], section
// 5.1.  Round One - Commitment.
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

// Round2 implements the Round Two - Signature Share Generation phase from
// [FROST], section 5.2 Round Two - Signature Share Generation.
func (s *Signer) Round2(
	message []byte,
	nonce *Nonce,
	commitments []*NonceCommitment,
) (*big.Int, error) {
	// TODO: validate the number of commitments

	// participant_list = participants_from_commitment_list(commitment_list)
	validationErrors, participants := s.validateGroupCommitments(commitments)
	if len(validationErrors) != 0 {
		return nil, errors.Join(validationErrors...)
	}

	// binding_factor_list = compute_binding_factors(group_public_key, commitment_list, msg)
	bindingFactors := s.computeBindingFactors(message, commitments)
	// binding_factor = binding_factor_for_participant(binding_factor_list, identifier)
	bindingFactor := bindingFactors[s.signerIndex]

	// group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
	groupCommitment := s.computeGroupCommitment(commitments, bindingFactors)

	// lambda_i = derive_interpolating_value(participant_list, identifier)
	lambda := s.deriveInterpolatingValue(s.signerIndex, participants)

	// challenge = compute_challenge(group_commitment, group_public_key, msg)
	challenge := s.computeChallenge(message, groupCommitment)

	bnbf := new(big.Int).Mul(nonce.bindingNonce, bindingFactor) // (binding_nonce * binding_factor)
	lski := new(big.Int).Mul(lambda, s.secretKeyShare)          // lambda_i * sk_i
	lskic := new(big.Int).Mul(lski, challenge)                  // (lambda_i * sk_i * challenge)

	// sig_share = hiding_nonce + (binding_nonce * binding_factor) + (lambda_i * sk_i * challenge)
	sigShare := new(big.Int).Add(
		nonce.hidingNonce,
		new(big.Int).Add(bnbf, lskic),
	)

	return sigShare, nil
}

// validateGroupCommitments is a helper function used internally in RoundTwo
// to validate the group commitments. Four validations are done:
// - This signer's commitment is included in the commitments.
// - None of the commitments is a point not lying on the curve.
// - The list of commitments is sorted in ascending order by signer identifier.
// - None of the commitments is nil.
//
// Additionally, the function returns the list of participants if there were no
// validation errors. This way, the function implements
// def participants_from_commitment_list(commitment_list) function from [FROST]
// section 4.3. List Operations.
//
// If this signer's commitment is not included in the commitments, the function
// does not perform the rest of validations to not spend any more computing
// resources.
func (s *Signer) validateGroupCommitments(
	commitments []*NonceCommitment,
) ([]error, []uint64) {
	// Validations required, as specified in [FROST]:
	//
	// 3.1 Prime-Order Group
	//
	//   (...)
	//
	//   SerializeElement(A): Maps an Element A to a canonical byte array
	//   buf of fixed length Ne.  This function raises an error if A is the
	//   identity element of the group.
	//
	// 4.2. Polynomials
	//
	//   (...)
	//
	//   Errors:
	//    - "invalid parameters", if 1) x_i is not in L, or if 2) any
	//      x-coordinate is represented more than once in L.
	//
	// 4.3. List Operations
	//
	//   (...)
	//
	//   commitment_list = [(i, hiding_nonce_commitment_i,
	//	 binding_nonce_commitment_i), ...], a list of commitments issued by
	//	 each participant, where each element in the list indicates a
	//	 NonZeroScalar identifier i and two commitment Element values
	//	 (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list
	//	 MUST be sorted in ascending order by identifier.

	found := false
	for _, c := range commitments {
		if c != nil && c.signerIndex == s.signerIndex {
			found = true
			break
		}
	}

	if !found {
		return []error{
			fmt.Errorf("current signer's commitment not found on the list"),
		}, nil
	}

	return s.validateGroupCommitmentsBase(commitments)
}
