package frost

import (
	"errors"
	"math/big"
)

// Coordinator represents a coordinator of the [FROST] signing protocol.
type Coordinator struct {
	Participant
}

// NewCoordinator creates a new [FROST] Coordinator instance.
func NewCoordinator(
	ciphersuite Ciphersuite,
	publicKey *Point,
) *Coordinator {
	return &Coordinator{
		Participant: Participant{
			ciphersuite: ciphersuite,
			publicKey:   publicKey,
		},
	}
}

// Aggregate implements Signature Share Aggregation from [FROST], section
// 5.3. Signature Share Aggregation.
//
// Note that the signature produced by the signature share aggregation in
// [FROST] may not be valid if there are malicious signers present.
func (c *Coordinator) Aggregate(
	message []byte,
	commitments []*NonceCommitment,
	signatureShares []*big.Int,
) (*Signature, error) {
	// From [FROST]:
	//
	// 5.3.  Signature Share Aggregation
	//
	//   After participants perform round two and send their signature shares
	//   to the Coordinator, the Coordinator aggregates each share to produce
	//   a final signature. Before aggregating, the Coordinator MUST validate
	//   each signature share using DeserializeScalar. If validation fails,
	//   the Coordinator MUST abort the protocol as the resulting signature
	//   will be invalid.  If all signature shares are valid, the Coordinator
	//   aggregates them to produce the final signature using the following
	//   procedure.
	//
	//   Inputs:
	//    - commitment_list = [(i, hiding_nonce_commitment_i,
	//      binding_nonce_commitment_i), ...], a list of commitments issued by
	//      each participant, where each element in the list indicates a
	//      NonZeroScalar identifier i and two commitment Element values
	//      (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list
	//      MUST be sorted in ascending order by identifier.
	//    - msg, the message to be signed, a byte string.
	//    - group_public_key, public key corresponding to the group signing
	//      key, an Element.
	//    - sig_shares, a set of signature shares z_i, Scalar values, for each
	//      participant, of length NUM_PARTICIPANTS, where
	//      MIN_PARTICIPANTS <= NUM_PARTICIPANTS <= MAX_PARTICIPANTS.
	//
	//   Outputs:
	//    - (R, z), a Schnorr signature consisting of an Element R and
	//      Scalar z.

	// TODO: validate the number of signature shares

	validationErrors, _ := c.validateGroupCommitmentsBase(commitments)
	if len(validationErrors) != 0 {
		return nil, errors.Join(validationErrors...)
	}

	// binding_factor_list = compute_binding_factors(group_public_key, commitment_list, msg)
	bindingFactors := c.computeBindingFactors(message, commitments)

	// group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
	groupCommitment := c.computeGroupCommitment(commitments, bindingFactors)

	curve := c.ciphersuite.Curve()
	curveOrder := curve.Order()

	// z = Scalar(0)
	z := big.NewInt(0)
	// for z_i in sig_shares:
	//     z = z + z_i
	for _, zi := range signatureShares {
		z.Add(z, zi)
		z.Mod(z, curveOrder)
	}

	// return (group_commitment, z)
	return &Signature{groupCommitment, z}, nil
}
