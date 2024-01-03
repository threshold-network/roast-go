package frost

import (
	"encoding/binary"
	"math/big"
)

// Participant implements the base functionality for all [FROST] protocol
// participants, no matter the participant type: signer, coordinator, or both.
type Participant struct {
	ciphersuite Ciphersuite

	publicKey *Point // group_public_key in [FROST]
}

// NonceCommitment is a message produced in Round One of [FROST].
type NonceCommitment struct {
	signerIndex            uint64
	hidingNonceCommitment  *Point
	bindingNonceCommitment *Point
}

// bindingFactors is a helper structure produced by computeBindingFactors function.
type bindingFactors map[uint64]*big.Int

// computeBindingFactors implements def compute_binding_factors(group_public_key,
// commitment_list, msg) function from [FROST], as defined in section 4.4. Binding
// Factors Computation.
//
// The function calling computeBindingFactors must ensure a valid number of
// commitments have been received and call validateGroupCommitment to validate
// the received commitments.
func (p *Participant) computeBindingFactors(
	message []byte,
	commitments []*NonceCommitment,
) bindingFactors {
	// From [FROST]:
	//
	// 4.4.  Binding Factors Computation
	//
	//   This section describes the subroutine for computing binding factors
	//   based on the participant commitment list, message to be signed, and
	//   group public key.
	//
	//   Inputs:
	//     - group_public_key, the public key corresponding to the group signing
	//       key, an Element.
	//     - commitment_list = [(i, hiding_nonce_commitment_i,
	//       binding_nonce_commitment_i), ...], a list of commitments issued by
	//       each participant, where each element in the list indicates a
	//       NonZeroScalar identifier i and two commitment Element values
	//       (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list
	//       MUST be sorted in ascending order by identifier.
	//     - msg, the message to be signed.
	//
	//   Outputs:
	//     - binding_factor_list, a list of (NonZeroScalar, Scalar) tuples
	//       representing the binding factors.

	// group_public_key_enc = G.SerializeElement(group_public_key)
	curve := p.ciphersuite.Curve()
	groupPublicKeyEncoded := curve.SerializePoint(p.publicKey)

	// msg_hash = H4(msg)
	msgHash := p.ciphersuite.H4(message)

	// encoded_commitment_hash =
	//    H5(encode_group_commitment_list(commitment_list))
	groupCommitmentEncoded := p.encodeGroupCommitment(commitments)
	encodedCommitHash := p.ciphersuite.H5(groupCommitmentEncoded)

	// rho_input_prefix = group_public_key_enc || msg_hash || encoded_commitment_hash
	rhoInputPrefix := concat(groupPublicKeyEncoded, msgHash, encodedCommitHash)

	// binding_factor_list = []
	bindingFactors := make(map[uint64]*big.Int, len(commitments))

	// for (identifier, hiding_nonce_commitment,
	//      binding_nonce_commitment) in commitment_list:
	for _, commitment := range commitments {
		// rho_input = rho_input_prefix || G.SerializeScalar(identifier)
		rhoInput := make([]byte, len(rhoInputPrefix)+8)
		copy(rhoInput, rhoInputPrefix)
		binary.BigEndian.AppendUint64(rhoInput, commitment.signerIndex)
		// binding_factor = H1(rho_input)
		bindingFactor := p.ciphersuite.H1(rhoInput)
		// binding_factor_list.append((identifier, binding_factor))
		bindingFactors[commitment.signerIndex] = bindingFactor
	}

	// return binding_factor_list
	return bindingFactors
}

// computeGroupCommitment implements def compute_group_commitment(commitment_list,
// binding_factor_list) function from [FROST], as defined in section 4.5. Group
// Commitment Computation.
//
// The function calling computeGroupCommitment must ensure a valid number of
// commitments have been received and call validateGroupCommitment to validate
// the received commitments.
func (p *Participant) computeGroupCommitment(
	commitments []*NonceCommitment,
	bindingFactors bindingFactors,
) *Point {
	// From [FROST]:
	//
	// 4.5.  Group Commitment Computation
	//
	//   This section describes the subroutine for creating the group
	//   commitment from a commitment list.
	//
	//   Inputs:
	//     - commitment_list = [(i, hiding_nonce_commitment_i,
	//       binding_nonce_commitment_i), ...], a list of commitments issued by
	//       each participant, where each element in the list indicates a
	//       NonZeroScalar identifier i and two commitment Element values
	//       (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list
	//       MUST be sorted in ascending order by identifier.
	//     - binding_factor_list = [(i, binding_factor), ...],
	//       a list of (NonZeroScalar, Scalar) tuples representing the binding
	//       factor Scalar for the given identifier.
	//
	//   Outputs:
	//     - group_commitment, an Element.

	curve := p.ciphersuite.Curve()

	// group_commitment = G.Identity()
	groupCommitment := curve.Identity()

	// for (identifier, hiding_nonce_commitment,
	//     binding_nonce_commitment) in commitment_list:
	for _, commitment := range commitments {
		// binding_factor = binding_factor_for_participant(
		//     binding_factor_list, identifier)
		bindingFactor := bindingFactors[commitment.signerIndex]
		// binding_nonce = G.ScalarMult(
		//     binding_nonce_commitment,
		//     binding_factor)
		bindingNonce := curve.EcMul(
			commitment.bindingNonceCommitment,
			bindingFactor,
		)
		// group_commitment = (
		//     group_commitment +
		//     hiding_nonce_commitment +
		//     binding_nonce)
		groupCommitment = curve.EcAdd(
			groupCommitment,
			curve.EcAdd(commitment.hidingNonceCommitment, bindingNonce),
		)
	}

	// return group_commitment
	return groupCommitment
}

// encodeGroupCommitment implements def encode_group_commitment_list(commitment_list)
// function from [FROST], as defined in section 4.3. List Operations.
//
// The function calling encodeGroupCommitment must ensure a valid number of
// commitments have been received and call validateGroupCommitment to validate
// the received commitments.
func (p *Participant) encodeGroupCommitment(
	commitments []*NonceCommitment,
) []byte {
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
	//
	//   def encode_group_commitment_list(commitment_list):

	curve := p.ciphersuite.Curve()
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

// deriveInterpolatingValue implements def derive_interpolating_value(L, x_i)
// function from [FROST], as defined in section 4.2 Polynomials.
// L is the list of the indices of the members of the particular group.
// xi is the index of the participant i.
//
// The function calling deriveInterpolatingValue must ensure a valid number of
// commitments have been received and call validateGroupCommitment to validate
// the received commitments.
func (p *Participant) deriveInterpolatingValue(xi uint64, L []uint64) *big.Int {
	// From [FROST]:
	//
	// 4.2.  Polynomials
	//
	//   This section defines polynomials over Scalars that are used in the
	//   main protocol.  A polynomial of maximum degree t is represented as a
	//   list of t+1 coefficients, where the constant term of the polynomial
	//   is in the first position and the highest-degree coefficient is in the
	//   last position.  For example, the polynomial x^2 + 2x + 3 has degree 2
	//   and is represented as a list of 3 coefficients [3, 2, 1].  A point on
	//   the polynomial f is a tuple (x, y), where y = f(x).
	//
	//   The function derive_interpolating_value derives a value used for
	//   polynomial interpolation.  It is provided a list of x-coordinates as
	//   input, each of which cannot equal 0.
	//
	//   Inputs:
	//     - L, the list of x-coordinates, each a NonZeroScalar.
	//     - x_i, an x-coordinate contained in L, a NonZeroScalar.
	//
	//   Outputs:
	//     - value, a Scalar.
	//
	//   Errors:
	//     - "invalid parameters", if 1) x_i is not in L, or if 2) any
	//       x-coordinate is represented more than once in L.
	//
	//   def derive_interpolating_value(L, x_i):

	// Note that the validation is handled in validateGroupCommitment function.

	order := p.ciphersuite.Curve().Order()
	// numerator = Scalar(1)
	num := big.NewInt(1)
	// denominator = Scalar(1)
	den := big.NewInt(1)
	// for x_j in L:
	for _, xj := range L {
		if xj == xi {
			// if x_j == x_i: continue
			continue
		}
		// numerator *= x_j
		num.Mul(num, big.NewInt(int64(xj)))
		num.Mod(num, order)
		// denominator *= x_j - x_i
		den.Mul(den, big.NewInt(int64(xj)-int64(xi)))
		den.Mod(den, order)
	}

	// value = numerator / denominator
	denInv := new(big.Int).ModInverse(den, order)
	res := new(big.Int).Mul(num, denInv)
	res = res.Mod(res, order)

	// return value
	return res
}

// computeChallenge implements def compute_group_commitment(commitment_list,
// binding_factor_list) from [FROST] as defined in section 4.6. Signature
// Challenge Computation.
func (p *Participant) computeChallenge(
	message []byte,
	groupCommitment *Point,
) *big.Int {

	// From [FROST]:
	//
	// 4.6.  Signature Challenge Computation
	//
	//   This section describes the subroutine for creating the per-message
	//   challenge.
	//
	//   Inputs:
	//     - group_commitment, the group commitment, an Element.
	//     - group_public_key, the public key corresponding to the group signing
	//       key, an Element.
	//     - msg, the message to be signed, a byte string.
	//
	//   Outputs:
	//     - challenge, a Scalar.
	//
	// def compute_group_commitment(commitment_list, binding_factor_list)

	curve := p.ciphersuite.Curve()
	// group_comm_enc = G.SerializeElement(group_commitment)
	groupCommitmentEncoded := curve.SerializePoint(groupCommitment)
	// group_public_key_enc = G.SerializeElement(group_public_key)
	publicKeyEncoded := curve.SerializePoint(p.publicKey)
	// challenge_input = group_comm_enc || group_public_key_enc || msg
	// challenge = H2(challenge_input)
	// return challenge
	return p.ciphersuite.H2(groupCommitmentEncoded, publicKeyEncoded, message)
}
