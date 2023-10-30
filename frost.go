package main


import (
	"crypto/rand"
	"fmt"
	"math/big"
	// "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// nonce generations that salts randomness with the secret
func genNonce(secret []byte) *big.Int {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return H3(concat(b, secret))
}

type Commit struct {
	i uint64 // participant index
	hnc Point // hiding nonce commitment
	bnc Point // blinding nonce commitment
}

type BindingFactor struct {
	i uint64 // participant index
	bf *big.Int // binding factor
}

type Nonce struct {
	hn *big.Int // hiding nonce
	bn *big.Int // blinding nonce
}

type Signature struct {
	R Point
	z *big.Int
}

type SigVerifyPrecalc struct {
	bfs []BindingFactor
	challenge *big.Int
}

func toBytes(x uint64) []byte {
	b := make([]byte, 8)
	return big.NewInt(int64(x)).FillBytes(b)
}

/*
4.3.  List Operations

   This section describes helper functions that work on lists of values
   produced during the FROST protocol.  The following function encodes a
   list of participant commitments into a byte string for use in the
   FROST protocol.

   Inputs:
   - commitment_list = [(i, hiding_nonce_commitment_i,
     binding_nonce_commitment_i), ...], a list of commitments issued by
     each participant, where each element in the list indicates a
     NonZeroScalar identifier i and two commitment Element values
     (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list
     MUST be sorted in ascending order by identifier.

   Outputs:
   - encoded_group_commitment, the serialized representation of
     commitment_list, a byte string.
*/
// def encode_group_commitment_list(commitment_list):
func encodeGroupCommitment(cs []Commit) []byte {
	// encoded_group_commitment = nil
	b := make([]byte, 0)
	// for (identifier, hiding_nonce_commitment,
	//      binding_nonce_commitment) in commitment_list:
	for _, ci := range cs {
		// encoded_commitment = (
		//     G.SerializeScalar(identifier) ||
		//     G.SerializeElement(hiding_nonce_commitment) ||
		//     G.SerializeElement(binding_nonce_commitment))
		// encoded_group_commitment = (
		//     encoded_group_commitment ||
		//     encoded_commitment)
		b = concat(b, toBytes(ci.i), ci.hnc.Bytes(), ci.bnc.Bytes())
	}
	// return encoded_group_commitment
	return b
}

/*
   The following function is used to extract identifiers from a
   commitment list.

   Inputs:
   - commitment_list = [(i, hiding_nonce_commitment_i,
     binding_nonce_commitment_i), ...], a list of commitments issued by
     each participant, where each element in the list indicates a
     NonZeroScalar identifier i and two commitment Element values
     (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list
     MUST be sorted in ascending order by identifier.

   Outputs:
   - identifiers, a list of NonZeroScalar values.
*/
// def participants_from_commitment_list(commitment_list):
func participantsFromCommitList(cs []Commit) []uint64 {
	// identifiers = []
	ms := make([]uint64, len(cs))
	prev := uint64(0)

	// for (identifier, _, _) in commitment_list:
	//     identifiers.append(identifier)
	for i, ci := range cs {
		ms[i] = ci.i
		if (ci.i <= prev) {
			panic("invalid order in commit list")
		}
		prev = ci.i
	}
	// return identifiers
	return ms
}

/*
The following function is used to extract a binding factor from a
   list of binding factors.

   Inputs:
   - binding_factor_list = [(i, binding_factor), ...],
     a list of binding factors for each participant, where each element
     in the list indicates a NonZeroScalar identifier i and Scalar
     binding factor.
   - identifier, participant identifier, a NonZeroScalar.

   Outputs:
   - binding_factor, a Scalar.

   Errors:
   - "invalid participant", when the designated participant is
     not known.
*/
// def binding_factor_for_participant(binding_factor_list, identifier):
func bindingFactorForParticipant(bfs []BindingFactor, i uint64) *big.Int {
	// for (i, binding_factor) in binding_factor_list:
	for _, b := range bfs {
		// if identifier == i:
		//     return binding_factor
		if (b.i == i) {
			return b.bf
		}
	}
	// raise "invalid participant"
	panic("binding factor not found")
}

/*
4.4.  Binding Factors Computation

   This section describes the subroutine for computing binding factors
   based on the participant commitment list, message to be signed, and
   group public key.

Inputs:
- group_public_key, the public key corresponding to the group signing
  key, an Element.
- commitment_list = [(i, hiding_nonce_commitment_i,
  binding_nonce_commitment_i), ...], a list of commitments issued by
  each participant, where each element in the list indicates a
  NonZeroScalar identifier i and two commitment Element values
  (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list
  MUST be sorted in ascending order by identifier.
- msg, the message to be signed.

Outputs:
- binding_factor_list, a list of (NonZeroScalar, Scalar) tuples
  representing the binding factors.
*/
// def compute_binding_factors(group_public_key, commitment_list, msg):
func computeBindingFactors(pk Point, cs []Commit, msg []byte) []BindingFactor {
	// group_public_key_enc = G.SerializeElement(group_public_key)
	groupPubkeyEnc := pk.Bytes()
	// // Hashed to a fixed-length.
  	// msg_hash = H4(msg)
	msgHash := H4(msg)
	// encoded_commitment_hash =
	//    H5(encode_group_commitment_list(commitment_list))
	encodedCommitHash := H5(encodeGroupCommitment(cs))
	// // The encoding of the group public key is a fixed length within a ciphersuite.
	// rho_input_prefix = group_public_key_enc || msg_hash || encoded_commitment_hash
	rhoInputPrefix := concat(groupPubkeyEnc, msgHash, encodedCommitHash)

	// binding_factor_list = []
	bfs := make([]BindingFactor, len(cs))

	// for (identifier, hiding_nonce_commitment,
	//      binding_nonce_commitment) in commitment_list:
	for j, cj := range cs {
		// rho_input = rho_input_prefix || G.SerializeScalar(identifier)
		rhoInput := concat(rhoInputPrefix, toBytes(cj.i))
		// binding_factor = H1(rho_input)
		bf := H1(rhoInput)
		// binding_factor_list.append((identifier, binding_factor))
		bfs[j] = BindingFactor{cj.i, bf}
	}
	// return binding_factor_list
	return bfs
}

/*
4.5.  Group Commitment Computation

   This section describes the subroutine for creating the group
   commitment from a commitment list.

   Inputs:
   - commitment_list = [(i, hiding_nonce_commitment_i,
     binding_nonce_commitment_i), ...], a list of commitments issued by
     each participant, where each element in the list indicates a
     NonZeroScalar identifier i and two commitment Element values
     (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list
     MUST be sorted in ascending order by identifier.
   - binding_factor_list = [(i, binding_factor), ...],
     a list of (NonZeroScalar, Scalar) tuples representing the binding
     factor Scalar for the given identifier.

   Outputs:
   - group_commitment, an Element.
*/
// def compute_group_commitment(commitment_list, binding_factor_list):
func computeGroupCommitment(cs []Commit, bfs []BindingFactor) Point {
	// group_commitment = G.Identity()
	gc := G.ID()

	// for (identifier, hiding_nonce_commitment,
	//     binding_nonce_commitment) in commitment_list:
	for _, ci := range cs {
		// binding_factor = binding_factor_for_participant(
		//     binding_factor_list, identifier)
		bf := bindingFactorForParticipant(bfs, ci.i)
		// binding_nonce = G.ScalarMult(
		//     binding_nonce_commitment,
		//     binding_factor)
		bn := EcMul(ci.bnc, bf)
		// group_commitment = (
		//     group_commitment +
		//     hiding_nonce_commitment +
		//     binding_nonce)
		gc = EcAdd(gc, EcAdd(ci.hnc, bn))
	}

	// return group_commitment
	return gc
}

/*
4.6.  Signature Challenge Computation

   This section describes the subroutine for creating the per-message
   challenge.

   Inputs:
   - group_commitment, the group commitment, an Element.
   - group_public_key, the public key corresponding to the group signing
     key, an Element.
   - msg, the message to be signed, a byte string.

   Outputs:
   - challenge, a Scalar.
*/
// def compute_challenge(group_commitment, group_public_key, msg):
func computeChallenge(gc Point, pk Point, msg []byte) *big.Int {
	// group_comm_enc = G.SerializeElement(group_commitment)
	// group_public_key_enc = G.SerializeElement(group_public_key)
	// challenge_input = group_comm_enc || group_public_key_enc || msg
	// challenge = H2(challenge_input)
	gcb := gc.ToBytes32()
	pkb := pk.ToBytes32()
	challenge := BIP340HashChallenge(gcb[:], pkb[:], msg)
	// return challenge
	return FromBytes32(challenge)
}

/*
5.1.  Round One - Commitment

   Round one involves each participant generating nonces and their
   corresponding public commitments.  A nonce is a pair of Scalar
   values, and a commitment is a pair of Element values.  Each
   participant's behavior in this round is described by the commit
   function below.  Note that this function invokes nonce_generate
   twice, once for each type of nonce produced.  The output of this
   function is a pair of secret nonces (hiding_nonce, binding_nonce) and
   their corresponding public commitments (hiding_nonce_commitment,
   binding_nonce_commitment).

   Inputs:
   - sk_i, the secret key share, a Scalar.

   Outputs:
   - (nonce, comm), a tuple of nonce and nonce commitment pairs,
     where each value in the nonce pair is a Scalar and each value in
     the nonce commitment pair is an Element.
*/
// def commit(sk_i):
func round1(i uint64, ski *big.Int) (Nonce, Commit) {
	// hiding_nonce = nonce_generate(sk_i)
	hn := genNonce(ski.Bytes())
	// binding_nonce = nonce_generate(sk_i)
	bn := genNonce(ski.Bytes())
	// hiding_nonce_commitment = G.ScalarBaseMult(hiding_nonce)
	hnc := EcBaseMul(hn)
	// binding_nonce_commitment = G.ScalarBaseMult(binding_nonce)
	bnc := EcBaseMul(bn)

	// nonces = (hiding_nonce, binding_nonce)
	// comms = (hiding_nonce_commitment, binding_nonce_commitment)
	// return (nonces, comms)
	return Nonce{hn, bn}, Commit{i, hnc, bnc}
}

/*
5.2.  Round Two - Signature Share Generation

   In round two, the Coordinator is responsible for sending the message
   to be signed, and for choosing which participants will participate
   (of number at least MIN_PARTICIPANTS).  Signers additionally require
   locally held data; specifically, their private key and the nonces
   corresponding to their commitment issued in round one.

   The Coordinator begins by sending each participant the message to be
   signed along with the set of signing commitments for all participants
   in the participant list.  Each participant MUST validate the inputs
   before processing the Coordinator's request.  In particular, the
   Signer MUST validate commitment_list, deserializing each group
   Element in the list using DeserializeElement from Section 3.1.  If
   deserialization fails, the Signer MUST abort the protocol.  Moreover,
   each participant MUST ensure that its identifier and commitments
   (from the first round) appear in commitment_list.  Applications which
   require that participants not process arbitrary input messages are
   also required to perform relevant application-layer input validation
   checks; see Section 7.7 for more details.

   Upon receipt and successful input validation, each Signer then runs
   the following procedure to produce its own signature share.

Connolly, et al.          Expires 22 March 2024                [Page 22]
Internet-Draft                    FROST                   September 2023

Inputs:
- identifier, identifier i of the participant, a NonZeroScalar.
- sk_i, Signer secret key share, a Scalar.
- group_public_key, public key corresponding to the group signing
  key, an Element.
- nonce_i, pair of Scalar values (hiding_nonce, binding_nonce)
  generated in round one.
- msg, the message to be signed, a byte string.
- commitment_list = [(i, hiding_nonce_commitment_i,
  binding_nonce_commitment_i), ...], a list of commitments issued by
  each participant, where each element in the list indicates a
  NonZeroScalar identifier i and two commitment Element values
  (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list
  MUST be sorted in ascending order by identifier.

Outputs:
- sig_share, a signature share, a Scalar.
*/
// def sign(identifier, sk_i, group_public_key,
//          nonce_i, msg, commitment_list):
func round2(i uint64, ski *big.Int, pk Point, nonce Nonce, msg []byte, cs []Commit) *big.Int {
	// # Compute the binding factor(s)
	// binding_factor_list = compute_binding_factors(group_public_key, commitment_list, msg)
	bfs := computeBindingFactors(pk, cs, msg)
	// binding_factor = binding_factor_for_participant(binding_factor_list, identifier)
	bf := bindingFactorForParticipant(bfs, i)

	// # Compute the group commitment
	// group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
	gc := computeGroupCommitment(cs, bfs)

	// # Compute the interpolating value
	// participant_list = participants_from_commitment_list(commitment_list)
	members := participantsFromCommitList(cs)
	// lambda_i = derive_interpolating_value(participant_list, identifier)
	lambda_i := deriveInterpolatingValue(i, members)

	// # Compute the per-message challenge
	// challenge = compute_challenge(group_commitment, group_public_key, msg)
	challenge := computeChallenge(gc, pk, msg)

	// # Compute the signature share
	// (hiding_nonce, binding_nonce) = nonce_i
	// sig_share = hiding_nonce + (binding_nonce * binding_factor) + (lambda_i * sk_i * challenge)
	bnbf := new(big.Int).Mul(nonce.bn, bf)
	lski := new(big.Int).Mul(lambda_i, ski)
	lskic := new(big.Int).Mul(lski, challenge)

	bnbflskic := new(big.Int).Add(bnbf, lskic)

	sigShare := new(big.Int).Add(nonce.hn, bnbflskic)

	// return sig_share
	return sigShare
}

/*
5.3.  Signature Share Aggregation

   After participants perform round two and send their signature shares
   to the Coordinator, the Coordinator aggregates each share to produce
   a final signature.  Before aggregating, the Coordinator MUST validate
   each signature share using DeserializeScalar.  If validation fails,
   the Coordinator MUST abort the protocol as the resulting signature
   will be invalid.  If all signature shares are valid, the Coordinator
   aggregates them to produce the final signature using the following
   procedure.

Inputs:
- commitment_list = [(i, hiding_nonce_commitment_i,
  binding_nonce_commitment_i), ...], a list of commitments issued by
  each participant, where each element in the list indicates a
  NonZeroScalar identifier i and two commitment Element values
  (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list
  MUST be sorted in ascending order by identifier.
- msg, the message to be signed, a byte string.
- group_public_key, public key corresponding to the group signing
  key, an Element.
- sig_shares, a set of signature shares z_i, Scalar values, for each
  participant, of length NUM_PARTICIPANTS, where
  MIN_PARTICIPANTS <= NUM_PARTICIPANTS <= MAX_PARTICIPANTS.

Outputs:
- (R, z), a Schnorr signature consisting of an Element R and
  Scalar z.
*/
// def aggregate(commitment_list, msg, group_public_key, sig_shares):
func aggregate(pk Point, cs []Commit, msg []byte, shares []*big.Int) Signature {
	// # Compute the binding factors
	// binding_factor_list = compute_binding_factors(group_public_key, commitment_list, msg)
	bfs := computeBindingFactors(pk, cs, msg)

	// # Compute the group commitment
	// group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
	gc := computeGroupCommitment(cs, bfs)

	// # Compute aggregated signature
	// z = Scalar(0)
	z := big.NewInt(0)
	// for z_i in sig_shares:
    //     z = z + z_i
	for _, zi := range shares {
		z.Add(z, zi)
		z.Mod(z, G.q())
	}

	e := computeChallenge(gc, pk, msg)

	R := EcSub(EcBaseMul(z), EcMul(pk, e))
	fmt.Println(R.Y)

	// return (group_commitment, z)
	return Signature{gc, z}
}

/*
   The function for verifying a signature share, denoted
   verify_signature_share, is described below.  Recall that the
   Coordinator is configured with "group info" which contains the group
   public key PK and public keys PK_i for each participant, so the
   group_public_key and PK_i function arguments MUST come from that
   previously stored group info.

Inputs:
- identifier, identifier i of the participant, a NonZeroScalar.
- PK_i, the public key for the i-th participant, where
  PK_i = G.ScalarBaseMult(sk_i), an Element.
- comm_i, pair of Element values in G
  (hiding_nonce_commitment, binding_nonce_commitment) generated in
  round one from the i-th participant.
- sig_share_i, a Scalar value indicating the signature share as
  produced in round two from the i-th participant.
- commitment_list = [(i, hiding_nonce_commitment_i,
  binding_nonce_commitment_i), ...], a list of commitments issued by
  each participant, where each element in the list indicates a
  NonZeroScalar identifier i and two commitment Element values
  (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list
  MUST be sorted in ascending order by identifier.
- group_public_key, public key corresponding to the group signing
  key, an Element.
- msg, the message to be signed, a byte string.

Outputs:
- True if the signature share is valid, and False otherwise.
*/
// def verify_signature_share(
//     identifier, PK_i, comm_i, sig_share_i, commitment_list,
//     group_public_key, msg):
func verifySignatureShare(
	i uint64,
	pk_i Point,
	commit_i Commit,
	sigShare_i *big.Int,
	cs []Commit,
	pk Point,
	msg []byte,
) bool {
	// # Compute the binding factors
	// binding_factor_list = compute_binding_factors(group_public_key, commitment_list, msg)
	bfs := computeBindingFactors(pk, cs, msg)
	// binding_factor = binding_factor_for_participant(binding_factor_list, identifier)
	bf := bindingFactorForParticipant(bfs, i)

	// # Compute the group commitment
	// group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
	gc := computeGroupCommitment(cs, bfs)

	// # Compute the commitment share
	// (hiding_nonce_commitment, binding_nonce_commitment) = comm_i
	// comm_share = hiding_nonce_commitment + G.ScalarMult(
	//     binding_nonce_commitment, binding_factor)
	cShare := EcAdd(commit_i.hnc, EcMul(commit_i.bnc, bf))

	// # Compute the challenge
	// challenge = compute_challenge(
	//     group_commitment, group_public_key, msg)
	challenge := computeChallenge(gc, pk, msg)

	// # Compute the interpolating value
	// participant_list = participants_from_commitment_list(commitment_list)
	members := participantsFromCommitList(cs)
	// lambda_i = derive_interpolating_value(participant_list, identifier)
	lambda_i := deriveInterpolatingValue(i, members)

	cli := new(big.Int).Mul(challenge, lambda_i)

	// # Compute relation values
	// l = G.ScalarBaseMult(sig_share_i)
	l := EcBaseMul(sigShare_i)
	// r = comm_share + G.ScalarMult(PK_i, challenge * lambda_i)
	r := EcAdd(cShare, EcMul(pk_i, cli))

	// return l == r
	return PointsEq(l, r)
}

// Same as above, but use cached binding factors and challenge,
// only calculating them on the first call on the attempt.
// This constitutes a major saving in coordinator overhead,
// especially with large group sizes.
func verifySignatureSharePrecalc(
	i uint64,
	pk_i Point,
	commit_i Commit,
	sigShare_i *big.Int,
	cs []Commit,
	pk Point,
	msg []byte,
	precalc *SigVerifyPrecalc,
) bool {
	if precalc.challenge == nil {
		// fmt.Println("calculating shared values for signature share verification")
		bfs := computeBindingFactors(pk, cs, msg)
		gc := computeGroupCommitment(cs, bfs)
		challenge := computeChallenge(gc, pk, msg)

		precalc.bfs = bfs
		precalc.challenge = challenge
	}
	bf := bindingFactorForParticipant(precalc.bfs, i)
	cShare := EcAdd(commit_i.hnc, EcMul(commit_i.bnc, bf))
	members := participantsFromCommitList(cs)
	lambda_i := deriveInterpolatingValue(i, members)
	cli := new(big.Int).Mul(precalc.challenge, lambda_i)
	l := EcBaseMul(sigShare_i)
	r := EcAdd(cShare, EcMul(pk_i, cli))
	return PointsEq(l, r)
}

func ToBIP340(sig Signature) BIP340Signature {
	return BIP340Signature{ ToBytes32(sig.R.X), ToBytes32(sig.z) }
}