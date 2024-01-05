package frost

import (
	"fmt"
	"math/big"
)

// Ciphersuite interface abstracts out the particular ciphersuite implementation
// used for the [FROST] protocol execution. This is a strategy design pattern
// allowing to use [FROST] with different ciphersuites, like BIP-340 (secp256k1)
// or Jubjub. A [FROST] ciphersuite must specify the underlying prime-order group
// details and cryptographic hash functions.
type Ciphersuite interface {
	Hashing
	Curve() Curve

	// EncodePoint encodes the given elliptic curve point to a byte slice in
	// a way that is *specific* to the given ciphersuite needs. This is
	// especially important when calculating a signature challenge in [FROST].
	//
	// This function may yield a different result than SerializePoint function
	// from the Curve interface. While the SerializePoint result should be
	// considered an internal serialization that may be optimized for speed or
	// data consistency, the EncodePoint result should be considered an external
	// serialization, always reflecting the given ciphersuite's specification
	// requirements.
	EncodePoint(point *Point) []byte

	// VerifySignature verifies the provided signature for the message against
	// the group public key. The function returns true and nil error when the
	// signature is valid. The function returns false and an error when the
	// signature is valid. The error provides a detailed explanation on why
	// the signature verification failed.
	VerifySignature(
		signature *Signature,
		publicKey *Point,
		message []byte,
	) (bool, error)
}

// Hashing interface abstracts out hash functions implementations specific to the
// ciphersuite used.
//
// [FROST] requires the use of a cryptographically secure hash function,
// generically written as H. Using H, [FROST] introduces distinct domain-separated
// hashes, H1, H2, H3, H4, and H5. The details of H1, H2, H3, H4, and H5 vary
// based on ciphersuite.
//
// Note that for some of those functions it may be important to use a specific
// encoding of elliptic curve points depending on the ciphersuite being
// implemented.
type Hashing interface {
	H1(m []byte) *big.Int
	H2(m []byte, ms ...[]byte) *big.Int
	H3(m []byte, ms ...[]byte) *big.Int
	H4(m []byte) []byte
	H5(m []byte) []byte
}

// Curve interface abstracts out the particular elliptic curve implementation
// specific to the ciphersuite used.
type Curve interface {
	// EcBaseMul returns k*G, where G is the base point of the group.
	EcBaseMul(*big.Int) *Point

	// EcMul returns k*P where P is the point provided as a parameter and k is
	// as integer.
	EcMul(*Point, *big.Int) *Point

	// EcAdd returns the sum of two elliptic curve points.
	EcAdd(*Point, *Point) *Point

	// EcSub returns the subtraction of two elliptic curve points.
	EcSub(*Point, *Point) *Point

	// Identity returns elliptic curve identity element.
	Identity() *Point

	// Order returns the order of the group produced by the elliptic curve
	// generator.
	Order() *big.Int

	// IsPointOnCurve validates if the point lies on the curve and is not an
	// identity element.
	//
	// [FROST] requires to validate if we are dealing with a valid element of
	// the group and that element is a non-identity element.
	// For elliptic curve cryptography, we do not have an identity element but
	// we take the point at infinity as an identity element. The point at
	// infinity is an extra point O and it is not on the curve. In our case it
	// is enough to validate if the point is on the curve. This validation will
	// satisfy [FROST] requirements of a valid, non-identity element of the
	// group.
	IsPointOnCurve(*Point) bool

	// SerializedPointLength returns the byte length of a serialized curve point.
	// The value is specific to the implementation. It is expected that the
	// SerializePoint function always return a slice of this length and the
	// DeserializePoint can only deserialize byte slice of this length.
	SerializedPointLength() int

	// SerializePoint serializes the provided elliptic curve point to bytes.
	// The byte slice returned must always have a length equal to
	// SerializedPointLength().
	SerializePoint(*Point) []byte

	// DeserializePoint deserializes byte slice to an elliptic curve point. The
	// byte slice length must be equal to SerializedPointLength(). Otherwise,
	// the function returns nil.
	DeserializePoint([]byte) *Point
}

// Point represents a valid point on the Curve.
type Point struct {
	X *big.Int // the X coordinate of the point
	Y *big.Int // the Y coordinate of the point
}

// String transforms Point structure into a string so that it can be used
// in logging.
func (p *Point) String() string {
	return fmt.Sprintf("Point[X=0x%v, Y=0x%v]", p.X.Text(16), p.Y.Text(16))
}

// Signature represents a Schnorr signature produced by [FROST] protocol as
// a result of the signature share aggregation. Note that the signature produced
// by the signature share aggregation in [FROST] may not be valid if there are
// malicious signers present.
type Signature struct {
	R *Point   // R in [FROST] appendix C
	Z *big.Int // z in [FROST] appendix C
}
