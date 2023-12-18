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
}

// Hashing interface abstracts out hash functions implementations specific to the
// ciphersuite used.
//
// [FROST] requires the use of a cryptographically secure hash function,
// generically written as H. Using H, [FROST] introduces distinct domain-separated
// hashes, H1, H2, H3, H4, and H5. The details of H1, H2, H3, H4, and H5 vary
// based on ciphersuite.
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

	// IsNotIdentity validates if the point lies on the curve and is not an
	// identity element.
	IsNotIdentity(*Point) bool

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
