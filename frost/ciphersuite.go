package frost

import "math/big"

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
	EcBaseMul(*big.Int) *Point
}

// Point represents a valid point on the Curve.
type Point struct {
	X *big.Int // the X coordinate of the point
	Y *big.Int // the Y coordinate of the point
}
