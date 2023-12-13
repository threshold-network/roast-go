package roast

import (
	"crypto/sha256"
	"math/big"
)

// The contextString as defined in section 6.5. FROST(secp256k1, SHA-256) of
// [FROST] is "FROST-secp256k1-SHA256-v1". Since we do a BIP-340 specialized
// version, we use "FROST-secp256k1-BIP340-v1" as the contextString.
var contextString = []byte("FROST-secp256k1-BIP340-v1")

// h1 is the implementation of H1(m) function from [FROST] implemented in a way
// compatible to how [BIP340] hashing functions are specified.
func h1(m []byte) *big.Int {
	dst := concat(contextString, []byte("rho"))
	return hashToScalar(dst, m)
}

// hashToScalar computes [BIP340] tagged hash of the message and turns it into
// a scalar modulo secp256k1 curve order, as specified in [BIP340].
func hashToScalar(tag, msg []byte) *big.Int {
	hashed := bip340Hash(tag, msg)
	ej := os2ip(hashed[:])

	// This is not safe for all curves. As explained in [BIP340]:
	//
	// Note that in general, taking a uniformly random 256-bit integer modulo
	// the curve order will produce an unacceptably biased result. However, for
	// the secp256k1 curve, the order is sufficiently close to 2256 that this
	// bias is not observable (1 - n / 2^256 is around 1.27 * 2^-128).
	ej.Mod(ej, G.N)

	return ej
}

// bip340Hash implements the hash function as defined in [BIP340].
func bip340Hash(tag, msg []byte) [32]byte {
	// From [BIP340] specification section:
	//
	// The function hash_name(x) where x is a byte array returns the 32-byte hash
	// SHA256(SHA256(tag) || SHA256(tag) || x), where tag is the UTF-8 encoding
	// of name.
	hashedTag := sha256.Sum256(tag)
	slicedTag := hashedTag[:]
	hashed := sha256.Sum256(concat(slicedTag, slicedTag, msg))

	return hashed
}

// concat performs a concatenation of byte slices without the modification of
// the slices passed as parameters. A brand new slice instance is always
// returned from the function.
func concat(a []byte, bs ...[]byte) []byte {
	// From the Go documentation of the append function:
	//
	// "The append built-in function appends elements to the end of a slice. If
	// it has sufficient capacity, the destination is resliced to accommodate
	// the new elements. If it does not, a new underlying array will be
	// allocated."
	//
	// Using just append(a, b...) can modify a by extending its length
	// if it has sufficient capacity to hold b.
	// We want to avoid unexpected effects on a so we create a new slice c
	// and operate on it.
	c := make([]byte, len(a))
	copy(c, a)
	for _, b := range bs {
		c = append(c, b...)
	}
	return c
}

// os2ip converts byte array into a nonnegative integer as specified in
// [RFC8017] section 4.2.
func os2ip(b []byte) *big.Int {
	// From [RFC8017] section 4.2:
	//
	//  1. Let X_1 X_2 ... X_xLen be the octets of X from first to last,
	//     and let x_(xLen-i) be the integer value of the octet X_i for 1
	//     <= i <= xLen.
	//  2. Let x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) +
	//     ...  + x_1 256 + x_0.
	//  3. Output x.
	return new(big.Int).SetBytes(b)
}
