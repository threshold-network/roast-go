package frost

import (
	"crypto/sha256"
	"math/big"
)

// Hash interface abstracts out hash functions implementations specific to the
// ciphersuite used. This is a strategy design pattern allowing to use FROST
// with different ciphersuites, like secp256k1 or Jubjub curves.
//
// [FROST] requires the use of a cryptographically secure hash function,
// generically written as H. Using H, [FROST] introduces distinct domain-separated
// hashes, H1, H2, H3, H4, and H5. The details of H1, H2, H3, H4, and H5 vary
// based on ciphersuite.
type Hash interface {
	H1(m []byte) *big.Int
	H2(m []byte, ms ...[]byte) *big.Int
	H3(m []byte, ms ...[]byte) *big.Int
	H4(m []byte) []byte
	H5(m []byte) []byte
}

// Bip340Hash is [BIP-340] implementation of [FROST] functions required by the
// `Hash` interface.
type Bip340Hash struct {
}

// H1 is the implementation of H1(m) function from [FROST].
func (b *Bip340Hash) H1(m []byte) *big.Int {
	// From [FROST], we know the tag should be DST = contextString || "rho".
	dst := concat(b.contextString(), []byte("rho"))
	// We use [BIP-340]-compatible hashing algorithm and turn the hash into
	// a scalar, as expected by [FROST] for H1.
	return b.hashToScalar(dst, m)
}

// H2 is the implementation of H2(m) function from [FROST].
func (b *Bip340Hash) H2(m []byte, ms ...[]byte) *big.Int {
	// For H2, we need to use [BIP-340] tag because the verification algorithm
	// from [BIP034] expects this tag to be used:
	//
	// Let e = int(hash_BIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
	//
	// This is the only H* function where we MUST use the [BIP-340] tag.
	return b.hashToScalar([]byte("BIP0340/challenge"), concat(m, ms...))
}

// H3 is the implementation of H3(m) function from [FROST].
func (b *Bip340Hash) H3(m []byte, ms ...[]byte) *big.Int {
	// From [FROST], we know the tag should be DST = contextString || "nonce".
	dst := concat(b.contextString(), []byte("nonce"))
	// We use [BIP-340]-compatible hashing algorithm and turn the hash into
	// a scalar, as expected by [FROST] for H3.
	return b.hashToScalar(dst, concat(m, ms...))
}

// H4 is the implementation of H4(m) function from [FROST].
func (b *Bip340Hash) H4(m []byte, ms ...[]byte) []byte {
	// From [FROST], we know the tag should be DST = contextString || "msg".
	dst := concat(b.contextString(), []byte("msg"))
	hash := b.hash(dst, m)
	return hash[:]
}

// H5 is the implementation of H5(m) function from [FROST].
func (b *Bip340Hash) H5(m []byte, ms ...[]byte) []byte {
	// From [FROST], we know the tag should be DST = contextString || "com".
	dst := concat(b.contextString(), []byte("com"))
	hash := b.hash(dst, m)
	return hash[:]
}

// contextString is a contextString as required by [FROST] to be used in tagged
// hashes. The value is specific to [BIP-340] ciphersuite.
func (b *Bip340Hash) contextString() []byte {
	// The contextString as defined in section 6.5. FROST(secp256k1, SHA-256) of
	// [FROST] is "FROST-secp256k1-SHA256-v1". Since we do a BIP-340 specialized
	// version, we use "FROST-secp256k1-BIP340-v1".
	return []byte("FROST-secp256k1-BIP340-v1")
}

// hashToScalar computes [BIP-340] tagged hash of the message and turns it into
// a scalar modulo secp256k1 curve order, as specified in [BIP-340].
func (b *Bip340Hash) hashToScalar(tag, msg []byte) *big.Int {
	hashed := b.hash(tag, msg)
	ej := os2ip(hashed[:])

	// This is not safe for all curves. As explained in [BIP-340]:
	//
	// Note that in general, taking a uniformly random 256-bit integer modulo
	// the curve order will produce an unacceptably biased result. However, for
	// the secp256k1 curve, the order is sufficiently close to 2256 that this
	// bias is not observable (1 - n / 2^256 is around 1.27 * 2^-128).
	ej.Mod(ej, G.N)

	return ej
}

// hash implements the tagged hash function as defined in [BIP-340].
func (b *Bip340Hash) hash(tag, msg []byte) [32]byte {
	// From [BIP-340] specification section:
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
// [RFC-8017] section 4.2.
func os2ip(b []byte) *big.Int {
	// From [RFC-8017] section 4.2:
	//
	//  1. Let X_1 X_2 ... X_xLen be the octets of X from first to last,
	//     and let x_(xLen-i) be the integer value of the octet X_i for 1
	//     <= i <= xLen.
	//  2. Let x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) +
	//     ...  + x_1 256 + x_0.
	//  3. Output x.
	return new(big.Int).SetBytes(b)
}
