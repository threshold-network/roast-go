package frost

import (
	"crypto/sha256"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// Bip340Ciphersuite is [BIP-340] implementation of [FROST] ciphersuite.
// The ciphersuite uses secp256k1 elliptic curve as the prime-order group and
// Bitcoin hashing function implementation for H* [FROST] functions.
type Bip340Ciphersuite struct {
	curve *Bip340Curve
}

// NewBip340Ciphersuite creates a new instance of Bip340Ciphersuite in a state
// ready to be used for the [FROST] protocol execution.
func NewBip340Ciphersuite() *Bip340Ciphersuite {
	return &Bip340Ciphersuite{
		curve: &Bip340Curve{secp256k1.S256()},
	}
}

// Curve returns secp256k1 curve implementation used in [BIP-340].
func (b *Bip340Ciphersuite) Curve() Curve {
	return b.curve
}

type Bip340Curve struct {
	*secp256k1.BitCurve
}

// EcBaseMul returns k*G, where G is the base point of the group.
func (bc *Bip340Curve) EcBaseMul(k *big.Int) *Point {
	kmod := new(big.Int).Mod(k, bc.N)
	x, y := bc.ScalarBaseMult(kmod.Bytes())
	return &Point{x, y}
}

// EcMul returns k*P where P is the point provided as a parameter and k is
// as integer.
func (bc *Bip340Curve) EcMul(p *Point, k *big.Int) *Point {
	kmod := new(big.Int).Mod(k, bc.N)
	x, y := bc.ScalarMult(p.X, p.Y, kmod.Bytes())
	return &Point{x, y}
}

// EcAdd returns the sum of two elliptic curve points.
func (bc *Bip340Curve) EcAdd(a *Point, b *Point) *Point {
	x, y := bc.Add(a.X, a.Y, b.X, b.Y)
	return &Point{x, y}
}

// EcSub returns the subtraction of two elliptic curve points.
func (bc *Bip340Curve) EcSub(a *Point, b *Point) *Point {
	bNeg := &Point{b.X, new(big.Int).Neg(b.Y)}
	return bc.EcAdd(a, bNeg)
}

// Identity returns elliptic curve identity element.
func (bc *Bip340Curve) Identity() *Point {
	// For elliptic curves, the identity is the point at infinity.
	// For secp256k1 we pick a conventional representation as (0,0) in cartesian
	// coordinates. This is fine because 0,0 does not lie on the secp256k1 curve.
	return &Point{big.NewInt(0), big.NewInt(0)}
}

// Order returns the order of the group produced by the elliptic curve generator.
func (bc *Bip340Curve) Order() *big.Int {
	return new(big.Int).Set(bc.N)
}

// IsPointOnCurve validates if the point lies on the curve and is not an
// identity element.
func (bc *Bip340Curve) IsPointOnCurve(p *Point) bool {
	return bc.IsOnCurve(p.X, p.Y)
}

// SerializedPointLength returns the byte length of a serialized curve point.
func (b *Bip340Curve) SerializedPointLength() int {
	// From the Marshal() function of secp256k1 go-ethereum implementation:
	// 	 byteLen := (BitCurve.BitSize + 7) >> 3
	//   ret := make([]byte, 1+2*byteLen)
	return 65
}

// SerializePoint serializes the provided elliptic curve point to bytes.
// The slice length is equal to SerializedPointLength().
func (b *Bip340Curve) SerializePoint(p *Point) []byte {
	// Note that secp256k1 implementation uses a fixed length of
	// (BitCurve.BitSize + 7) >> 3
	return b.Marshal(p.X, p.Y)
}

// DeserializePoint deserializes byte slice to an elliptic curve point. The
// byte slice length must be equal to SerializedPointLength(). The deserialized
// point must be a valid, non-identity point lying on the curve. Otherwise,
// the function returns nil.
func (b *Bip340Curve) DeserializePoint(bytes []byte) *Point {
	x, y := b.Unmarshal(bytes)
	if x == nil || y == nil {
		return nil
	}

	point := &Point{x, y}

	if !b.IsPointOnCurve(point) {
		return nil
	}

	return point
}

// H1 is the implementation of H1(m) function from [FROST].
func (b *Bip340Ciphersuite) H1(m []byte) *big.Int {
	// From [FROST], we know the tag should be DST = contextString || "rho".
	dst := concat(b.contextString(), []byte("rho"))
	// We use [BIP-340]-compatible hashing algorithm and turn the hash into
	// a scalar, as expected by [FROST] for H1.
	return b.hashToScalar(dst, m)
}

// H2 is the implementation of H2(m) function from [FROST].
func (b *Bip340Ciphersuite) H2(m []byte, ms ...[]byte) *big.Int {
	// For H2, we need to use [BIP-340] tag because the verification algorithm
	// from [BIP034] expects this tag to be used:
	//
	// Let e = int(hash_BIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
	//
	// This is the only H* function where we MUST use the [BIP-340] tag.
	return b.hashToScalar([]byte("BIP0340/challenge"), concat(m, ms...))
}

// H3 is the implementation of H3(m) function from [FROST].
func (b *Bip340Ciphersuite) H3(m []byte, ms ...[]byte) *big.Int {
	// From [FROST], we know the tag should be DST = contextString || "nonce".
	dst := concat(b.contextString(), []byte("nonce"))
	// We use [BIP-340]-compatible hashing algorithm and turn the hash into
	// a scalar, as expected by [FROST] for H3.
	return b.hashToScalar(dst, concat(m, ms...))
}

// H4 is the implementation of H4(m) function from [FROST].
func (b *Bip340Ciphersuite) H4(m []byte) []byte {
	// From [FROST], we know the tag should be DST = contextString || "msg".
	dst := concat(b.contextString(), []byte("msg"))
	hash := b.hash(dst, m)
	return hash[:]
}

// H5 is the implementation of H5(m) function from [FROST].
func (b *Bip340Ciphersuite) H5(m []byte) []byte {
	// From [FROST], we know the tag should be DST = contextString || "com".
	dst := concat(b.contextString(), []byte("com"))
	hash := b.hash(dst, m)
	return hash[:]
}

// contextString is a contextString as required by [FROST] to be used in tagged
// hashes. The value is specific to [BIP-340] ciphersuite.
func (b *Bip340Ciphersuite) contextString() []byte {
	// The contextString as defined in section 6.5. FROST(secp256k1, SHA-256) of
	// [FROST] is "FROST-secp256k1-SHA256-v1". Since we do a BIP-340 specialized
	// version, we use "FROST-secp256k1-BIP340-v1".
	return []byte("FROST-secp256k1-BIP340-v1")
}

// hashToScalar computes [BIP-340] tagged hash of the message and turns it into
// a scalar modulo secp256k1 curve order, as specified in [BIP-340].
func (b *Bip340Ciphersuite) hashToScalar(tag, msg []byte) *big.Int {
	hashed := b.hash(tag, msg)
	ej := os2ip(hashed[:])

	// This is not safe for all curves. As explained in [BIP-340]:
	//
	// Note that in general, taking a uniformly random 256-bit integer modulo
	// the curve order will produce an unacceptably biased result. However, for
	// the secp256k1 curve, the order is sufficiently close to 2256 that this
	// bias is not observable (1 - n / 2^256 is around 1.27 * 2^-128).
	ej.Mod(ej, b.curve.N)

	return ej
}

// hash implements the tagged hash function as defined in [BIP-340].
func (b *Bip340Ciphersuite) hash(tag, msg []byte) [32]byte {
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

// EncodePoint encodes the given elliptic curve point to a byte slice in a way
// that is *specific* to [BIP-340] needs.
//
// This function yields a different result than SerializePoint function from the
// Curve interface. The SerializePoint serializes both X and Y coordinates,
// while EncodePoint serializes just X coordinate, as it is expected by
// [BIP-340] for the challenge computation. The way SerializePoint works allows
// to avoid computing Y coordinate manually when exchanging data. The way
// EncodePoint works is dictated by [BIP-340] specification.
func (b *Bip340Ciphersuite) EncodePoint(point *Point) []byte {
	xMod := new(big.Int).Mod(point.X, b.curve.P)
	xbs := make([]byte, 32)
	xMod.FillBytes(xbs)
	return xbs
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
