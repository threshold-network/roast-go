package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"math/big"
)

var contextString = []byte("FROST-secp256k1-SHA256-v11")

var bip340ChallengeTag = []byte("BIP0340/challenge")
var bip340AuxTag = []byte("BIP0340/aux")
var bip340NonceTag = []byte("BIP0340/nonce")

func BIP340Hash(tag, m []byte) [32]byte {
	hashedTag := sha256.Sum256(tag)
	slicedTag := hashedTag[:]
	hashed := sha256.Sum256(concat(slicedTag, slicedTag, m))

	return hashed
}

func BIP340HashChallenge(ms ...[]byte) [32]byte {
	return BIP340Hash(bip340ChallengeTag, concat(ms[0], ms[1:]...))
}

func BIP340HashAux(ms ...[]byte) [32]byte {
	return BIP340Hash(bip340AuxTag, concat(ms[0], ms[1:]...))
}

func BIP340HashNonce(ms ...[]byte) [32]byte {
	return BIP340Hash(bip340NonceTag, concat(ms[0], ms[1:]...))
}

func H(m []byte) []byte {
	hashed := sha256.Sum256(m)
	return hashed[:]
}

func H1(m []byte) *big.Int {
	DST := concat(contextString, []byte("rho"))
	return hashToScalar(DST, m)
}

func H2(m []byte) *big.Int {
	return hashToScalar(bip340ChallengeTag, m)
}

func H3(m []byte) *big.Int {
	DST := concat(contextString, []byte("nonce"))
	return hashToScalar(DST, m)
}

func H4(m []byte) []byte {
	hashed := BIP340Hash(concat(contextString, []byte("msg")), m)
	return hashed[:]
}

func H5(m []byte) []byte {
	hashed := BIP340Hash(concat(contextString, []byte("com")), m)
	return hashed[:]
}

func hashToScalar(tag, msg []byte) *big.Int {
	hashed := BIP340Hash(tag, msg)

	ej := OS2IP(hashed[:])
	ej.Mod(ej, curve.curve.N)

	return ej
}

func OS2IP(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func I2OSP(x *big.Int, xLen uint64) []byte {
	buf := make([]byte, xLen)
	return x.FillBytes(buf)
}

func HashToInt(msg []byte) *big.Int {
	h := sha256.Sum256(msg)
	return FromBytes32(h)
}

// Safe concatenation of byte slices:
// Using append(a, b...) can modify a by extending its length
// if it has sufficient capacity to hold b.
// To avoid this in all circumstances, copy a to a new array
// before appending the rest.
func concat(a []byte, bs ...[]byte) []byte {
	c := make([]byte, len(a))
	copy(c, a)
	for _, b := range bs {
		c = append(c, b...)
	}
	return c
}

func xor(a, b []byte) []byte {
	l := min(len(a), len(b))
	dest := make([]byte, l)
	subtle.XORBytes(dest, a, b)
	return dest
}