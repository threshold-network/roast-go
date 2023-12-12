package main

import (
	"crypto/rand"
	// "crypto/sha256"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
)

type FrostCurve [C CurveImpl] struct {
	curve C
}

type CurveImpl interface {
	ID() *Point
	// Generator() *Point
	Order() *big.Int
	EcMul(*Point, *big.Int) *Point
	EcAdd(*Point, *Point) *Point
	EcSub(*Point, *Point) *Point
	EcBaseMul(*big.Int) *Point
	Encode(*Point) []byte
	// Decode([]byte) (*Point, error)
}

type bip340curve interface {
	Secp256k1
}

type Secp256k1 struct {
	curve *secp256k1.BitCurve
}

var curve = Secp256k1{secp256k1.S256()}

type Point struct {
	X *big.Int // the X coordinate of the point
	Y *big.Int // the Y coordinate of the point
}

// Represent the X-coordinate of the point as a 32-byte array
func (P Point) ToBytes32() [32]byte {
	var xb [32]byte
	xbs := xb[:]
	P.X.FillBytes(xbs)
	return xb
}

func (P Point) Bytes() []byte {
	bb := make([]byte, 64)
	P.X.FillBytes(bb[0:32])
	P.Y.FillBytes(bb[32:64])
	return bb
}

func PointFrom(b []byte) *Point {
	xb := make([]byte, 32)
	copy(xb, b[0:32])
	x := new(big.Int).SetBytes(xb)
	yb := make([]byte, 32)
	copy(yb, b[32:64])
	y := new(big.Int).SetBytes(yb)
	return &Point{x, y}
}

func PointsEq(A, B *Point) bool {
	return A.X.Cmp(B.X) == 0 && A.Y.Cmp(B.Y) == 0
}

func Copy(P *Point) *Point {
	x := new(big.Int).Set(P.X)
	y := new(big.Int).Set(P.Y)
	return &Point{x, y}
}

func (g Secp256k1) ID() *Point {
    return &Point{big.NewInt(0), big.NewInt(0)}
}

func IsInf(P *Point) bool {
	return P.X.Cmp(big.NewInt(0)) == 0
}

func HasEvenY(P *Point) bool {
	return P.Y.Bit(0) == 0
}

func (G Secp256k1) EcMul(P *Point, s *big.Int) *Point {
	sp := new(big.Int).Mod(s, G.curve.N)
	Ps_x, Ps_y := G.curve.ScalarMult(P.X, P.Y, sp.Bytes())
	return &Point{Ps_x, Ps_y}
}

func (G Secp256k1) EcBaseMul(s *big.Int) *Point {
	sp := new(big.Int).Mod(s, G.curve.N)
	gs_x, gs_y := G.curve.ScalarBaseMult(sp.Bytes())
	return &Point{gs_x, gs_y}
}

func (G Secp256k1) EcAdd(X *Point, Y *Point) *Point {
	XY_x, XY_y := G.curve.Add(X.X, X.Y, Y.X, Y.Y)
	return &Point{XY_x, XY_y}
}

func (G Secp256k1) EcSub(X *Point, Y *Point) *Point {
	Yneg := &Point{Y.X, new(big.Int).Neg(Y.Y)}
	return G.EcAdd(X, Yneg)
}

func (G Secp256k1) Encode(P *Point) []byte {
	return P.Bytes()
}

func (G Secp256k1) Decode(bs []byte) (*Point, error) {
	P := PointFrom(bs)
	return P, nil
}

func (G Secp256k1) SampleFq() *big.Int {
	b := make([]byte, G.curve.BitSize/8)
	i := new(big.Int)
	for valid := false; !valid; {
		_, err := rand.Read(b)
		if err != nil {
			panic(err)
		}
		i.SetBytes(b)
		if i.Cmp(G.curve.N) < 0 {
			valid = true
		}
	}
	return i
}

func (G Secp256k1) BytesToFq(b []byte) *big.Int {
	x := new(big.Int)
	x.SetBytes(b)
	x.Mod(x, G.curve.N)

	return x
}

func (g Secp256k1) Generator() *Point {
	x := new(big.Int).Set(g.curve.Gx)
	y := new(big.Int).Set(g.curve.Gy)
	return &Point{x, y}
}

func (g Secp256k1) Order() *big.Int {
    return new(big.Int).Set(g.curve.N)
}