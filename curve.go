package main

import (
	"crypto/rand"
	// "crypto/sha256"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
)

type Curve secp256k1.BitCurve

var curve = Curve(*secp256k1.S256())
var G = &curve

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
	xb := make([]byte, 32)
	P.X.FillBytes(xb)
	yb := make([]byte, 32)
	P.Y.FillBytes(yb)
	return concat(xb, yb)
}

func PointFrom(b []byte) Point {
	xb := make([]byte, 32)
	copy(xb, b[0:32])
	x := new(big.Int).SetBytes(xb)
	yb := make([]byte, 32)
	copy(yb, b[32:64])
	y := new(big.Int).SetBytes(yb)
	return Point{x, y}
}

func PointsEq(A, B Point) bool {
	return A.X.Cmp(B.X) == 0 && A.Y.Cmp(B.Y) == 0
}

func Copy(P Point) Point {
	x := new(big.Int).Set(P.X)
	y := new(big.Int).Set(P.Y)
	return Point{x, y}
}

func (g *Curve) ID() Point {
    P := g.g()
    Yneg := new(big.Int).Neg(P.Y)
    // Yneg.Neg(Yneg)

    Pneg := Point{P.X, Yneg}
    return EcAdd(P, Pneg)
    // return Point{big.NewInt(0), big.NewInt(0)}
}

func IsInf(P Point) bool {
	return P.X.Cmp(big.NewInt(0)) == 0
}

func HasEvenY(P Point) bool {
	return P.Y.Bit(0) == 0
}

func EcMul(P Point, s *big.Int) Point {
	sp := new(big.Int).Mod(s, G.N)
	Ps_x, Ps_y := (*secp256k1.BitCurve)(G).ScalarMult(P.X, P.Y, sp.Bytes())
	return Point{Ps_x, Ps_y}
}

func EcBaseMul(s *big.Int) Point {
	sp := new(big.Int).Mod(s, G.N)
	gs_x, gs_y := (*secp256k1.BitCurve)(G).ScalarBaseMult(sp.Bytes())
	return Point{gs_x, gs_y}
}

func EcAdd(X Point, Y Point) Point {
	XY_x, XY_y := (*secp256k1.BitCurve)(G).Add(X.X, X.Y, Y.X, Y.Y)
	return Point{XY_x, XY_y}
}

func EcSub(X Point, Y Point) Point {
	Yneg := Point{Y.X, new(big.Int).Neg(Y.Y)}
	return EcAdd(X, Yneg)
}

func SampleFq() *big.Int {
	b := make([]byte, G.BitSize/8)
	i := new(big.Int)
	for valid := false; !valid; {
		_, err := rand.Read(b)
		if err != nil {
			panic(err)
		}
		i.SetBytes(b)
		if i.Cmp(G.N) < 0 {
			valid = true
		}
	}
	return i
}

func BytesToFq(b []byte) *big.Int {
	x := new(big.Int)
	x.SetBytes(b)
	x.Mod(x, G.N)

	return x
}

func (g *Curve) g() Point {
	x := new(big.Int).Set(g.Gx)
	y := new(big.Int).Set(g.Gy)
	return Point{x, y}
}

func (g *Curve) q() *big.Int {
    return new(big.Int).Set(g.N)
}