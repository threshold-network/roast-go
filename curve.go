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

/*

FIXME:

> go run .
63582888022005087057460948200698713736356686157995429580655227621581986205496
--- verify signature ---
63582888022005087057460948200698713736356686157995429580655227621581986205496
true
preparing member channel 1
preparing member channel 2
preparing member channel 3
preparing member channel 4
preparing member channel 5
preparing member channel 6
preparing member channel 7
preparing member channel 8
preparing member channel 9
coordinator 1 requesting commits
sending request to member 1
sending request to member 2
sending request to member 3
sending request to member 4
sending request to member 5
sending request to member 6
sending request to member 7
sending request to member 8
sending request to member 9
member 1 responding to commit request
member 8 responding to commit request
coordinator 1 received commit from member 8
member 9 responding to commit request
coordinator 1 received commit from member 1
member 2 responding to commit request
member 3 responding to commit request
coordinator 1 received commit from member 9
member 4 responding to commit request
coordinator 1 received commit from member 3
member 7 responding to commit request
member 6 responding to commit request
coordinator 1 received commit from member 4
member 9 responding to sign request
member 5 responding to commit request
coordinator 1 received commit from member 6
member 3 responding to sign request
coordinator 1 received commit from member 7
member 1 responding to sign request
coordinator 1 received commit from member 5
member 8 responding to sign request
member 4 responding to sign request
coordinator 1 received share from member 9
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x10 pc=0x49cd06]

goroutine 15 [running]:
math/big.(*Int).Sign(...)
        /usr/lib64/go/1.21/src/math/big/int.go:49
github.com/ethereum/go-ethereum/crypto/secp256k1.(*BitCurve).Add(0xc0001a9b60?, 0xc0001a9b80?, 0xc0001ef220?, 0xc0001a97a0?, 0xc0001c42b0?)
        /home/eth/go/pkg/mod/github.com/ethereum/go-ethereum@v1.13.1/crypto/secp256k1/curve.go:133 +0x66
main.EcAdd(...)
        /home/eth/work/roast-go/curve.go:87
main.verifySignatureShare(0x9, {0xc0001a9b60?, 0xc0001a9b80?}, {0x9, {0xc0001a9dc0, 0xc0001a9de0}, {0xc0001a9e00, 0xc0001a9e20}}, 0x4c4e20?, {0xc0001d0b40, ...}, ...)
        /home/eth/work/roast-go/frost.go:537 +0x2b8
main.(*RoastExecution).ReceiveShare(0xc0001d4000, 0x9, {0x78, 0xac, 0x43, 0xdf, 0xdc, 0x31, 0xe2, 0x8d, ...}, ...)
        /home/eth/work/roast-go/coordinator.go:161 +0x227
main.(*RoastExecution).RunCoordinator(0xc0001d4000, {0xc00007e840?, 0xc00007e8a0?}, {0xc0000a8120, 0x9, 0x0?})
        /home/eth/work/roast-go/coordinator.go:240 +0x43b
main.RunRoastCh.func2()
        /home/eth/work/roast-go/protocol.go:129 +0x76
created by main.RunRoastCh in goroutine 1
        /home/eth/work/roast-go/protocol.go:127 +0x67f
exit status 2


*/