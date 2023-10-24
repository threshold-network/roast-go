package main

import (
	"fmt"
	"math/big"
)

type BIP340Signature struct {
	rb [32]byte
	sb [32]byte
}

func LiftX(x *big.Int) (Point, error) {
	p := G.P
	if x.Cmp(p) != -1 {
		return Point{nil, nil}, fmt.Errorf("LiftX: value of x exceeds field size")
	}
	c := new(big.Int).Exp(x, big.NewInt(3), p)
	c.Add(c, big.NewInt(7))
	c.Mod(c, p)

	e := new(big.Int).Add(p, big.NewInt(1))
	e.Div(e, big.NewInt(4))
	// e.Mod(e, p)

	y := new(big.Int).Exp(c, e, p)

	y2 := new(big.Int).Exp(y, big.NewInt(2), p)

	if c.Cmp(y2) != 0 {
		return Point{nil, nil}, fmt.Errorf("LiftX: no curve point matching x")
	}

	if y.Bit(0) != 0 {
		y.Sub(p, y)
	}
	return Point{x, y}, nil
}

// Input:
// The secret key sk: a 32-byte array
// The message m: a byte array
// Auxiliary random data a: a byte array
func BIP340Sign(skb [32]byte, msg []byte, a []byte) BIP340Signature {
	// Let d' = int(sk)
	dd := FromBytes32(skb)
	// Fail if d' = 0 or d' ≥ n
	if dd.Cmp(G.N) != -1 {
		panic("secret key exceeds range")
	}
	// Let P = d'⋅G
	P := EcBaseMul(dd)
	// Let d = d' if has_even_y(P), otherwise let d = n - d'.
	d := new(big.Int)
	if HasEvenY(P) {
		d.Set(dd)
	} else {
		d.Sub(G.N, dd)
	}
	// Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a)[11].
	auxHash := BIP340HashAux(a)
	db := ToBytes32(d)
	t := xor(db[:], auxHash[:])
	// Let rand = hashBIP0340/nonce(t || bytes(P) || m)[12].
	pb := P.ToBytes32()
	rand := BIP340HashNonce(t, pb[:], msg)
	// Let k' = int(rand) mod n[13].
	kk := new(big.Int).Mod(FromBytes32(rand), G.N)
	// Fail if k' = 0.
	if IsZero(kk) {
		panic("k is zero")
	}
	// Let R = k'⋅G.
	R := EcBaseMul(kk)
	// Let k = k' if has_even_y(R), otherwise let k = n - k' .
	k := new(big.Int)
	if HasEvenY(R) {
		k.Set(kk)
	} else {
		k.Sub(G.N, kk)
	}
	// Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
	rb := R.ToBytes32()
	eHash := BIP340HashChallenge(rb[:], pb[:], msg)
	e := new(big.Int).Mod(FromBytes32(eHash), G.N)
	// Let sig = bytes(R) || bytes((k + ed) mod n).
	ed := new(big.Int).Mul(e, d)
	ked := new(big.Int).Add(k, ed)
	kedmod := new(big.Int).Mod(ked, G.N)
	sig := BIP340Signature{ rb, ToBytes32(kedmod) }

	if !BIP340Verify(sig, pb, msg) {
		panic("created signature does not verify")
	}

	return sig
}

func BIP340Verify(sig BIP340Signature, pkb [32]byte, msg []byte) bool {
	P, err := LiftX(FromBytes32(pkb))
	if err != nil {
		fmt.Println(err)
		fmt.Println("liftX error")
		return false
	}

	// r is a coordinate of a point in the field
	r := FromBytes32(sig.rb)
	if r.Cmp(G.P) != -1 {
		fmt.Println("r >= P")
		return false
	}

	// s is a scalar
	s := FromBytes32(sig.sb)
	if s.Cmp(G.N) != -1 {
		fmt.Println("s >= N")
		return false
	}

	pb := P.ToBytes32()
	// e := H2(concat(sig.rb[:], pb[:], msg[:]))
	eHash := BIP340HashChallenge(sig.rb[:], pb[:], msg)
	e := new(big.Int).Mod(FromBytes32(eHash), G.N)

	R := EcSub(EcBaseMul(s), EcMul(P, e))

	if IsInf(R) {
		fmt.Println("R infinite")
		return false
	}

	fmt.Println(R.Y)
	// R.Y is not even
	if R.Y.Bit(0) != 0 {
		fmt.Println("R.Y not even")
		return false
	}

	if R.X.Cmp(r) != 0 {
		fmt.Println(R.X)
		fmt.Println(r)
		fmt.Println("R.X != r")
		return false
	}

	return true
}

/*
FIXME: unexpected R.X != r with following values of R.Y:

case 1:

23897722509207951717803159524980286455416184134365462808398302808970597218351
106450779596764643922704909739894999128340084802897435504460256555956258459124

case 2:

114983223195334487868794691485953220567913142093480264677244825913831095999902
41933126816717622098184868261463488088630222827715045303692879282718368837800

case 3:

R.X = 88237589896761293066782573873059305961250984105136818952129896190174887718311
r   = 92969380900914639994523238295275354849816377058067753582599362192585694290836

R.Y in aggregate: 53140585281022697158848720990634019024509591704429141788805026098482283599027
R.Y in verify:    156620474446557016514927458068231588368087575834588512257661140247378008757

presumably fixed in computeChallenge() which previously used gc.X.Bytes() and pk.X.Bytes()
which could produce a differing result if either gc or pk had a length less than 32 bytes
*/