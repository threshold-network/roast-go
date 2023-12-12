package main

import (
	"fmt"
	"math/big"
)

type BIP340Signature struct {
	rb [32]byte
	sb [32]byte
}

func LiftX(G Secp256k1, x *big.Int) (*Point, error) {
	p := G.curve.P
	if x.Cmp(p) != -1 {
		return &Point{nil, nil}, fmt.Errorf("LiftX: value of x exceeds field size")
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
		return &Point{nil, nil}, fmt.Errorf("LiftX: no curve point matching x")
	}

	if y.Bit(0) != 0 {
		y.Sub(p, y)
	}
	return &Point{x, y}, nil
}

// Input:
// The secret key sk: a 32-byte array
// The message m: a byte array
// Auxiliary random data a: a byte array
func BIP340Sign(G Secp256k1, skb [32]byte, msg []byte, a []byte) BIP340Signature {
	// Let d' = int(sk)
	dd := FromBytes32(skb)
	// Fail if d' = 0 or d' ≥ n
	if dd.Cmp(G.Order()) != -1 {
		panic("secret key exceeds range")
	}
	// Let P = d'⋅G
	P := G.EcBaseMul(dd)
	// Let d = d' if has_even_y(P), otherwise let d = n - d'.
	d := new(big.Int)
	if HasEvenY(P) {
		d.Set(dd)
	} else {
		d.Sub(G.Order(), dd)
	}
	// Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a)[11].
	auxHash := BIP340HashAux(a)
	db := ToBytes32(d)
	t := xor(db[:], auxHash[:])
	// Let rand = hashBIP0340/nonce(t || bytes(P) || m)[12].
	pb := P.ToBytes32()
	rand := BIP340HashNonce(t, pb[:], msg)
	// Let k' = int(rand) mod n[13].
	kk := new(big.Int).Mod(FromBytes32(rand), G.Order())
	// Fail if k' = 0.
	if IsZero(kk) {
		panic("k is zero")
	}
	// Let R = k'⋅G.
	R := G.EcBaseMul(kk)
	// Let k = k' if has_even_y(R), otherwise let k = n - k' .
	k := new(big.Int)
	if HasEvenY(R) {
		k.Set(kk)
	} else {
		k.Sub(G.Order(), kk)
	}
	// Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
	rb := R.ToBytes32()
	eHash := BIP340HashChallenge(rb[:], pb[:], msg)
	e := new(big.Int).Mod(FromBytes32(eHash), G.Order())
	// Let sig = bytes(R) || bytes((k + ed) mod n).
	ed := new(big.Int).Mul(e, d)
	ked := new(big.Int).Add(k, ed)
	kedmod := new(big.Int).Mod(ked, G.Order())
	sig := BIP340Signature{ rb, ToBytes32(kedmod) }

	if !BIP340Verify(G, sig, pb, msg) {
		panic("created signature does not verify")
	}

	return sig
}

func BIP340Verify(G Secp256k1, sig BIP340Signature, pkb [32]byte, msg []byte) bool {
	P, err := LiftX(G, FromBytes32(pkb))
	if err != nil {
		fmt.Println(err)
		fmt.Println("liftX error")
		return false
	}

	// r is a coordinate of a point in the field
	r := FromBytes32(sig.rb)
	if r.Cmp(G.curve.P) != -1 {
		fmt.Println("r >= P")
		return false
	}

	// s is a scalar
	s := FromBytes32(sig.sb)
	if s.Cmp(G.Order()) != -1 {
		fmt.Println("s >= N")
		return false
	}

	pb := P.ToBytes32()
	// e := H2(concat(sig.rb[:], pb[:], msg[:]))
	eHash := BIP340HashChallenge(sig.rb[:], pb[:], msg)
	e := new(big.Int).Mod(FromBytes32(eHash), G.Order())

	R := G.EcSub(G.EcBaseMul(s), G.EcMul(P, e))

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
