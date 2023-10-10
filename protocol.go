package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type Member struct {
	i uint64
	skShare *big.Int
	pkShare Point
}

func main() {
	n := 9
	t := 5

	members, pk := RunKeygen(n, t)

	msg := []byte("message")

	// round 1
	participants := members[0:t]
	nonces := make([]Nonce, t)
	commits := make([]Commit, t)

	for j, memberJ := range participants {
		nonceJ, commitJ := round1(memberJ.i, memberJ.skShare)

		nonces[j] = nonceJ
		commits[j] = commitJ
	}

	// round 2
	shares := make([]*big.Int, t)

	for j, memberJ := range participants {
		shares[j] = round2(memberJ.i, memberJ.skShare, pk, nonces[j], msg, commits)

		if !verifySignatureShare(memberJ.i, memberJ.pkShare, commits[j], shares[j], commits, pk, msg) {
			fmt.Println("signature share failure")
		}
	}

	sig := aggregate(pk, commits, msg, shares)

	fmt.Println("--- verify signature ---")

	valid := BIP340Verify(ToBIP340(sig), ToBytes32(pk.X), msg)

	fmt.Println(valid)
}

func RunKeygen(n, t int) ([]Member, Point) {
	sk, pk := GenSharedKey()

	coeffs := GenPoly(sk, t)

	members := make([]Member, n)

	for j := range members {
		i := j + 1
		skShare := CalculatePoly(coeffs, i)
		pkShare := EcBaseMul(skShare)

		members[j] = Member{ uint64(i), skShare, pkShare }
	}

	return members, pk
}

func GenSharedKey() (*big.Int, Point) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	sk := OS2IP(b)
	sk.Mod(sk, G.q())

	pk := EcBaseMul(sk)

	if !HasEvenY(pk) {
		sk.Sub(G.q(), sk)
		pk = EcBaseMul(sk)
	}

	return sk, pk
}
