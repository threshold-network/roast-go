package main

import (
	"crypto/rand"
	"math/big"
)

// Create a polynomial with degree t-1
// Return an array of t elements,
// where each term of the polynomial equals arr[i] * x^i
func GenPoly(secret *big.Int, t int) []*big.Int {
	arr := make([]*big.Int, t)
	arr[0] = secret
	for i := 1; i < t ; i++ {
		b := make([]byte, 32)
		_, err := rand.Read(b)
		if err != nil {
			panic(err)
		}
		arr[i] = new(big.Int).Mod(OS2IP(b), G.q())
	}
	return arr
}

func CalculatePoly(coeffs []*big.Int, x int) *big.Int {
	res := new(big.Int)

	bigX := big.NewInt(int64(x))

	for i, coeff := range coeffs {
		tmp := new(big.Int).Exp(bigX, big.NewInt(int64(i)), G.q())
		tmp.Mul(tmp, coeff)
		res.Add(res, tmp)
	}
	return res
}

func deriveInterpolatingValue(xi uint64, L []uint64) (*big.Int, *big.Int) {
	// FIXME: add checking as per 4.2
	num := big.NewInt(1)
	den := big.NewInt(1)
	for _, xj := range L {
		if (xj == xi) { continue }
		num.Mul(num, big.NewInt(int64(xj)))
		den.Mul(den, big.NewInt(int64(xj) - int64(xi)))
	}

	return num, den
}