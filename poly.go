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

/*
4.2.  Polynomials

   This section defines polynomials over Scalars that are used in the
   main protocol.  A polynomial of maximum degree t is represented as a
   list of t+1 coefficients, where the constant term of the polynomial
   is in the first position and the highest-degree coefficient is in the
   last position.  For example, the polynomial x^2 + 2x + 3 has degree 2
   and is represented as a list of 3 coefficients [3, 2, 1].  A point on
   the polynomial f is a tuple (x, y), where y = f(x).

   The function derive_interpolating_value derives a value used for
   polynomial interpolation.  It is provided a list of x-coordinates as
   input, each of which cannot equal 0.

   Inputs:
   - L, the list of x-coordinates, each a NonZeroScalar.
   - x_i, an x-coordinate contained in L, a NonZeroScalar.

   Outputs:
   - value, a Scalar.

   Errors:
   - "invalid parameters", if 1) x_i is not in L, or if 2) any
     x-coordinate is represented more than once in L.
*/
// def derive_interpolating_value(L, x_i):
func deriveInterpolatingValue(xi uint64, L []uint64) *big.Int {
	found := false
	// numerator = Scalar(1)
	num := big.NewInt(1)
	// denominator = Scalar(1)
	den := big.NewInt(1)
	// for x_j in L:
	for _, xj := range L {
		if (xj == xi) {
			// for x_j in L:
			//     if count(x_j, L) > 1:
			//         raise "invalid parameters"
			if found {
				panic("invalid parameters")
			}
			found = true
			// if x_j == x_i: continue
			continue
		}
		// numerator *= x_j
		num.Mul(num, big.NewInt(int64(xj)))
		num.Mod(num, G.N)
		// denominator *= x_j - x_i
		den.Mul(den, big.NewInt(int64(xj) - int64(xi)))
		den.Mod(den, G.N)
	}

	// if x_i not in L:
	//     raise "invalid parameters"
	if !found {
		panic("invalid parameters")
	}
	// value = numerator / denominator
	// return value

	denInv := new(big.Int).ModInverse(den, G.N)
	res := new(big.Int).Mul(num, denInv)
	res = res.Mod(res, G.N)

	return res
}