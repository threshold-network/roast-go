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

Connolly, et al.          Expires 22 March 2024                [Page 12]
Internet-Draft                    FROST                   September 2023

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
func deriveInterpolatingValue(xi uint64, L []uint64) (*big.Int, *big.Int) {
	// FIXME: add checking as per 4.2
	found := false
	num := big.NewInt(1)
	den := big.NewInt(1)
	for _, xj := range L {
		if (xj == xi) {
			if found {
				panic("invalid parameters")
			}
			found = true
			continue
		}
		num.Mul(num, big.NewInt(int64(xj)))
		den.Mul(den, big.NewInt(int64(xj) - int64(xi)))
	}

	if !found {
		panic("invalid parameters")
	}
	return num, den
}