package testutils

import (
	"crypto/rand"
	"math/big"
)

// GenerateKeyShares generates a secret key and secret key shares for the group
// of the given size with the required signing threshold.
func GenerateKeyShares(
	secretKey *big.Int,
	groupSize int,
	threshold int,
	order *big.Int,
) []*big.Int {
	coefficients := generatePolynomial(secretKey, threshold, order)

	secretKeyShares := make([]*big.Int, groupSize)
	for i := 0; i < groupSize; i++ {
		j := i + 1
		secretKeyShares[i] = calculatePolynomial(
			coefficients,
			j,
			order,
		)
	}

	return secretKeyShares
}

// generatePolynomial generates a polynomial of degree equal to `threshold` with
// random coefficients, not higher than the group `order`.
func generatePolynomial(
	secretKey *big.Int,
	threshold int,
	order *big.Int,
) []*big.Int {
	arr := make([]*big.Int, threshold)
	arr[0] = secretKey
	for i := 1; i < threshold; i++ {
		random, err := rand.Int(rand.Reader, order)
		if err != nil {
			panic(err)
		}
		arr[i] = random
	}

	return arr
}

// calculatePolynomial calculates the polynomial value for the given `x` modulo
// group `order`. Polynomial `coefficients` need to be passed as parameters.
func calculatePolynomial(
	coefficients []*big.Int,
	x int,
	order *big.Int,
) *big.Int {
	result := new(big.Int)

	bigX := big.NewInt(int64(x))

	for i, c := range coefficients {
		tmp := new(big.Int).Exp(bigX, big.NewInt(int64(i)), order)
		tmp.Mul(tmp, c)
		result.Add(result, tmp)
	}

	return new(big.Int).Mod(result, order)
}
