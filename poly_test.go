package main

import (
	"math/big"
	"testing"
)

func TestCalculatePoly(t *testing.T) {
	// 3x^2 + 2x + 1
	coeffs := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
	}

	// x = 0
	// f(x) = 1
	res1 := CalculatePoly(coeffs, 0)
	if res1.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("x = 0 returns %d instead of 1", res1.Int64())
	}

	// x = 1
	// f(x) = 3 + 2 + 1 = 6
	res2 := CalculatePoly(coeffs, 1)
	if res2.Cmp(big.NewInt(6)) != 0 {
		t.Fatalf("x = 1 returns %d instead of 6", res1.Int64())
	}

	// x = 2
	// f(x) = 12 + 4 + 1 = 17
	res3 := CalculatePoly(coeffs, 2)
	if res3.Cmp(big.NewInt(17)) != 0 {
		t.Fatalf("x = 2 returns %d instead of 17", res1.Int64())
	}
}