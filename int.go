package main

import (
	"math/big"
)

func ToBytes32(i *big.Int) [32]byte {
	var b [32]byte
	bs := b[:]
	i.FillBytes(bs)
	return b
}

func FromBytes32(b [32]byte) *big.Int {
	return new(big.Int).SetBytes(b[:])
}

func IsZero(x *big.Int) bool {
	return x.Cmp(big.NewInt(0)) == 0
}

func BigintEq(x, y *big.Int) bool {
	return x.Cmp(y) == 0 
}