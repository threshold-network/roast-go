package roast

import "github.com/ethereum/go-ethereum/crypto/secp256k1"

type Curve secp256k1.BitCurve

var curve = Curve(*secp256k1.S256())
var G = &curve
