package frost

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"threshold.network/roast/internal/testutils"
)

func TestBip340CurveEcBaseMul(t *testing.T) {
	curve := NewBip340Ciphersuite().Curve()
	point := curve.EcBaseMul(big.NewInt(10))

	expectedX := "72488970228380509287422715226575535698893157273063074627791787432852706183111"
	expectedY := "62070622898698443831883535403436258712770888294397026493185421712108624767191"

	testutils.AssertStringsEqual(t, "X coordinate", expectedX, point.X.String())
	testutils.AssertStringsEqual(t, "Y coordinate", expectedY, point.Y.String())
}

func TestBip340CurveEcMul(t *testing.T) {
	curve := NewBip340Ciphersuite().Curve()
	point := curve.EcBaseMul(big.NewInt(10))
	result := curve.EcMul(point, big.NewInt(5))

	expectedX := "18752372355191540835222161239240920883340654532661984440989362140194381601434"
	expectedY := "88478450163343634110113046083156231725329016889379853417393465962619872936244"

	testutils.AssertStringsEqual(t, "X coordinate", expectedX, result.X.String())
	testutils.AssertStringsEqual(t, "Y coordinate", expectedY, result.Y.String())
}

func TestBip340CurveEcAdd(t *testing.T) {
	curve := NewBip340Ciphersuite().Curve()
	point1 := curve.EcBaseMul(big.NewInt(10))
	point2 := curve.EcBaseMul(big.NewInt(20))
	result := curve.EcAdd(point1, point2)

	expectedX := "49378132684229722274313556995573891527709373183446262831552359577455015004672"
	expectedY := "78123232289538034746933569305416412888858560602643272431489024958214987548923"

	testutils.AssertStringsEqual(t, "X coordinate", expectedX, result.X.String())
	testutils.AssertStringsEqual(t, "Y coordinate", expectedY, result.Y.String())
}

func TestBip340CurveEcSub(t *testing.T) {
	curve := NewBip340Ciphersuite().Curve()
	point1 := curve.EcBaseMul(big.NewInt(30))
	point2 := curve.EcBaseMul(big.NewInt(5))
	result := curve.EcSub(point1, point2)

	expectedX := "66165162229742397718677620062386824252848999675912518712054484685772795754260"
	expectedY := "52018513869565587577673992057861898728543589604141463438466108080111932355586"

	testutils.AssertStringsEqual(t, "X coordinate", expectedX, result.X.String())
	testutils.AssertStringsEqual(t, "Y coordinate", expectedY, result.Y.String())
}

func TestBip340CurveEcAdd_Identity(t *testing.T) {
	curve := NewBip340Ciphersuite().Curve()
	point := curve.EcBaseMul(big.NewInt(10))
	identity := curve.Identity()

	result1 := curve.EcAdd(point, identity)
	result2 := curve.EcAdd(identity, point)

	expectedX := "72488970228380509287422715226575535698893157273063074627791787432852706183111"
	expectedY := "62070622898698443831883535403436258712770888294397026493185421712108624767191"

	testutils.AssertStringsEqual(t, "X coordinate", expectedX, result1.X.String())
	testutils.AssertStringsEqual(t, "Y coordinate", expectedY, result1.Y.String())
	testutils.AssertStringsEqual(t, "X coordinate", expectedX, result2.X.String())
	testutils.AssertStringsEqual(t, "Y coordinate", expectedY, result2.Y.String())
}

func TestBip340CurveSerializedPointLength(t *testing.T) {
	curve := NewBip340Ciphersuite().Curve()

	point := curve.EcBaseMul(big.NewInt(1119991111222))

	actual := len(curve.SerializePoint(point))
	expected1 := curve.SerializedPointLength()
	expected2 := 65 // double-checking in case the underlying implementation changes

	testutils.AssertIntsEqual(t, "byte length", expected1, actual)
	testutils.AssertIntsEqual(t, "byte length", expected2, actual)
}

func TestBip340CurveSerializeDeserializePoint(t *testing.T) {
	curve := NewBip340Ciphersuite().Curve()

	point := curve.EcBaseMul(big.NewInt(1337))

	serialized := curve.SerializePoint(point)
	deserialized := curve.DeserializePoint(serialized)

	testutils.AssertBigIntsEqual(t, "X coordinate", point.X, deserialized.X)
	testutils.AssertBigIntsEqual(t, "Y coordinate", point.Y, deserialized.Y)
}

func TestBip340CurveDeserialize(t *testing.T) {
	// The happy path is covered by TestBip340CurveSerializeDeserializePoint.
	// Let's cover the negative path.

	curve := NewBip340Ciphersuite().Curve()
	point := curve.EcBaseMul(big.NewInt(10))

	serialized := curve.SerializePoint(point)

	tests := map[string]struct {
		input []byte
	}{
		"nil": {
			input: nil,
		},
		"empty": {
			input: []byte{},
		},
		"one less than expected": {
			input: serialized[:len(serialized)-1],
		},
		"one more than expected": {
			input: append(serialized, 0x1),
		},
		"not on the curve": {
			input: curve.SerializePoint(&Point{big.NewInt(1), big.NewInt(2)}),
		},
		"identity element": {
			input: curve.SerializePoint(curve.Identity()),
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			result := curve.DeserializePoint(test.input)
			if result != nil {
				t.Fatalf("nil result expected, got: [%v]", result)
			}
		})
	}

}

func TestBip340CiphersuiteH1(t *testing.T) {
	// There are no official test vectors available. Yet, we want to ensure the
	// function does not panic for empty or nil. We also want to make sure the
	// happy path works producing a non-zero value.
	tests := map[string]struct {
		m        []byte
		expected string
	}{
		"nil": {
			m: nil,
		},
		"empty": {
			m: []byte{},
		},
		"non-empty": {
			m: []byte("hello_world"),
		},
	}

	ciphersuite := NewBip340Ciphersuite()
	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			testutils.AssertBigIntNonZero(t, "H1 result", ciphersuite.H1(test.m))
		})
	}
}

func TestBip340CiphersuiteH2(t *testing.T) {
	// There are no official test vectors available. Yet, we want to ensure the
	// function does not panic for empty or nil. We also want to make sure the
	// happy path works producing a non-zero value.
	tests := map[string]struct {
		m        []byte
		ms       [][]byte
		expected string
	}{
		"nil message": {
			m:  nil,
			ms: [][]byte{{0x1}},
		},
		"some of optional messages nil": {
			m:  []byte{0x1},
			ms: [][]byte{{0x1}, nil, {0x2}},
		},
		"empty message": {
			m:  []byte{},
			ms: [][]byte{{0x1}},
		},
		"some of optional messages empty": {
			m:  []byte{},
			ms: [][]byte{{0x1}, {}, {0x2}},
		},
		"non-empty": {
			m:  []byte{0x1},
			ms: [][]byte{{0x1}, {0x2}},
		},
	}

	ciphersuite := NewBip340Ciphersuite()
	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			testutils.AssertBigIntNonZero(t, "H2 result", ciphersuite.H2(test.m))

		})
	}
}

func TestBip340CiphersuiteH3(t *testing.T) {
	// There are no official test vectors available. Yet, we want to ensure the
	// function does not panic for empty or nil. We also want to make sure the
	// happy path works producing a non-zero value.
	tests := map[string]struct {
		m        []byte
		ms       [][]byte
		expected string
	}{
		"nil message": {
			m:  nil,
			ms: [][]byte{{0x1}},
		},
		"some of optional messages nil": {
			m:  []byte{0x1},
			ms: [][]byte{{0x1}, nil, {0x2}},
		},
		"empty message": {
			m:  []byte{},
			ms: [][]byte{{0x1}},
		},
		"some of optional messages empty": {
			m:  []byte{},
			ms: [][]byte{{0x1}, {}, {0x2}},
		},
		"non-empty": {
			m:  []byte{0x1},
			ms: [][]byte{{0x1}, {0x2}},
		},
	}

	ciphersuite := NewBip340Ciphersuite()
	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			testutils.AssertBigIntNonZero(t, "H3 result", ciphersuite.H3(test.m))
		})
	}
}

func TestBip340CiphersuiteH4(t *testing.T) {
	// There are no official test vectors available. Yet, we want to ensure the
	// function does not panic for empty or nil. We also want to make sure the
	// happy path works producing a non-zero value.
	tests := map[string]struct {
		m        []byte
		expected string
	}{
		"nil": {
			m: nil,
		},
		"empty": {
			m: []byte{},
		},
		"non-empty": {
			m: []byte("hello_world"),
		},
	}

	ciphersuite := NewBip340Ciphersuite()
	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			// The length is unknown so we can't use bytes.Equal. Casting to
			// big.Int instead.
			result := new(big.Int).SetBytes(ciphersuite.H4(test.m))
			testutils.AssertBigIntNonZero(t, "H4 result", result)
		})
	}
}

func TestBip340CiphersuiteH5(t *testing.T) {
	// There are no official test vectors available. Yet, we want to ensure the
	// function does not panic for empty or nil. We also want to make sure the
	// happy path works producing a non-zero value.
	tests := map[string]struct {
		m        []byte
		expected string
	}{
		"nil": {
			m: nil,
		},
		"empty": {
			m: []byte{},
		},
		"non-empty": {
			m: []byte("hello_world"),
		},
	}

	ciphersuite := NewBip340Ciphersuite()
	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			// The length is unknown so we can't use bytes.Equal. Casting to
			// big.Int instead.
			result := new(big.Int).SetBytes(ciphersuite.H5(test.m))
			testutils.AssertBigIntNonZero(t, "H5 result", result)
		})
	}
}

func TestBip340CiphersuiteHashToScalar(t *testing.T) {
	tests := map[string]struct {
		tag []byte
		msg []byte
	}{
		"empty tag": {
			tag: []byte{},
			msg: []byte("message"),
		},
		"empty msg": {
			tag: []byte("tag"),
			msg: []byte{},
		},
		"empty tag and msg": {
			tag: []byte{},
			msg: []byte{},
		},
		"nil tag": {
			tag: nil,
			msg: []byte("message"),
		},
		"nil msg": {
			tag: []byte("tag"),
			msg: nil,
		},
		"nil tag and msg": {
			tag: nil,
			msg: nil,
		},
		"non-empty tag and msg": {
			tag: []byte("tag"),
			msg: []byte("msg"),
		},
	}

	ciphersuite := NewBip340Ciphersuite()
	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			// No official test vectors are available so we only make sure the
			// function does not panic and returns non-nil and non-zero value.
			scalar := ciphersuite.hashToScalar(test.tag, test.msg)
			if scalar == nil {
				t.Fatal("unexpected nil returned")
			}
			testutils.AssertBigIntNonZero(t, "hashToScalar result", scalar)
		})
	}
}

func TestBip340CiphersuiteHash(t *testing.T) {
	tests := map[string]struct {
		tag []byte
		msg []byte
	}{
		"empty tag": {
			tag: []byte{},
			msg: []byte("message"),
		},
		"empty msg": {
			tag: []byte("tag"),
			msg: []byte{},
		},
		"empty tag and msg": {
			tag: []byte{},
			msg: []byte{},
		},
		"nil tag": {
			tag: nil,
			msg: []byte("message"),
		},
		"nil msg": {
			tag: []byte("tag"),
			msg: nil,
		},
		"nil tag and msg": {
			tag: nil,
			msg: nil,
		},
		"non-empty tag and msg": {
			tag: []byte("tag"),
			msg: []byte("msg"),
		},
	}

	empty := make([]byte, 32)
	ciphersuite := NewBip340Ciphersuite()

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			// No official test vectors are available so we only make sure the
			// function does not panic and returns non-zero value
			hash := ciphersuite.hash(test.tag, test.msg)
			if bytes.Equal(hash[:], empty) {
				t.Fatal("empty bytes")
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {
	tests := []struct {
		signature   string
		publicKeyX  string
		message     string
		isValid     bool
		expectedErr string
	}{
		// official [BIP-340] test vectors: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
		{
			signature:  "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
			publicKeyX: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
			message:    "0000000000000000000000000000000000000000000000000000000000000000",
			isValid:    true,
		},
		{
			signature:  "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
			publicKeyX: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			message:    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			isValid:    true,
		},
		{
			signature:  "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
			publicKeyX: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
			message:    "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
			isValid:    true,
		},
		{
			signature:  "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
			publicKeyX: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
			message:    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			isValid:    true,
		},
		{
			signature:  "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
			publicKeyX: "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
			message:    "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
			isValid:    true,
		},
		{
			signature:   "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			publicKeyX:  "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
			message:     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			isValid:     false,
			expectedErr: "point publicKey is infinite",
		},
		{
			signature:   "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
			publicKeyX:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			message:     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			isValid:     false,
			expectedErr: "coordinate R.y is not even",
		},
		{
			signature:   "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
			publicKeyX:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			message:     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			isValid:     false,
			expectedErr: "coordinate R.y is not even",
		},

		{
			signature:   "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
			publicKeyX:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			message:     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			isValid:     false,
			expectedErr: "coordinate R.x != r",
		},
		{
			signature:   "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
			publicKeyX:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			message:     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			isValid:     false,
			expectedErr: "point R is infinite",
		},
		{
			signature:   "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
			publicKeyX:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			message:     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			isValid:     false,
			expectedErr: "point R is infinite",
		},
		{
			signature:   "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			publicKeyX:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			message:     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			isValid:     false,
			expectedErr: "coordinate R.x != r",
		},
		{
			signature:   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			publicKeyX:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			message:     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			isValid:     false,
			expectedErr: "r >= P",
		},
		{
			signature:   "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
			publicKeyX:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			message:     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			isValid:     false,
			expectedErr: "s >= N",
		},
		{
			signature:   "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			publicKeyX:  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
			message:     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			isValid:     false,
			expectedErr: "point publicKey exceeds field size",
		},
		{
			signature:  "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
			publicKeyX: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
			message:    "",
			isValid:    true,
		},
		{
			signature:  "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
			publicKeyX: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
			message:    "11",
			isValid:    true,
		},
		{
			signature:  "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
			publicKeyX: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
			message:    "0102030405060708090A0B0C0D0E0F1011",
			isValid:    true,
		},
		{
			signature:  "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
			publicKeyX: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
			message:    "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
			isValid:    true,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test case %v", i), func(t *testing.T) {
			ciphersuite = NewBip340Ciphersuite()

			calculateY := func(x *big.Int) *big.Int {
				x3 := new(big.Int).Mul(x, x)    //x²
				x3.Mul(x3, x)                   //x³
				x3.Add(x3, ciphersuite.curve.B) //x³+B
				x3.Mod(x3, ciphersuite.curve.P) //(x³+B)%P
				y := new(big.Int).ModSqrt(x3, ciphersuite.curve.P)

				// x is not on the curve; this is a negative test case for
				// which  we can't calculate y
				if y == nil {
					return big.NewInt(2) // even
				}

				return y
			}

			sigBytes, err := hex.DecodeString(test.signature)
			if err != nil {
				t.Fatal(err)
			}

			pubKeyXBytes, err := hex.DecodeString(test.publicKeyX)
			if err != nil {
				t.Fatal(err)
			}

			msg, err := hex.DecodeString(test.message)
			if err != nil {
				t.Fatal(err)
			}

			rX := new(big.Int).SetBytes(sigBytes[0:32])
			rY := calculateY(rX)
			signature := &Signature{
				R: &Point{
					X: rX,
					Y: rY,
				},
				Z: new(big.Int).SetBytes(sigBytes[32:64]),
			}

			pubKeyX := new(big.Int).SetBytes(pubKeyXBytes)
			pubKeyY := calculateY(pubKeyX)
			pubKey := &Point{
				X: pubKeyX,
				Y: pubKeyY,
			}

			res, err := ciphersuite.VerifySignature(signature, pubKey, msg)

			testutils.AssertBoolsEqual(
				t,
				"signature verification result",
				test.isValid,
				res,
			)

			if !test.isValid {
				if err == nil {
					t.Fatal("expected not-nil error")
				}
				testutils.AssertStringsEqual(
					t,
					"signature verification error message",
					test.expectedErr,
					err.Error(),
				)
			}
		})
	}
}

func TestConcat(t *testing.T) {
	tests := map[string]struct {
		expected []byte
		a        []byte
		b        [][]byte
	}{
		"one empty slice": {
			expected: []byte{},
			a:        []byte{},
		},
		"two empty slices": {
			expected: []byte{},
			a:        []byte{},
			b:        [][]byte{{}},
		},
		"multiple empty slices": {
			expected: []byte{},
			a:        []byte{},
			b:        [][]byte{{}, {}},
		},
		"the first slice empty": {
			expected: []byte{0xb, 0xc, 0xd},
			a:        []byte{},
			b:        [][]byte{{0xb, 0xc}, {0xd}},
		},
		"some other slices empty": {
			expected: []byte{0xa, 0xc},
			a:        []byte{0xa},
			b:        [][]byte{{}, {0xc}},
		},
		"the first slice nil": {
			expected: []byte{0xb, 0xc, 0xd},
			a:        nil,
			b:        [][]byte{{0xb, 0xc}, {0xd}},
		},
		"some other slices nil": {
			expected: []byte{0xa, 0xd},
			a:        []byte{0xa},
			b:        [][]byte{nil, {0xd}},
		},
		"all slices non-empty": {
			expected: []byte{0xa, 0xb, 0xc, 0xd, 0xe},
			a:        []byte{0xa, 0xb},
			b:        [][]byte{{0xc, 0xd}, {0xe}},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			testutils.AssertBytesEqual(
				t,
				test.expected,
				concat(test.a, test.b...),
			)
		})
	}
}

func TestOs2Ip(t *testing.T) {
	tests := map[string]struct {
		expected *big.Int
		input    []byte
	}{
		"nil": {
			expected: big.NewInt(0),
			input:    nil,
		},
		"empty array": {
			expected: big.NewInt(0),
			input:    []byte{},
		},
		"non-empty array": {
			expected: big.NewInt(2571), // 0xa * 256^1 + 0xb * 256^0
			input:    []byte{0xa, 0xb},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			testutils.AssertBigIntsEqual(
				t,
				"os2ip result for "+testName,
				test.expected,
				os2ip(test.input),
			)
		})
	}
}
