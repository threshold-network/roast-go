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
		// TODO: add the remaining BIP-340 test vectors
		// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test case %v", i), func(t *testing.T) {
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

			signature := &Signature{
				R: &Point{
					X: new(big.Int).SetBytes(sigBytes[0:32]),
					Y: nil, // TODO: fix it
				},
				Z: new(big.Int).SetBytes(sigBytes[32:64]),
			}

			pubKey := &Point{
				X: new(big.Int).SetBytes(pubKeyXBytes),
				Y: nil, // TODO: fix it
			}

			ciphersuite = NewBip340Ciphersuite()
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
