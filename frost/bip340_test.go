package frost

import (
	"bytes"
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
