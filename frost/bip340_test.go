package frost

import (
	"bytes"
	"math/big"
	"testing"

	"threshold.network/roast/internal/testutils"
)

func Test_Bip340Ciphersuite_H1(t *testing.T) {
	// There are no official test vectors available. Yet, we want to ensure the
	// function does not panic for empty or nil. We also want to make sure the
	// happy path works producing a non-zero value.
	var tests = map[string]struct {
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

func Test_Bip340Ciphersuite_H2(t *testing.T) {
	// There are no official test vectors available. Yet, we want to ensure the
	// function does not panic for empty or nil. We also want to make sure the
	// happy path works producing a non-zero value.
	var tests = map[string]struct {
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

func Test_Bip340Ciphersuite_H3(t *testing.T) {
	// There are no official test vectors available. Yet, we want to ensure the
	// function does not panic for empty or nil. We also want to make sure the
	// happy path works producing a non-zero value.
	var tests = map[string]struct {
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

func Test_Bip340Ciphersuite_H4(t *testing.T) {
	// There are no official test vectors available. Yet, we want to ensure the
	// function does not panic for empty or nil. We also want to make sure the
	// happy path works producing a non-zero value.
	var tests = map[string]struct {
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

func Test_Bip340Ciphersuite_H5(t *testing.T) {
	// There are no official test vectors available. Yet, we want to ensure the
	// function does not panic for empty or nil. We also want to make sure the
	// happy path works producing a non-zero value.
	var tests = map[string]struct {
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

func Test_Bip340Ciphersuite_hashToScalar(t *testing.T) {
	var tests = map[string]struct {
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

func Test_Bip340Ciphersuite_hash(t *testing.T) {
	var tests = map[string]struct {
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
	var tests = map[string]struct {
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
	var tests = map[string]struct {
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
