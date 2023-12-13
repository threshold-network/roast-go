package roast

import (
	"bytes"
	"math/big"
	"testing"

	"threshold.network/roast/internal/testutils"
)

func TestH1(t *testing.T) {
	// There are no official test vectors available yet we want to ensure the h1
	// function works as we expect it to work before the small change in this
	// function leads to problems elsewhere unnoticed. We assert it works for
	// nil and empty value as well as add one dummy test case for a simple message.
	var tests = map[string]struct {
		m        []byte
		expected string
	}{
		"nil": {
			m:        nil,
			expected: "37788820164651289037378519705078027523735361473650157767227654519376265667966",
		},
		"empty": {
			m:        nil,
			expected: "37788820164651289037378519705078027523735361473650157767227654519376265667966",
		},
		"non-empty": {
			m:        []byte("hello_world"),
			expected: "11900941195119110547012528910823967871135873302377227736111572072836076818402",
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			expected, _ := new(big.Int).SetString(test.expected, 10)
			testutils.AssertBigIntsEqual(t, "h1 result", expected, h1(test.m))
		})
	}
}

func TestHashToScalar(t *testing.T) {
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

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			// No official test vectors are available so we only make sure the
			// function does not panic and returns non-nil and non-zero value.
			scalar := hashToScalar(test.tag, test.msg)
			if scalar == nil {
				t.Fatal("unexpected nil returned")
			}
			testutils.AssertBigIntNonZero(t, "hashToScalar result", scalar)
		})
	}
}

func TestBip340Hash(t *testing.T) {
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

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			// No official test vectors are available so we only make sure the
			// function does not panic and returns non-zero value
			hash := bip340Hash(test.tag, test.msg)
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
