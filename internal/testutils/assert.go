package testutils

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"golang.org/x/exp/slices"
)

// AssertBigIntNonZero checks if the provided not-nil big integer is non-zero.
// If the provided big integer is zero, it reports a test failure.
func AssertBigIntNonZero(t *testing.T, description string, actual *big.Int) {
	if actual.Cmp(big.NewInt(0)) == 0 {
		t.Errorf("expected %s to be non-zero", description)
	}
}

// AssertBigIntsEqual checks if two not-nil big integers are equal. If not, it
// reports a test failure.
func AssertBigIntsEqual(t *testing.T, description string, expected *big.Int, actual *big.Int) {
	if expected.Cmp(actual) != 0 {
		t.Errorf(
			"unexpected %s\nexpected: %v\nactual:   %v\n",
			description,
			expected,
			actual,
		)
	}
}

// AssertUintsEqual checks if two unsigned integers are equal. If not, it
// reports a test failure.
func AssertUintsEqual(t *testing.T, description string, expected uint64, actual uint64) {
	if expected != actual {
		t.Errorf(
			"unexpected %s\nexpected: %v\nactual:   %v\n",
			description,
			expected,
			actual,
		)
	}
}

// AssertIntsEqual checks if two integers are equal. If not, it reports a test
// failure.
func AssertIntsEqual(t *testing.T, description string, expected int, actual int) {
	if expected != actual {
		t.Errorf(
			"unexpected %s\nexpected: %v\nactual:   %v\n",
			description,
			expected,
			actual,
		)
	}
}

// AssertBytesEqual checks if the two bytes array are equal. If not, it reports
// a test failure.
func AssertBytesEqual(t *testing.T, expectedBytes []byte, actualBytes []byte) {
	err := testBytesEqual(expectedBytes, actualBytes)

	if err != nil {
		t.Error(err)
	}
}

// AssertStringsEqual checks if two strings are equal. If not, it reports a test
// failure.
func AssertStringsEqual(t *testing.T, description string, expected string, actual string) {
	if expected != actual {
		t.Errorf(
			"unexpected %s\nexpected: %s\nactual:   %s\n",
			description,
			expected,
			actual,
		)
	}
}

// AssertBoolsEqual checks if two booleans are equal. If not, it reports a test
// failure.
func AssertBoolsEqual(t *testing.T, description string, expected bool, actual bool) {
	if expected != actual {
		t.Errorf(
			"unexpected %s\nexpected: %v\nactual:   %v\n",
			description,
			expected,
			actual,
		)
	}
}

func testBytesEqual(expectedBytes []byte, actualBytes []byte) error {
	minLen := len(expectedBytes)
	diffCount := 0
	if actualLen := len(actualBytes); actualLen < minLen {
		diffCount = minLen - actualLen
		minLen = actualLen
	} else {
		diffCount = actualLen - minLen
	}

	for i := 0; i < minLen; i++ {
		if expectedBytes[i] != actualBytes[i] {
			diffCount++
		}
	}

	if diffCount != 0 {
		return fmt.Errorf(
			"byte slices differ in %v places\nexpected: [%v]\nactual:   [%v]",
			diffCount,
			expectedBytes,
			actualBytes,
		)
	}

	return nil
}

func AssertUint16SlicesEqual[T ~uint16](
	t *testing.T,
	description string,
	expected []T,
	actual []T,
) {
	if !slices.Equal(expected, actual) {
		t.Errorf(
			"unexpected %s\nexpected: %v\nactual:   %v\n",
			description,
			expected,
			actual,
		)
	}
}

func AssertDeepEqual(
	t *testing.T,
	description string,
	expected any,
	actual any,
) {
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf(
			"unexpected %s\nexpected: %v\nactual:   %v\n",
			description,
			expected,
			actual,
		)
	}
}
