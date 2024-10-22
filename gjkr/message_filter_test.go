package gjkr

import (
	"testing"

	"threshold.network/roast/internal/testutils"
)

func TestFindInactive(t *testing.T) {
	var tests = map[string]struct {
		groupSize  uint16
		senders    []memberIndex
		expectedIA []memberIndex
	}{
		"with no inactive senders": {
			groupSize:  5,
			senders:    []memberIndex{1, 4, 3, 2, 5},
			expectedIA: []memberIndex{},
		},
		"with inactivity and senders ordered": {
			groupSize:  5,
			senders:    []memberIndex{1, 3, 5},
			expectedIA: []memberIndex{2, 4},
		},
		"with inactivity and senders not ordered": {
			groupSize:  5,
			senders:    []memberIndex{5, 1, 3},
			expectedIA: []memberIndex{2, 4},
		},
		"with all senders inactive": {
			groupSize:  5,
			senders:    []memberIndex{},
			expectedIA: []memberIndex{1, 2, 3, 4, 5},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			messages := make([]*ephemeralPublicKeyMessage, len(test.senders))
			for i, senderIndex := range test.senders {
				messages[i] = &ephemeralPublicKeyMessage{senderIndex: senderIndex}
			}

			ia := findInactive(test.groupSize, messages)
			testutils.AssertUint16SlicesEqual(
				t,
				"inactive members",
				test.expectedIA,
				ia,
			)
		})
	}
}

func TestDeduplicateBySender(t *testing.T) {
	var tests = map[string]struct {
		senders              []memberIndex
		expectedDeduplicated []memberIndex
	}{
		"with no duplicates": {
			senders:              []memberIndex{1, 4, 3, 2, 5},
			expectedDeduplicated: []memberIndex{1, 4, 3, 2, 5},
		},
		"with duplicates and senders ordered": {
			senders:              []memberIndex{1, 1, 2, 3, 3, 4, 5, 5},
			expectedDeduplicated: []memberIndex{1, 2, 3, 4, 5},
		},
		"with duplicates and senders not ordered": {
			senders:              []memberIndex{5, 2, 5, 3, 1, 3, 3, 2, 5, 4, 5},
			expectedDeduplicated: []memberIndex{5, 2, 3, 1, 4},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			messages := make([]*ephemeralPublicKeyMessage, len(test.senders))
			for i, senderIndex := range test.senders {
				messages[i] = &ephemeralPublicKeyMessage{senderIndex: senderIndex}
			}

			deduplicatedSenders := make([]memberIndex, 0)
			for _, msg := range deduplicateBySender(messages) {
				deduplicatedSenders = append(deduplicatedSenders, msg.senderIdx())
			}
			testutils.AssertUint16SlicesEqual(
				t,
				"deduplicated senders",
				test.expectedDeduplicated,
				deduplicatedSenders,
			)
		})
	}
}
