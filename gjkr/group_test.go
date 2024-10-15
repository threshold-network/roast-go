package gjkr

import (
	"fmt"
	"slices"
	"testing"

	"threshold.network/roast/internal/testutils"
)

func TestMarkMemberAsDisqualified(t *testing.T) {
	var tests = map[string]struct {
		updateFunc                  func(g *group)
		expectedDisqualifiedMembers []memberIndex
		expectedInactiveMembers     []memberIndex
	}{
		"mark member as disqualified": {
			updateFunc: func(g *group) {
				g.markMemberAsDisqualified(2)
			},
			expectedDisqualifiedMembers: []memberIndex{2},
		},
		"mark member as disqualified twice": {
			updateFunc: func(g *group) {
				g.markMemberAsDisqualified(3)
				g.markMemberAsDisqualified(3)
			},
			expectedDisqualifiedMembers: []memberIndex{3},
		},
		"mark member from out of the group as disqualified": {
			updateFunc: func(g *group) {
				g.markMemberAsDisqualified(102)
			},
			expectedDisqualifiedMembers: []memberIndex{},
		},
		"mark all members as disqualified": {
			updateFunc: func(g *group) {
				g.markMemberAsDisqualified(1)
				g.markMemberAsDisqualified(2)
				g.markMemberAsDisqualified(3)
				g.markMemberAsDisqualified(4)
				g.markMemberAsDisqualified(5)
			},
			expectedDisqualifiedMembers: []memberIndex{1, 2, 3, 4, 5},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			groupSize := uint16(5)
			group := newGroup(2, groupSize)
			test.updateFunc(group)

			for i := uint16(1); i <= groupSize; i++ {
				idx := memberIndex(i)
				shouldBeDisqualified := slices.Contains(
					test.expectedDisqualifiedMembers,
					idx,
				)
				testutils.AssertBoolsEqual(
					t,
					fmt.Sprintf("disqualification state for %v", idx),
					shouldBeDisqualified,
					group.isDisqualified(idx),
				)
				testutils.AssertBoolsEqual(
					t,
					fmt.Sprintf("inactivity state for %v", idx),
					false,
					group.isInactive(idx),
				)
				if !shouldBeDisqualified {
					testutils.AssertBoolsEqual(
						t,
						"operating state",
						true,
						group.isOperating(idx),
					)
				}
			}
		})
	}
}

func TestMarkMemberAsInactive(t *testing.T) {
	var tests = map[string]struct {
		updateFunc                  func(g *group)
		expectedDisqualifiedMembers []memberIndex
		expectedInactiveMembers     []memberIndex
	}{
		"mark member as inactive": {
			updateFunc: func(g *group) {
				g.markMemberAsInactive(1)
				g.markMemberAsInactive(3)
			},
			expectedInactiveMembers: []memberIndex{1, 3},
		},
		"mark member as inactive twice": {
			updateFunc: func(g *group) {
				g.markMemberAsInactive(2)
				g.markMemberAsInactive(2)
			},
			expectedInactiveMembers: []memberIndex{2},
		},
		"mark member from out of the group as inactive": {
			updateFunc: func(g *group) {
				g.markMemberAsInactive(6)
			},
			expectedInactiveMembers: []memberIndex{},
		},
		"mark all members as inactive": {
			updateFunc: func(g *group) {
				g.markMemberAsInactive(1)
				g.markMemberAsInactive(2)
				g.markMemberAsInactive(3)
				g.markMemberAsInactive(4)
				g.markMemberAsInactive(5)
			},
			expectedInactiveMembers: []memberIndex{1, 2, 3, 4, 5},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			groupSize := uint16(5)
			group := newGroup(2, groupSize)
			test.updateFunc(group)

			for i := uint16(1); i <= groupSize; i++ {
				idx := memberIndex(i)
				shouldBeInactive := slices.Contains(
					test.expectedInactiveMembers,
					idx,
				)
				testutils.AssertBoolsEqual(
					t,
					fmt.Sprintf("inactivity state for %v", idx),
					shouldBeInactive,
					group.isInactive(idx),
				)
				testutils.AssertBoolsEqual(
					t,
					fmt.Sprintf("disqualification state for %v", idx),
					false,
					group.isDisqualified(idx),
				)

				if !shouldBeInactive {
					testutils.AssertBoolsEqual(
						t,
						"operating state",
						true,
						group.isOperating(idx),
					)
				}
			}
		})
	}
}

func TestIsInGroup(t *testing.T) {
	group := newGroup(2, 3)

	testutils.AssertBoolsEqual(
		t,
		"is in group state for 0",
		false,
		group.isInGroup(0),
	)
	testutils.AssertBoolsEqual(
		t,
		"is in group state for 1",
		true,
		group.isInGroup(1),
	)
	testutils.AssertBoolsEqual(
		t,
		"is in group state for 2",
		true,
		group.isInGroup(2),
	)
	testutils.AssertBoolsEqual(
		t,
		"is in group state for 3",
		true,
		group.isInGroup(3),
	)
	testutils.AssertBoolsEqual(
		t,
		"is in group state for 4",
		false,
		group.isInGroup(4),
	)
}
