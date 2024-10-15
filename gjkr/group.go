package gjkr

// group represents the current state of information about the GJKR key
// generation group. Each GJKR protocol participant should have the same group
// state at the end of each protocol step.
type group struct {
	dishonestThreshold uint16
	groupSize          uint16

	allMemberIndexes          []memberIndex
	inactiveMemberIndexes     []memberIndex
	disqualifiedMemberIndexes []memberIndex
}

func newGroup(dishonestThreshold uint16, groupSize uint16) *group {
	allMemberIndexes := make([]memberIndex, groupSize)
	for i := uint16(0); i < groupSize; i++ {
		allMemberIndexes[i] = memberIndex(i + 1)
	}

	return &group{
		dishonestThreshold:        dishonestThreshold,
		groupSize:                 groupSize,
		allMemberIndexes:          allMemberIndexes,
		inactiveMemberIndexes:     []memberIndex{},
		disqualifiedMemberIndexes: []memberIndex{},
	}
}

// markMemberAsDisqualified adds the member with the given index to the list of
// disqualified members. If the member is not a part of the group, is already
// disqualified or marked as inactive, the function does nothing.
func (g *group) markMemberAsDisqualified(memberIndex memberIndex) {
	if g.isOperating(memberIndex) {
		g.disqualifiedMemberIndexes = append(g.disqualifiedMemberIndexes, memberIndex)
	}
}

// markMemberAsInactive adds the member with the given index to the list of
// inactive members. If the member is not a part of the group, is already
// disqualified or marked as inactive, the function does nothing.
func (g *group) markMemberAsInactive(memberIndex memberIndex) {
	if g.isOperating(memberIndex) {
		g.inactiveMemberIndexes = append(g.inactiveMemberIndexes, memberIndex)
	}
}

// isOperating returns true if member with the given index belongs to the group
// and has not been marked as inactive or disqualified.
func (g *group) isOperating(memberIndex memberIndex) bool {
	return g.isInGroup(memberIndex) &&
		!g.isInactive(memberIndex) &&
		!g.isDisqualified(memberIndex)
}

func (g *group) isInGroup(memberIndex memberIndex) bool {
	return memberIndex > 0 && uint16(memberIndex) <= g.groupSize
}

func (g *group) isInactive(memberIndex memberIndex) bool {
	for _, inactiveMemberIndex := range g.inactiveMemberIndexes {
		if memberIndex == inactiveMemberIndex {
			return true
		}
	}

	return false
}

func (g *group) isDisqualified(memberIndex memberIndex) bool {
	for _, disqualifiedMemberIndex := range g.disqualifiedMemberIndexes {
		if memberIndex == disqualifiedMemberIndex {
			return true
		}
	}

	return false
}
