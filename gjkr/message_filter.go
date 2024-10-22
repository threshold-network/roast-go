package gjkr

// findInactive goes through the messages passed as a parameter and finds all
// inactive members for this set of messages. The function does not care if
// the given member was already marked as inactive before. The function makes no
// assumptions about the ordering of the list elements.
func findInactive[T interface{ senderIdx() memberIndex }](
	groupSize uint16, list []T,
) []memberIndex {
	senders := make(map[memberIndex]bool)
	for _, item := range list {
		senders[item.senderIdx()] = true
	}

	inactive := make([]memberIndex, 0)
	for i := uint16(1); i <= groupSize; i++ {
		if !senders[memberIndex(i)] {
			inactive = append(inactive, memberIndex(i))
		}
	}

	return inactive
}

// deduplicateBySender removes duplicated items for the given sender. It always
// takes the first item that occurs for the given sender and ignores the
// subsequent ones.
func deduplicateBySender[T interface{ senderIdx() memberIndex }](
	list []T,
) []T {
	senders := make(map[memberIndex]bool)
	result := make([]T, 0)

	for _, item := range list {
		if _, exists := senders[item.senderIdx()]; !exists {
			senders[item.senderIdx()] = true
			result = append(result, item)
		}
	}

	return result
}

func (m *symmetricKeyGeneratingMember) preProcessMessages(
	ephemeralPubKeyMessages []*ephemeralPublicKeyMessage,
) []*ephemeralPublicKeyMessage {
	inactiveMembers := findInactive(m.group.groupSize, ephemeralPubKeyMessages)
	for _, ia := range inactiveMembers {
		m.group.markMemberAsInactive(ia)
	}

	// TODO: validate session ID

	return deduplicateBySender(ephemeralPubKeyMessages)
}
