package gjkr

// filterForSession goes through the messages passed as a parameter and finds
// all messages sent for the given session ID.
func filterForSession[T interface{ getSessionID() string }](
	sessionID string,
	list []T,
) []T {
	result := make([]T, 0)

	for _, msg := range list {
		if msg.getSessionID() == sessionID {
			result = append(result, msg)
		}
	}

	return result
}

// findInactive goes through the messages passed as a parameter and finds all
// inactive members for this set of messages. The function does not care if
// the given member was already marked as inactive before. The function makes no
// assumptions about the ordering of the list elements.
func findInactive[T interface{ getSenderIndex() memberIndex }](
	groupSize uint16,
	list []T,
) []memberIndex {
	senders := make(map[memberIndex]bool)
	for _, item := range list {
		senders[item.getSenderIndex()] = true
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
func deduplicateBySender[T interface{ getSenderIndex() memberIndex }](
	list []T,
) []T {
	senders := make(map[memberIndex]bool)
	result := make([]T, 0)

	for _, msg := range list {
		if _, exists := senders[msg.getSenderIndex()]; !exists {
			senders[msg.getSenderIndex()] = true
			result = append(result, msg)
		}
	}

	return result
}

func (m *symmetricKeyGeneratingMember) preProcessMessages(
	ephemeralPubKeyMessages []*ephemeralPublicKeyMessage,
) []*ephemeralPublicKeyMessage {
	forThisSession := filterForSession(m.sessionID, ephemeralPubKeyMessages)

	inactiveMembers := findInactive(m.group.groupSize, forThisSession)
	for _, ia := range inactiveMembers {
		m.group.markMemberAsInactive(ia)
	}

	return deduplicateBySender(forThisSession)
}
