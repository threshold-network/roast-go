package gjkr

import (
	"fmt"
	"sync"
)

// For complaint resolution, group members need to have access to messages
// exchanged between the accuser and the accused party. There are two situations
// in the DKG protocol where group members generate values individually for
// every other group member:
//
// - Ephemeral ECDH (phase 2) - after each group member generates an ephemeral
// keypair for each other group member and broadcasts those ephemeral public keys
// in the clear (phase 1), group members must ECDH those public keys with the
// ephemeral private key for that group member to derive a symmetric key.
// In the case of an accusation, members performing compliant resolution need to
// validate the private ephemeral key revealed by the accuser. To perform the
// validation, members need to compare public ephemeral key published by the
// accuser in phase 1 with the private ephemeral key published by the accuser.
//
// - Polynomial generation (phase 3) - each group member generates two sharing
// polynomials, and calculates shares as points on these polynomials individually
// for each other group member. Shares are publicly broadcast, encrypted with a
// symmetric key established between the sender and receiver. In the case of an
// accusation, members performing compliant resolution need to look at the shares
// sent by the accused party. To do this, they read the round 3 message from the
// log, and decrypt it using the symmetric key used between the accuser and
// accused party. The key is publicly revealed by the accuser.
type evidenceLog struct {
	// senderIndex -> *ephemeralPublicKeyMessage
	pubKeyMessageLog *messageStorage[*ephemeralPublicKeyMessage]
}

func newEvidenceLog() *evidenceLog {
	return &evidenceLog{
		pubKeyMessageLog: newMessageStorage[*ephemeralPublicKeyMessage](),
	}
}

// putEphemeralMessage is a function that takes a single
// EphemeralPubKeyMessage, and stores that as evidence for future
// accusation trials for a given (sender, receiver) pair. If a message
// already exists for the given sender, we return an error to the user.
func (e *evidenceLog) putEphemeralPublicKeyMessage(
	pubKeyMessage *ephemeralPublicKeyMessage,
) error {
	return e.pubKeyMessageLog.putMessage(
		pubKeyMessage.senderIndex,
		pubKeyMessage,
	)
}

// getEphemeralPublicKeyMessage returns the `ephemeralPublicKeyMessage`
// broadcast in the first protocol round by the given sender.
func (e *evidenceLog) getEphemeralPublicKeyMessage(
	sender memberIndex,
) *ephemeralPublicKeyMessage {
	return e.pubKeyMessageLog.getMessage(sender)
}

type messageStorage[T interface{}] struct {
	cache     map[memberIndex]T
	cacheLock sync.RWMutex
}

func newMessageStorage[T interface{}]() *messageStorage[T] {
	return &messageStorage[T]{
		cache: make(map[memberIndex]T),
	}
}

func (ms *messageStorage[T]) getMessage(sender memberIndex) T {
	ms.cacheLock.RLock()
	defer ms.cacheLock.RUnlock()

	return ms.cache[sender]
}

func (ms *messageStorage[T]) putMessage(sender memberIndex, message T) error {
	ms.cacheLock.Lock()
	defer ms.cacheLock.Unlock()

	if _, ok := ms.cache[sender]; ok {
		return fmt.Errorf(
			"message exists for sender %v",
			sender,
		)
	}

	ms.cache[sender] = message
	return nil
}
