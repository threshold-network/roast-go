package gjkr

import "threshold.network/roast/ephemeral"

// ephemeralPublicKeyMessage is a message payload that carries the sender's
// ephemeral public keys generated for all other group members.
//
// The receiver performs ECDH on a sender's ephemeral public key intended for
// the receiver and on the receiver's private ephemeral key, creating a symmetric
// key used for encrypting a conversation between the sender and the receiver.
// In case of an accusation for malicious behavior, the accusing party reveals
// its private ephemeral key so that all the other group members can resolve the
// accusation looking at messages exchanged between accuser and accused party.
// To validate correctness of accuser's private ephemeral key, all group members
// must know its ephemeral public key prior to exchanging any messages. Hence,
// this message contains all the generated public keys and it is broadcast
// within the group.
type ephemeralPublicKeyMessage struct {
	senderIndex memberIndex // i

	ephemeralPublicKeys map[memberIndex]*ephemeral.PublicKey // j -> Y_ij
}

func (m *ephemeralPublicKeyMessage) senderIdx() memberIndex {
	return m.senderIndex
}
