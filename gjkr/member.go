package gjkr

import "threshold.network/roast/ephemeral"

// memberIndex represents a unique index of a member of GJKR protocol.
// The values start from 1. For a group size of N, the memberIndex is
// 1 <= memberIndex <= N.
type memberIndex uint16

// member includes the core pieces of GJKR protocol member important for every
// phase of the protocol.
type member struct {
	memberIndex memberIndex
	sessionID   string
	group       *group
	evidenceLog evidenceLog

	logger Logger
}

// ephemeralKeyPairGeneratingMember represents one member in a distributed key
// generating group performing ephemeral key pair generation.
//
// Executes Phase 1 of the GJKR protocol.
type ephemeralKeyPairGeneratingMember struct {
	*member

	// Ephemeral key pairs used to create symmetric keys,
	// generated individually for each other group member.
	ephemeralKeyPairs map[memberIndex]*ephemeral.KeyPair
}

// symmetricKeyGeneratingMember represents one member in a distributed key
// generating group performing ephemeral symmetric key generation.
//
// Executes Phase 2 of the GJKR protocol.
type symmetricKeyGeneratingMember struct {
	*ephemeralKeyPairGeneratingMember

	// Symmetric keys used to encrypt confidential information,
	// generated individually for each other group member by ECDH'ing the
	// broadcasted ephemeral public key intended for this member and the
	// ephemeral private key generated for the other member.
	symmetricKeys map[memberIndex]ephemeral.SymmetricKey
}
