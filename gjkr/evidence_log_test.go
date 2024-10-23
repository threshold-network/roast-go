package gjkr

import (
	"reflect"
	"testing"

	"threshold.network/roast/internal/testutils"
)

func TestPutEphemeralPublicKeyMessageTwice(t *testing.T) {
	evidenceLog := newEvidenceLog()
	err := evidenceLog.putEphemeralPublicKeyMessage(
		&ephemeralPublicKeyMessage{
			senderIndex: memberIndex(1),
		})
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}

	err = evidenceLog.putEphemeralPublicKeyMessage(
		&ephemeralPublicKeyMessage{
			senderIndex: memberIndex(1),
		})
	if err == nil {
		t.Fatal("expected an error")
	}

	testutils.AssertStringsEqual(
		t,
		"error",
		"message exists for sender 1",
		err.Error(),
	)
}

func TestPutGetEphemeralPublicKeyMessage(t *testing.T) {
	evidenceLog := newEvidenceLog()

	message := &ephemeralPublicKeyMessage{
		senderIndex: memberIndex(1),
	}

	m := evidenceLog.getEphemeralPublicKeyMessage(memberIndex(1))
	if m != nil {
		t.Fatalf("expected message not to be found but has [%v]", m)
	}

	err := evidenceLog.putEphemeralPublicKeyMessage(message)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}

	m = evidenceLog.getEphemeralPublicKeyMessage(memberIndex(1))
	if !reflect.DeepEqual(message, m) {
		t.Fatalf(
			"unexpected message\nexpected: %v\nactual:   %v",
			message,
			m,
		)
	}
}
