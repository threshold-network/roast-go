package gjkr

import (
	"reflect"
	"testing"

	"threshold.network/roast/internal/testutils"
)

func TestPutEphemeralPublicKeyMessageTwice(t *testing.T) {
	dkgEvidenceLog := newDkgEvidenceLog()
	err := dkgEvidenceLog.putEphemeralPublicKeyMessage(
		&ephemeralPublicKeyMessage{
			senderIndex: memberIndex(1),
		})
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}

	err = dkgEvidenceLog.putEphemeralPublicKeyMessage(
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
	dkgEvidenceLog := newDkgEvidenceLog()

	message := &ephemeralPublicKeyMessage{
		senderIndex: memberIndex(1),
	}

	m := dkgEvidenceLog.getEphemeralPublicKeyMessage(memberIndex(1))
	if m != nil {
		t.Fatalf("expected message not to be found but has [%v]", m)
	}

	err := dkgEvidenceLog.putEphemeralPublicKeyMessage(message)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}

	m = dkgEvidenceLog.getEphemeralPublicKeyMessage(memberIndex(1))
	if !reflect.DeepEqual(message, m) {
		t.Fatalf(
			"unexpected message\nexpected: %v\nactual:   %v",
			message,
			m,
		)
	}
}
