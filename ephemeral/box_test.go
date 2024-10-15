package ephemeral

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

var accountPassword = []byte("passW0rd")

func TestBoxEncryptDecrypt(t *testing.T) {
	msg := "Keep Calm and Carry On"

	box := newBox(sha256.Sum256(accountPassword))

	encrypted, err := box.encrypt([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := box.decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	decryptedString := string(decrypted)
	if decryptedString != msg {
		t.Fatalf(
			"unexpected message\nexpected: %v\nactual: %v",
			msg,
			decryptedString,
		)
	}
}

func TestBoxCiphertextRandomized(t *testing.T) {
	msg := `Why do we tell actors to 'break a leg?'
			 Because every play has a cast.`

	box := newBox(sha256.Sum256(accountPassword))

	encrypted1, err := box.encrypt([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	encrypted2, err := box.encrypt([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	if len(encrypted1) != len(encrypted2) {
		t.Fatalf(
			"expected the same length of ciphertexts (%v vs %v)",
			len(encrypted1),
			len(encrypted2),
		)
	}

	if reflect.DeepEqual(encrypted1, encrypted2) {
		t.Fatalf("expected two different ciphertexts")
	}
}

func TestBoxGracefullyHandleBrokenCipher(t *testing.T) {
	box := newBox(sha256.Sum256(accountPassword))

	brokenCipher := []byte{0x01, 0x02, 0x03}

	_, err := box.decrypt(brokenCipher)

	expectedError := fmt.Errorf("symmetric key decryption failed")
	if !reflect.DeepEqual(expectedError, err) {
		t.Fatalf(
			"unexpected error\nexpected: %v\nactual:   %v",
			expectedError,
			err,
		)
	}
}
