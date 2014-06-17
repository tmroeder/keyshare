package keyshare

import (
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"testing/quick"
)

func TestZeroSlice(t *testing.T) {
	randBytes := make([]byte, 50)
	if _, err := io.ReadFull(rand.Reader, randBytes); err != nil {
		t.Error(err)
	}

	zeroSlice(randBytes)
	for _, b := range randBytes {
		if b != 0 {
			t.FailNow()
		}
	}
}

func shareKeyHelper(count, length int) bool {
	realCount := count % 200
	if realCount < 0 {
		realCount = -realCount
	}

	realLength := length % 65536
	if realLength < 0 {
		realLength = -realLength
	}

	key := make([]byte, realLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return false
	}

	shares, err := shareKey(realCount, key)
	if err != nil {
		// This is OK if we asked for 0 shares
		return realCount == 0
	}

	reassembledKey, err := assembleShares(shares)
	if err != nil {
		return false
	}

	if len(reassembledKey) != len(key) {
		return false
	}

	for i, _ := range reassembledKey {
		if reassembledKey[i] != key[i] {
			return false
		}
	}

	return true
}

func TestShareKey(t *testing.T) {
	if err := quick.Check(shareKeyHelper, nil); err != nil {
		t.Error(err)
	}
}

func encryptHelper(count, length int) bool {
	realCount := count % 200
	if realCount < 0 {
		realCount = -realCount
	}

	// Test plaintext sizes up to about 30 MB.
	realLength := length % (1 << 25)
	if realLength < 0 {
		realLength = -realLength
	}

	plaintext := make([]byte, realLength)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		return false
	}

	authEncrypted, shares, err := encryptAndShare(realCount, plaintext)
	if err != nil {
		return false
	}

	decrypted, err := assembleAndDecrypt(authEncrypted, shares)
	if err != nil {
		return false
	}

	if len(decrypted) != len(plaintext) {
		return false
	}

	for i, _ := range plaintext {
		if plaintext[i] != decrypted[i] {
			return false
		}
	}

	return true
}

func TestEncryptAndShare(t *testing.T) {
	if err := quick.Check(encryptHelper, nil); err != nil {
		t.Error(err)
	}
}

func encryptFileHelper(count, length int, failure bool) bool {
	// Test plaintext sizes up to about 30 MB.
	realLength := length % (1 << 25)
	if realLength < 0 {
		realLength = -realLength
	}

	realCount := count % 200
	if realCount < 0 {
		realCount = -realCount
	}

	// Create a temporary directory for the files
	tempdir, err := ioutil.TempDir("", "keyshare_test")
	if err != nil {
		return false
	}

	defer os.RemoveAll(tempdir)

	plaintextFile := tempdir + string(os.PathSeparator) + "plaintext"
	decryptedFile := tempdir + string(os.PathSeparator) + "decrypted"
	ciphertextFile := tempdir + string(os.PathSeparator) + "ciphertext"
	sharesFile := tempdir + string(os.PathSeparator) + "shares"

	plaintext := make([]byte, realLength)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		return false
	}

	if err := ioutil.WriteFile(plaintextFile, plaintext, 0600); err != nil {
		return false
	}

	if err := EncryptFile(plaintextFile, ciphertextFile, sharesFile, realCount); err != nil {
		return false
	}

	if failure {
		// Change one of the bytes in the file and make sure it fails decryption
		pf, err := os.OpenFile(ciphertextFile, os.O_RDWR, 0600)
		if err != nil {
			return false
		}

		garbageBytes := make([]byte, 10)
		if _, err = io.ReadFull(rand.Reader, garbageBytes); err != nil {
			return false
		}

		if _, err = pf.WriteAt(garbageBytes, 0); err != nil {
			return false
		}
	}

	if err := DecryptFile(decryptedFile, ciphertextFile, sharesFile); err != nil {
		return failure
	} else if failure {
		return false
	}

	decrypted, err := ioutil.ReadFile(decryptedFile)
	if err != nil {
		return false
	}

	if len(decrypted) != len(plaintext) {
		return false
	}

	for i, _ := range plaintext {
		if decrypted[i] != plaintext[i] {
			return false
		}
	}

	return true
}

func TestEncryptFile(t *testing.T) {
	if err := quick.Check(encryptFileHelper, nil); err != nil {
		t.Error(err)
	}
}
