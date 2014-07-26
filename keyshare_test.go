// Copyright 2014, Tom Roeder (tmroeder@gmail.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keyshare

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/gob"
	"fmt"
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

	bs, err := NewXORSharer(realCount)
	if err != nil {
		return false
	}

	shares, err := bs.Share(key)
	if err != nil {
		// This is OK if we asked for 0 shares
		return realCount == 0
	}

	reassembledKey, err := bs.Reassemble(shares)
	if err != nil {
		return false
	}

	if len(reassembledKey) != len(key) {
		return false
	}

	for i := range reassembledKey {
		if reassembledKey[i] != key[i] {
			return false
		}
	}

	return true
}

func TestShareKey(t *testing.T) {
	if testing.Short() {
		if !shareKeyHelper(20, 100) {
			t.Fatal("Couldn't share the key")
		}
	} else {
		if err := quick.Check(shareKeyHelper, nil); err != nil {
			t.Error(err)
		}
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

	bs, err := NewXORSharer(realCount)
	if err != nil {
		return false
	}

	authEncrypted, shares, err := EncryptAndShare(bs, plaintext)
	if err != nil {
		return false
	}

	decrypted, err := ReassembleAndDecrypt(bs, authEncrypted, shares)
	if err != nil {
		return false
	}

	if len(decrypted) != len(plaintext) {
		return false
	}

	for i := range plaintext {
		if plaintext[i] != decrypted[i] {
			return false
		}
	}

	return true
}

func TestEncryptAndShare(t *testing.T) {
	if testing.Short() {
		if !encryptHelper(10, 1024*1024) {
			t.Fatal("Couldn't encrypt a 1MB plaintext")
		}
	} else {
		if err := quick.Check(encryptHelper, nil); err != nil {
			t.Error(err)
		}
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

	bs, err := NewXORSharer(realCount)
	if err != nil {
		return false
	}

	ciphertext, shares, err := EncryptFile(plaintextFile, bs)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	if err := EncodeToBase64(ciphertextFile, sharesFile, ciphertext, shares); err != nil {
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

	if err := DecryptFile(decryptedFile, ciphertextFile, sharesFile, realCount, bs); err != nil {
		fmt.Println("Failed decryption:", err)
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

	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			return false
		}
	}

	return true
}

func TestEncryptFile(t *testing.T) {
	if testing.Short() {
		if !encryptFileHelper(10, 1024, false) {
			t.Fatal("Couldn't encrypt a 1MB plaintext")
		}
	} else {
		if err := quick.Check(encryptFileHelper, nil); err != nil {
			t.Error(err)
		}
	}
}

func TestInvalidXORSharer(t *testing.T) {
	if _, err := NewXORSharer(0); err == nil {
		t.Fatal("Incorrectly succeeded at creating an XOR sharer for 0 shares")
	}

	if _, err := NewXORSharer(-1); err == nil {
		t.Fatal("Incorrectly succeeded at creating an XOR sharer for -1 shares")
	}
}

func TestIncorrectXORShares(t *testing.T) {
	bs, err := NewXORSharer(2)
	if err != nil {
		t.Fatal("Couldn't create a new XOR sharer:", err)
	}

	plaintext := []byte(`test plaintext`)
	authEncrypted, shares, err := EncryptAndShare(bs, plaintext)
	if err != nil {
		t.Fatal("Couldn't encrypt and share the plaintext:", err)
	}

	// Give an invalid share type value to the first share.
	shares[0][0] = 255
	if _, err = ReassembleAndDecrypt(bs, authEncrypted, shares); err == nil {
		t.Fatal("Incorrectly succeeded at reassembling and decrypting the plaintext")
	}
}

func TestCiphertextDecodingError(t *testing.T) {
	bs, err := NewXORSharer(2)
	if err != nil {
		t.Fatal("Couldn't create a new XOR sharer:", err)
	}

	plaintext := []byte(`test plaintext`)
	authEncrypted, shares, err := EncryptAndShare(bs, plaintext)
	if err != nil {
		t.Fatal("Couldn't encrypt and share the plaintext:", err)
	}

	if _, err := rand.Read(authEncrypted[:10]); err != nil {
		t.Fatal("Couldn't write over the first 10 bytes of the encrypted data")
	}

	if _, err = ReassembleAndDecrypt(bs, authEncrypted, shares); err == nil {
		t.Fatal("Incorrectly succeeded at decoding the gob-encoded ciphertext")
	}
}

func TestAuthError(t *testing.T) {
	bs, err := NewXORSharer(2)
	if err != nil {
		t.Fatal("Couldn't create a new XOR sharer:", err)
	}

	plaintext := []byte(`test plaintext`)
	authEncrypted, shares, err := EncryptAndShare(bs, plaintext)
	if err != nil {
		t.Fatal("Couldn't encrypt and share the plaintext:", err)
	}

	// Decode the ciphertext blob and clobber the HMAC, then re-encode.
	abuf := bytes.NewBuffer(authEncrypted)
	dec := gob.NewDecoder(abuf)

	var ac AuthCiphertext
	err = dec.Decode(&ac)
	if err != nil {
		t.Fatal("Couldn't decode the auth ciphertext")
	}

	if _, err := rand.Read(ac.Hmac); err != nil {
		t.Fatal("Couldn't write over the HMAC:", err)
	}

	var abuf2 bytes.Buffer
	aencoder := gob.NewEncoder(&abuf2)
	if err = aencoder.Encode(ac); err != nil {
		t.Fatal("Couldn't re-encode the bytes:", err)
	}
	authenticatedCiphertext := abuf2.Bytes()

	if _, err = ReassembleAndDecrypt(bs, authenticatedCiphertext, shares); err == nil {
		t.Fatal("Incorrectly succeeded at checking the HMAC of the ciphertext")
	}
}

func TestCipherDecodeError(t *testing.T) {
	bs, err := NewXORSharer(2)
	if err != nil {
		t.Fatal("Couldn't create a new XOR sharer:", err)
	}

	plaintext := []byte(`test plaintext`)
	authEncrypted, shares, err := EncryptAndShare(bs, plaintext)
	if err != nil {
		t.Fatal("Couldn't encrypt and share the plaintext:", err)
	}

	// Get the key so we can HMAC the garbled ciphertext bytes.
	key, err := bs.Reassemble(shares)
	if err != nil {
		t.Fatal("Couldn't reassemble the key from the shares")
	}

	// Decode the ciphertext blob and clobber the ciphertext and re-HMAC it.
	abuf := bytes.NewBuffer(authEncrypted)
	dec := gob.NewDecoder(abuf)

	var ac AuthCiphertext
	err = dec.Decode(&ac)
	if err != nil {
		t.Fatal("Couldn't decode the auth ciphertext")
	}

	if _, err := rand.Read(ac.Ciphertext); err != nil {
		t.Fatal("Couldn't write over the HMAC:", err)
	}

	h := hmac.New(sha512.New, key[2*aes.BlockSize:])
	ac.Hmac = h.Sum(ac.Ciphertext)

	var abuf2 bytes.Buffer
	aencoder := gob.NewEncoder(&abuf2)
	if err = aencoder.Encode(ac); err != nil {
		t.Fatal("Couldn't re-encode the bytes:", err)
	}
	authenticatedCiphertext := abuf2.Bytes()

	// It's possible for the decoding process to panic because the random data
	// represents an invalid pointer. In that case, this recover method will catch
	// the panic and let the test succeed.
	defer func() {
		if r := recover(); r != nil {
			t.Log("Recovered from a decoding error, as expected")
		}
	}()

	if _, err = ReassembleAndDecrypt(bs, authenticatedCiphertext, shares); err == nil {
		t.Fatal("Incorrectly succeeded at checking the HMAC of the ciphertext")
	}
}
