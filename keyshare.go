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

// Package keyshare provides functions that encrypt and decrypt data and split
// keys.
package keyshare

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"image/png"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"code.google.com/p/rsc/qr"
)

// zeroSlice writes 0 over all the slice elements.
func zeroSlice(slice []byte) {
	for i, _ := range slice {
		slice[i] = 0
	}
}

// A ByteSharer shares and reassembles a byte stream.
type ByteSharer interface {
	Share([]byte) ([][]byte, error)
	Reassemble([][]byte) ([]byte, error)
}

// a fullSharer uses XOR-based (n, n) secret sharing to produce n shares.
type fullSharer struct {
	shareCount int
}

// NewXORSharer creates an (n, n) secret sharer.
func NewXORSharer(n int) (ByteSharer, error) {
	if n <= 0 {
		return nil, errors.New("Must have 1 or more shares")
	}

	return &fullSharer{n}, nil
}

const (
	XOR byte = iota
	Threshold
)

// shareKey splits the key into shareCount shares using (n, n) secret sharing.
// First, choose n-1 shares at random. Then compute the nth share as
// share_1 XOR share_2 XOR ... XOR share_{n-1} XOR key.
// This guarantees that a shareholder gets zero information (statistically)
// from the share they hold, but that the combination of all 4 shares by XOR
// is the key.
func (f *fullSharer) Share(key []byte) ([][]byte, error) {
	if f.shareCount <= 0 {
		return nil, errors.New("Can't create a non-positive number of shares")
	}

	shares := make([][]byte, f.shareCount)
	keySize := len(key)

	for i, _ := range shares {
		shares[i] = make([]byte, keySize+1)
		shares[i][0] = XOR
		if i < f.shareCount-1 {
			// Read a random value into this share.
			if _, err := io.ReadFull(rand.Reader, shares[i][1:]); err != nil {
				return nil, err
			}
		} else {
			// Note that all memory starts zeroed in Go, so this doesn't need the
			// equivalent of memset for the final share.
			for j, s := range shares {
				if j < f.shareCount-1 {
					for k := 1; k < len(s); k++ {
						shares[i][k] = shares[i][k] ^ s[k]
					}
				}
			}

			// XOR in the key.
			for k := 1; k < len(shares[i]); k++ {
				shares[i][k] = shares[i][k] ^ key[k-1]
			}
		}
	}

	return shares, nil
}

// assembleShares takes all the shares and XORs them together to get the key.
func (f *fullSharer) Reassemble(shares [][]byte) ([]byte, error) {
	key := make([]byte, len(shares[0])-1)

	for _, share := range shares {
		if share[0] != XOR {
			return nil, errors.New("Bad share type")
		}

		for j := 1; j < len(share); j++ {
			key[j-1] = key[j-1] ^ share[j]
		}
	}

	return key, nil
}

// A Ciphertext is an IV combined with a value encrypted using this ciphertext.
type Ciphertext struct {
	IV         []byte
	Enciphered []byte
}

// An AuthCiphertext combines a ciphertext with an integrity check in the form
// of an HMAC computed over the gob-encoded Ciphertext.
type AuthCiphertext struct {
	// gob-encoded Ciphertext that is hmac'd in the hmac field.
	Ciphertext []byte
	Hmac       []byte
}

// encryptAndSharePlaintext generates a fresh key, uses it to encrypt the
// plaintext, shares the key, zeroes it, and returns the ciphertext and the key
// shares to be distributed.
func encryptAndShare(sharer ByteSharer, plaintext []byte) ([]byte, [][]byte, error) {
	// We generate our secret, random key from /dev/urandom. No, really. It's OK.
	// On any system you trust enough to run this program, the output from
	// /dev/urandom will be strong enough for cryptographic purposes.

	// We're going to read a key for AES-256 directly, which means we need 32
	// bytes from /dev/urandom
	aesKeyLength256 := 2 * aes.BlockSize
	keySize := aesKeyLength256 + sha512.Size
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, nil, err
	}

	// Make sure the key gets zeroed no matter how we leave this function.
	defer zeroSlice(key)

	aesKey := key[:aesKeyLength256]
	hmacKey := key[aesKeyLength256:]

	// encrypt the file, and spit out the encryption and the shares.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, err
	}

	var ciphertext Ciphertext
	ciphertext.IV = make([]byte, aes.BlockSize)
	ciphertext.Enciphered = make([]byte, len(plaintext))

	// Get the iv as a slice of the second part of the ciphertext.
	if _, err = io.ReadFull(rand.Reader, ciphertext.IV); err != nil {
		return nil, nil, err
	}

	stream := cipher.NewCTR(block, ciphertext.IV)
	stream.XORKeyStream(ciphertext.Enciphered, plaintext)

	// Use gob encoding to define the data to be hmac'd
	var cbuf bytes.Buffer
	encoder := gob.NewEncoder(&cbuf)
	err = encoder.Encode(ciphertext)
	if err != nil {
		return nil, nil, err
	}

	var ac AuthCiphertext
	ac.Ciphertext = cbuf.Bytes()

	h := hmac.New(sha512.New, hmacKey)
	h.Write(ac.Ciphertext)
	ac.Hmac = h.Sum(nil)

	var abuf bytes.Buffer
	aencoder := gob.NewEncoder(&abuf)
	err = aencoder.Encode(ac)
	authenticatedCiphertext := abuf.Bytes()

	shares, err := sharer.Share(key)

	return authenticatedCiphertext, shares, nil
}

// assembleAndDecrypt reassembles a key from a set of shares and uses this key
// to authenticate and decrypt a ciphertext.
func assembleAndDecrypt(sharer ByteSharer, authenticatedCiphertext []byte, shares [][]byte) ([]byte, error) {
	// Reassemble the key and use that to check the HMAC
	key, err := sharer.Reassemble(shares)
	if err != nil {
		return nil, err
	}
	defer zeroSlice(key)

	aesKeyLength256 := 2 * aes.BlockSize
	aesKey := key[:aesKeyLength256]
	hmacKey := key[aesKeyLength256:]

	// Decode the ciphertext blob and check the HMAC.
	abuf := bytes.NewBuffer(authenticatedCiphertext)
	dec := gob.NewDecoder(abuf)

	var ac AuthCiphertext
	err = dec.Decode(&ac)
	if err != nil {
		return nil, err
	}

	h := hmac.New(sha512.New, hmacKey)
	h.Write(ac.Ciphertext)
	computedMac := h.Sum(nil)
	if subtle.ConstantTimeCompare(ac.Hmac, computedMac) != 1 {
		err = errors.New("Authentication failure")
		return nil, err
	}

	// Now it's safe to deserialize the inner gob structure.
	cbuf := bytes.NewBuffer(ac.Ciphertext)
	dec2 := gob.NewDecoder(cbuf)

	var c Ciphertext
	err = dec2.Decode(&c)
	if err != nil {
		return nil, err
	}

	// Decrypt the file now that the authentication check passed
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, c.IV)
	plaintext := make([]byte, len(c.Enciphered))
	stream.XORKeyStream(plaintext, c.Enciphered)

	return plaintext, nil
}

// EncryptFile takes in the name of a file to encrypt, an output file for the
// ciphertext, a share file prefix for the shares, and the number of shares to
// create and creates a file encrypted with a fresh key. This key is then shared
// into shareCount pieces.
func EncryptFile(plaintextFile, ciphertextFile, shareFile string, sharer ByteSharer) error {
	secretData, err := ioutil.ReadFile(plaintextFile)
	if err != nil {
		return err
	}
	defer zeroSlice(secretData)

	ciphertext, shares, err := encryptAndShare(sharer, secretData)
	for _, s := range shares {
		defer zeroSlice(s)
	}

	// Encode as a QR code.
	cs := base64.StdEncoding.EncodeToString(ciphertext)
	code, err := qr.Encode(cs, qr.H)
	if err != nil {
		return err
	}

	f, err := os.Create(ciphertextFile + ".png")
	if err != nil {
		return err
	}
	defer f.Close()

	if err := png.Encode(f, code.Image()); err != nil {
		return err
	}

	for i, s := range shares {
		fmt.Println(i)
		// Output the shares as well.
		shareOutput, err := os.Create(shareFile + strconv.Itoa(i) + ".png")
		if err != nil {
			return err
		}
		defer shareOutput.Close()

		shareString := base64.StdEncoding.EncodeToString(s)
		shareCode, err := qr.Encode(shareString, qr.H)
		if err := png.Encode(shareOutput, shareCode.Image()); err != nil {
			return err
		}
	}

	return nil
}

// DecryptFile takes in the name of a output file, a file to decrypt, and a file
// of shares, one per line. It decrypts the encrypted file into the output file
// or reports an error.
func DecryptFile(plaintextFile, ciphertextFile, shareFile string, sharer ByteSharer) error {
	// Get the shares from the file.
	sharesString, err := ioutil.ReadFile(shareFile)
	if err != nil {
		return err
	}

	// The shares are stored one per line.
	trimmedSharesString := strings.TrimSpace(string(sharesString))
	shareStrings := strings.Split(trimmedSharesString, "\n")
	shares := make([][]byte, len(shareStrings))
	encoding := base64.StdEncoding
	for i, ss := range shareStrings {
		shares[i], err = encoding.DecodeString(ss)
		defer zeroSlice(shares[i])
	}

	ciphertext, err := ioutil.ReadFile(ciphertextFile)
	if err != nil {
		return err
	}

	cipherBytes := make([]byte, encoding.DecodedLen(len(ciphertext)))
	_, err = encoding.Decode(cipherBytes, ciphertext)
	plaintext, err := assembleAndDecrypt(sharer, cipherBytes, shares)
	if err != nil {
		return err
	}
	defer zeroSlice(plaintext)

	err = ioutil.WriteFile(plaintextFile, plaintext, 0600)
	if err != nil {
		return err
	}

	return nil
}
