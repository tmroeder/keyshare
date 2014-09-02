// Copyright 2014, Tom Roeder (tmroeder@gmail.com). All rights reserved.
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
	"crypto/rand"
	"encoding/base64"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"testing"
)

const decodeQR = "./zxing"

var decodeQRArgs = []string{"--try-harder"}

func findDecodeQR() (string, error) {
	// Look for the decoder in the path and in the current directory. If we can't
	// find it, then give up on the test.
	path, err := exec.LookPath(decodeQR)
	if err == nil {
		return path, nil
	}

	if _, err := os.Stat(decodeQR); err != nil {
		return "", err
	}

	return decodeQR, nil
}

func TestRecovery(t *testing.T) {
	qrdec, err := findDecodeQR()
	if err != nil {
		t.Skip(err)
	}
	// Create a temporary directory for the files
	threshold := 3
	shareCount := 5
	tempdir, err := ioutil.TempDir("", "keyshare_recovery_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempdir)

	plaintextFile := path.Join(tempdir, "plaintext")
	//decryptedFile := path.Join(tempdir, "decrypted")
	ciphertextFile := path.Join(tempdir, "ciphertext")
	sharesPrefix := path.Join(tempdir, "shares")

	plaintext := make([]byte, 200)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		t.Fatal(err)
	}

	if err := ioutil.WriteFile(plaintextFile, plaintext, 0600); err != nil {
		t.Fatal(err)
	}

	bs, err := NewThresholdSharer(threshold, shareCount)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, shares, err := EncryptFile(plaintextFile, bs)
	if err != nil {
		t.Fatal(err)
	}

	if err := EncodeToQR(ciphertextFile, sharesPrefix, ciphertext, shares); err != nil {
		t.Fatal(err)
	}

	// Call the decoder to get back the ciphertext and each share.
	ccmdArgs := make([]string, len(decodeQRArgs)+1)
	copy(ccmdArgs, decodeQRArgs)
	ccmdArgs[len(ccmdArgs)-1] = ciphertextFile + ".png"

	ciphertextCmd := exec.Command(qrdec, ccmdArgs...)
	ciphertextBase64, err := ciphertextCmd.Output()
	if err != nil {
		t.Fatal("Couldn't run the QR decoding command to get the ciphertext:", err)
	}
	recoveredCiphertext, err := base64.StdEncoding.DecodeString(string(ciphertextBase64))
	if err != nil {
		t.Fatal("The base64 ciphertext didn't decode properly:", err)
	}
	if !bytes.Equal(recoveredCiphertext, ciphertext) {
		t.Fatal("The recovered ciphertext didn't match the original ciphertext")
	}

	for i := range shares {
		shareFile := sharesPrefix + strconv.Itoa(i) + ".png"
		scmdArgs := make([]string, len(decodeQRArgs)+1)
		copy(scmdArgs, decodeQRArgs)
		scmdArgs[len(ccmdArgs)-1] = shareFile
		scmd := exec.Command(qrdec, scmdArgs...)
		shareBase64, err := scmd.Output()
		if err != nil {
			t.Fatal("Couldn't run the QR decoding command to get share", i, ":", err)
		}
		recoveredShare, err := base64.StdEncoding.DecodeString(string(shareBase64))
		if err != nil {
			t.Fatal("The base64 share", i, "didn't decode properly:", err)
		}
		if !bytes.Equal(recoveredShare, shares[i]) {
			t.Fatal("Recovered share", i, "didn't match the original")
		}
	}
}
