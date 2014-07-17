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

package main

import (
	"flag"

	"github.com/golang/glog"
	"github.com/tmroeder/keyshare"
)

// main takes a path to the file to encrypt. Note that this must be performed on
// a trusted system, since this code doesn't guarantee that it eliminates all
// leaks.
func main() {
	// Take in a path as input, then generate a random key, encrypt
	var plaintextFile = flag.String("plaintext", "", "The path to the unencrypted file")
	var ciphertextFile = flag.String("ciphertext", "", "The path to the encrypted file")
	var shareFilePrefix = flag.String("share", "", "The prefix for the share files")
	var shareCount = flag.Int("count", 4, "The number of shares to generate")
	var shareThreshold = flag.Int("threshold", 3, "The number of shares needed to recover the file. Set this to 0 to use XOR-based (n, n) sharing.")
	var encrypt = flag.Bool("encrypt", false, "Encrypt the plaintext to the ciphertext")
	var decrypt = flag.Bool("decrypt", false, "Decrypt the ciphertext to the plaintext")
	var qr = flag.Bool("qr", false, "Encode the results into PNG QR-code images")
	flag.Parse()

	// Check the flags to make sure they make sense.
	if len(*plaintextFile) == 0 {
		glog.Fatal("Must specify a plaintext file to encrypt")
	}

	if len(*ciphertextFile) == 0 {
		glog.Fatal("Must specify a ciphertext file for encrypted output")
	}

	if len(*shareFilePrefix) == 0 {
		glog.Fatal("Must specify a share file")
	}

	if *encrypt == *decrypt {
		glog.Fatal("Must specify exactly one of --encrypt or --decrypt")
	}

	var bs keyshare.ByteSharer
	var err error
	if *shareThreshold > 0 {
		bs, err = keyshare.NewThresholdSharer(*shareThreshold, *shareCount)
		if err != nil {
			glog.Fatal("Couldn't set up threshold sharing for threshold ", *shareThreshold,
				" and share count ", *shareCount, ": ", err)
		}
	} else {
		bs, err = keyshare.NewXORSharer(*shareCount)
		if err != nil {
			glog.Fatal("Couldn't set up XOR sharing for ", *shareCount, " shares:", err)
		}
	}

	// Read the data and perform the operation.
	if *encrypt {
		ciphertext, shares, err := keyshare.EncryptFile(*plaintextFile, bs)
		if err != nil {
			glog.Fatal("Couldn't encrypt the file ", *plaintextFile, ": ", err)
		}

		if *qr {
			if err = keyshare.EncodeToQR(*ciphertextFile, *shareFilePrefix, ciphertext, shares); err != nil {
				glog.Fatal("Couldn't encode the encryption and shares to QR: ", err)
			}
		} else {
			if err = keyshare.EncodeToBase64(*ciphertextFile, *shareFilePrefix, ciphertext, shares); err != nil {
				glog.Fatal("Couldn't encode the encryption and shares to Base64: ", err)
			}
		}
	} else if *decrypt {
		err := keyshare.DecryptFile(*plaintextFile, *ciphertextFile, *shareFilePrefix, *shareCount, bs)
		if err != nil {
			glog.Fatal("Couldn't decrypt the file '", *ciphertextFile, "': ", err)
		}
	}
}
