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
	var shareFile = flag.String("shares", "", "The path to the shares")
	var shareCount = flag.Int("share_count", 4, "The number of shares to generate")
	var encrypt = flag.Bool("encrypt", false, "Encrypt the plaintext to the ciphertext")
	var decrypt = flag.Bool("decrypt", false, "Decrypt the ciphertext to the plaintext")
	flag.Parse()

	// Check the flags to make sure they make sense.
	if len(*plaintextFile) == 0 {
		glog.Fatal("Must specify a plaintext file to encrypt")
	}

	if len(*ciphertextFile) == 0 {
		glog.Fatal("Must specify a ciphertext file for encrypted output")
	}

	if len(*shareFile) == 0 {
		glog.Fatal("Must specify a share file")
	}

	if *encrypt == *decrypt {
		glog.Fatal("Must specify exactly one of --encrypt or --decrypt")
	}

	// Read the data and perform the operation.
	if *encrypt {
		err := keyshare.EncryptFile(*plaintextFile, *ciphertextFile, *shareFile, *shareCount)
		if err != nil {
			glog.Fatal("Couldn't encrypt the file", *plaintextFile, ":", err)
		}
	} else if *decrypt {
		err := keyshare.DecryptFile(*plaintextFile, *ciphertextFile, *shareFile)
		if err != nil {
			glog.Fatal("Couldn't decrypt the file", *ciphertextFile, ":", err)
		}
	}
}
