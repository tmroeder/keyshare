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
	"crypto/rand"
	"fmt"
	"testing"
)

func TestShareByte(t *testing.T) {
	var b byte = 137

	bs, err := NewThresholdSharer(2, 3)
	if err != nil {
		t.Fatal(err.Error())
	}

	ss := bs.(*shamirSharer)

	// IAH: port the tests to be separate and to use the new framework
	ys, err := ss.shareByte(b)
	if err != nil {
		t.Fatal(err.Error())
	}

	xs := []byte{1, 2, 3}
	b2, err := ss.recoverByte(xs, ys)
	if err != nil {
		t.Fatal(err.Error())
	}

	fmt.Println("Byte", b, ", shares", ys)
	if b != b2 {
		t.Fatal("Recovered incorrect byte")
	}

	b3, err := ss.recoverByte(xs[:2], ys[:2])
	if err != nil {
		t.Fatal(err.Error())
	}

	if b != b3 {
		t.Fatal("Couldn't recover the byte with exactly t shares")
	}

	b4, err := ss.recoverByte(xs[:1], ys[:1])
	if err != nil {
		t.Fatal("The recovery process failed with only one share")
	}

	fmt.Println("Recovered byte", b4)

	if b == b4 {
		t.Fatal("Incorrectly recovered the right value with too few shares")
	}
}

func TestManyShares(t *testing.T) {
	var b byte = 136

	bs, err := NewThresholdSharer(255, 255)
	if err != nil {
		t.Fatal(err.Error())
	}

	ss := bs.(*shamirSharer)

	ys, err := ss.shareByte(b)
	if err != nil {
		t.Fatal(err.Error())
	}

	xs := make([]byte, 255)
	for i := range xs {
		xs[i] = byte(i + 1)
	}

	b2, err := ss.recoverByte(xs, ys)
	if err != nil {
		t.Fatal(err.Error())
	}

	if b != b2 {
		t.Fatal("Recovered incorrect byte")
	}
}

func TestShareSlice(t *testing.T) {
	b := make([]byte, 137)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err.Error())
	}

	bs, err := NewThresholdSharer(3, 5)
	if err != nil {
		t.Fatal(err.Error())
	}

	shares, err := bs.Share(b)
	if err != nil {
		t.Fatal(err.Error())
	}

	b2, err := bs.Reassemble(shares)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(b2) != len(b) {
		t.Fatal("Invalid recovered length")
	}

	for i := range b {
		if b[i] != b2[i] {
			t.Fatal("Incorrect recovered bytes")
		}
	}

	// Recover with only 3 of the 5 shares.
	b3, err := bs.Reassemble(shares[1:4])
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(b3) != len(b) {
		t.Fatal("Invalid recovered length")
	}

	for i := range b {
		if b[i] != b3[i] {
			t.Fatal("Incorrect recovered bytes")
		}
	}

	fmt.Println("Got shares", shares)
}
