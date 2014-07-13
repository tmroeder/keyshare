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
  "fmt"
  "testing"

  "code.google.com/p/rsc/gf256"
)

func TestShareByte(t *testing.T) {
  var b byte = 137

  // Use the Reed-Solomon field for testing.
  f := gf256.NewField(0x11d, 2)

  ys, err := ShareByte(f, b, 2, 3)
  if err != nil {
    t.Fatal(err.Error())
  }

  xs := []byte{1, 2, 3}
  b2, err := RecoverByte(f, xs, ys)
  if err != nil {
    t.Fatal(err.Error())
  }

  fmt.Println("Byte", b, ", shares", ys)
  if b != b2 {
    t.Fatal("Recovered incorrect byte")
  }

  b3, err := RecoverByte(f, xs[:2], ys[:2])
  if err != nil {
    t.Fatal(err.Error())
  }

  if b != b3 {
    t.Fatal("Couldn't recover the byte with exactly t shares")
  }

  b4, err := RecoverByte(f, xs[:1], ys[:1])
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

  // Use the Reed-Solomon field for testing.
  f := gf256.NewField(0x11d, 2)

  ys, err := ShareByte(f, b, 255, 255)
  if err != nil {
    t.Fatal(err.Error())
  }

  xs := make([]byte, 255)
  for i := range xs {
    xs[i] = byte(i + 1)
  }

  b2, err := RecoverByte(f, xs, ys)
  if err != nil {
    t.Fatal(err.Error())
  }

  if b != b2 {
    t.Fatal("Recovered incorrect byte")
  }
}
