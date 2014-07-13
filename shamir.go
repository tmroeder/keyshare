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
  "errors"

  "code.google.com/p/rsc/gf256"
)

// ShareByte generates a (t, n) secret sharing for byte b over GF(256).
func ShareByte(f *gf256.Field, b byte, t, n int) ([]byte, error) {
  if t > 255 {
    return nil, errors.New("can't have more than 255 shares")
  }

  if t > n {
    return nil, errors.New("can't require more shares than you create")
  }
  
  if t <= 0 {
    return nil, errors.New("must require at least one share")
  }

  // Choose t - 1 random non-zero bytes
  coeff := make([]byte, t)
  coeff[0] = b

  for i := range coeff {
    if i != 0 {
      for coeff[i] == 0 {
        if _, err := rand.Read(coeff[i:i+1]); err != nil {
          return nil, err
        }
      }
    }
  }

  // Evaluate the polynomial at 1, 2, .., n
  ys := make([]byte, n)
  for i := 1; i <= n; i++ {
    ys[i - 1] = EvaluatePoly(coeff, byte(i), f)
  }

  return ys, nil
}

// EvaluatePoly evaluates a polynomial with coefficients in GF(256)
func EvaluatePoly(poly []byte, v byte, f *gf256.Field) byte {
  var pow byte = 1
  var acc byte = 0
  for _, b := range poly {
    acc = f.Add(acc, f.Mul(pow, b))
    pow = f.Mul(pow, v)
  }

  return acc
}

// RecoverByte uses the given xs and ys to recover the original byte using
// Langrange polynomial interpolation.
func RecoverByte(f *gf256.Field, xs, ys []byte) (byte, error) {
  if len(xs) != len(ys) {
    return 0, errors.New("inconsistent array counts")
  }

  // The byte can be recovered from the derived formula
  // sum_i(y_i prod_{j != i}(x_j / (x_i + x_j))), which follows in
  // characteristic 2 by setting x to 0 in the Langrange polynomial form.
  var acc byte = 0
  for i, y := range ys {
    var prod byte = 1
    xi := xs[i]
    for j, x := range xs {
      if j != i {
        p := f.Mul(x, f.Inv(f.Add(xi, x)))
        prod = f.Mul(prod, p)
      }
    }

    acc = f.Add(acc, f.Mul(y, prod))
  }

  return acc, nil
}
