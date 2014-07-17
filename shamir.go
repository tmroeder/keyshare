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

// A shamirSharer performs byte-wise (t, n) threshold secret sharing using
// GF(256).
type shamirSharer struct {
	f *gf256.Field
	t int
	n int
}

func NewThresholdSharer(t, n int) (ByteSharer, error) {
	if t > 255 {
		return nil, errors.New("can't have more than 255 shares")
	}

	if t > n {
		return nil, errors.New("can't require more shares than you create")
	}

	if t <= 0 {
		return nil, errors.New("must require at least one share")
	}

	ss := new(shamirSharer)
	ss.t = t
	ss.n = n

	// We use the Reed-Solomon field for the byte-wise secret-sharing operation.
	ss.f = gf256.NewField(0x11d, 2)
	return ss, nil
}

// shareByte generates a (t, n) secret sharing for byte b over GF(256).
func (ss *shamirSharer) shareByte(b byte) ([]byte, error) {

	// Choose t - 1 random non-zero bytes
	coeff := make([]byte, ss.t)
	coeff[0] = b

	for i := range coeff {
		if i != 0 {
			for coeff[i] == 0 {
				if _, err := rand.Read(coeff[i : i+1]); err != nil {
					return nil, err
				}
			}
		}
	}

	// Evaluate the polynomial at 1, 2, .., n
	ys := make([]byte, ss.n)
	for i := 1; i <= ss.n; i++ {
		ys[i-1] = evaluatePoly(coeff, byte(i), ss.f)
	}

	return ys, nil
}

// evaluatePoly evaluates a polynomial with coefficients in GF(256).
func evaluatePoly(poly []byte, v byte, f *gf256.Field) byte {
	var pow byte = 1
	var acc byte = 0
	for _, b := range poly {
		acc = f.Add(acc, f.Mul(pow, b))
		pow = f.Mul(pow, v)
	}

	return acc
}

// recoverByte uses the given xs and ys to recover the original byte using
// Lagrange polynomial interpolation.
func (ss *shamirSharer) recoverByte(xs, ys []byte) (byte, error) {
	if len(xs) != len(ys) {
		return 0, errors.New("inconsistent array counts")
	}

	// The byte can be recovered from the derived formula
	// sum_i(y_i prod_{j != i}(x_j / (x_i + x_j))), which follows in
	// characteristic 2 by setting x to 0 in the Lagrange polynomial form.
	var acc byte = 0
	for i, yi := range ys {
		var prod byte = 1
		xi := xs[i]
		for j, xj := range xs {
			if j != i {
				p := ss.f.Mul(xj, ss.f.Inv(ss.f.Add(xi, xj)))
				prod = ss.f.Mul(prod, p)
			}
		}

		acc = ss.f.Add(acc, ss.f.Mul(yi, prod))
	}

	return acc, nil
}

// Share uses Shamir secret sharing to encode a slice of bytes into n
// shares, any t of which can reconstruct the secret.
func (ss *shamirSharer) Share(bs []byte) ([][]byte, error) {
	// Create the shares and assign each a share number.
	shares := make([][]byte, ss.n)
	for j := range shares {
		shares[j] = make([]byte, len(bs)+2)

		// The first byte is the share type, and the second is the share number.
		shares[j][0] = Threshold
		shares[j][1] = byte(j + 1)
	}

	for i, b := range bs {
		byteShares, err := ss.shareByte(b)
		if err != nil {
			return nil, err
		}

		for j := range shares {
			shares[j][i+2] = byteShares[j]
		}
	}

	return shares, nil
}

// Reassemble takes in a set of shares and reconstructs each byte using Shamir
// secret sharing.
func (ss *shamirSharer) Reassemble(shares [][]byte) ([]byte, error) {
	xs := make([]byte, len(shares))
	ys := make([]byte, len(shares))
	l := len(shares[0])
	for i := range shares {
		if len(shares[i]) != l {
			return nil, errors.New("Inconsistent share lengths")
		}

		// The first element of a share is its share type.
		if shares[i][0] != Threshold {
			return nil, errors.New("Bad threshold share type")
		}

		// The second element of a share is its share number.
		xs[i] = shares[i][1]
	}

	secret := make([]byte, l-2)

	// Reconstruct each byte of the output.
	for i := 2; i < l; i++ {
		for j := range shares {
			ys[j] = shares[j][i]
		}

		var err error
		secret[i-2], err = ss.recoverByte(xs, ys)
		if err != nil {
			return nil, err
		}

	}

	return secret, nil
}
