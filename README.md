keyshare
--------

The keyshare library and its associated sharegen tool provide a way to encrypt a
file; it produces multiple shares of the key used to encrypt the file, and it
requires a threshold number of shares to perform decryption. Keyshare supports
two different schemes: XOR-based (n, n) secret sharing, and Shamir (t, n)
threshold secret sharing.

The sharegen tool can be used to encrypt a plaintext file `p` to a ciphertext
file `c` and a set of share files `s0`, `s1`, `s2`, and `s3` as follows.

    sharegen -encrypt -plaintext=p -ciphertext=c -share=s -count=4

If the threshold is 0, then sharegen uses XOR secret sharing, and all shares are
required for reassembly and decryption. Otherwise, there must be at least the
threshold number of share files available. The default value of `-threshold` is
0, so the default sharing scheme is XOR.

The decryption parameters are almost the same. For example, to produce a file
`p2` from the ciphertext `c` and the shares `s0`, `s1`, `s2`, and `s3`:

    sharegen -decrypt -plaintext=p2 -ciphertext=c -share=s -count=4

To produce QR-code PNG files for the ciphertext and the shares instead of
base64-encoded files, use the parameter `-qr`. Note that you must use an
external QR decoding tool to extract the base64-encoded ciphertext and shares to
decrypt the data. The main advantages of the QR code is that it adds
Reed-Solomon error-correcting codes and it is easier to extract as digital data
from printed files.

See `sharegen -help` for more details.
