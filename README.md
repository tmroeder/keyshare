keyshare
--------

The keyshare library and its associated sharegen tool provide a way to encrypt a
file; it produces multiple shares of the key used to encrypt the file, and it
requires a threshold number of shares to perform decryption. In the current
implementation, all shares are required.

The sharegen tool can be used to encrypt a plaintext file `p` to a ciphertext
file `c` and a share file `s` as follows.

    sharegen -encrypt -plaintext=p -ciphertext=c -shares=s

The decryption parameters are almost the same. For example, to produce a file
`p2` from the ciphertext `c` and the shares `s`:

    sharegen -decrypt -plaintext=p2 -ciphertext=c -shares=s

See `sharegen -help` for more details.
