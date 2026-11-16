# Unbalanced RSA test fixture

These 2,048-bit RSA fixtures are generated solely for compatibility tests.
They deliberately use 512-bit and 1,536-bit prime factors and are publicly
available, weak, non-secret test data. Never use them to protect real data.

The files cover PKCS#1 PEM, PKCS#8 PEM, OpenSSH private-key PEM, and legacy
encrypted PKCS#1 PEM. The encrypted test passphrase is
`unbalanced-test-pass`. `rsa-unbalanced.pub` is the matching authorized-key
line.
