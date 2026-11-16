# Unbalanced RSA test fixture

These 2,048-bit RSA fixtures are generated solely for compatibility tests.
They deliberately use 512-bit and 1,536-bit prime factors and are publicly
available, weak, non-secret test data. Never use them to protect real data.

The files in this crate cover PKCS#1 PEM, PKCS#8 PEM, OpenSSH private-key PEM,
and the matching authorized-key line. The age crate's package-local copy also
contains the legacy encrypted PKCS#1 PEM variant and its test-only passphrase.
