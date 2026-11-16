# `neotales-x509`

X.509 identifiers, certificate/SSH wire conversion, key encodings, and SSH
private-key conversion for Rust.

The crate contains its DER, PEM, SSH wire, bcrypt KDF, and key-conversion code
locally. It does not depend on a separate `neotales-crypto` package.

## What it covers

- **OpenSSH certificate and SSH-X.509 wire conversion**, including bounded
  parsing and writing for supported certificate forms.
- **SSH keypair conversion** for Ed25519, RSA, and P-256 into self-signed X.509
  certificates and PKCS#8 material.
- **PEM parsing/encoding** and an object identifier catalog.

## What it does not do

- **No validation against a trust store.** It parses and generates; deciding
  whether to trust a certificate is a policy decision that belongs to the caller
  and to whatever policy library they already use.
- **No revocation.** Same reason. A CRL or an OCSP response is fetched by
  something that knows the network.
- **No trust-store or revocation policy.** Callers decide whether to trust
  certificates and how to obtain revocation status.
- **No network access.** Parsing and generation are local operations.

## What is verified, and what is not

The workspace tests cover SSH key conversion, certificate and wire-format
round trips, validity-time boundaries, and truncation handling. Current local
verification was on Linux. No normal test invokes `ssh-keygen`/`ssh` for
external interoperability, and fuzzing is not configured.

## Direct dependencies

The manifest lists `aes`, `base64`, `blowfish`, `ctr`, `ed25519-dalek`,
`ml-dsa`, `p256`, `p384`, `p521`, `rcgen`, `rsa`, `sha2`, `subtle`, `time`,
and `zeroize`. Exact versions and feature flags are in `Cargo.toml`.

RSA PKCS#1, PKCS#8, and OpenSSH private-key parsing accepts unbalanced
two-prime keys using `rsa 0.10`'s wide-prime constructor, selected independently
of secret factor widths. This does **not** mean every such key can be converted
to X.509: certificate signing goes through `rcgen`/`ring`, which rejects
strongly asymmetric prime widths with `SshKeyError::InvalidPrivateKey`.
Multi-prime PKCS#1 keys are unsupported by upstream `rsa 0.10`.

## Licence

MIT. See [LICENSE.md](LICENSE.md).
