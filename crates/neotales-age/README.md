# `neotales-age`

An implementation of the [age](https://age-encryption.org) v1 file encryption
format for Rust. The core format runs in-process; the optional plugin client
launches the named `age-plugin-<name>` executable as a child process.

age is designed to be hard to misuse. A file is encrypted to *recipients* and
decrypted by *identities*, the two are asymmetric, and the format has no way to
express "encrypt with this password" without also being explicit about how the
password is stretched.

## What it supports

- **X25519** native keys, the format's default.
- **Post-quantum hybrid recipients**, ML-KEM-768 with X25519, for data that has to
  stay confidential for longer than a discrete logarithm is assumed to hold.
- **Encryption-only tagged recipients** on P-256 and on the same hybrid, for a
  curve with different hardware support.
- **scrypt passphrases.**
- **SSH keys**, Ed25519 and RSA, so an existing `~/.ssh` identity works.
- **The binary STREAM payload and strict ASCII armor**, both implemented directly.
- **Plugins**, including recipient/identity protocol clients and an executable
  framework. Client calls spawn plugin processes and exchange the age plugin
  protocol over pipes.

It implements the format itself rather than wrapping the `age` command-line
program. Plugin support is the exception to the no-subprocess rule: treat plugin
executables as external programs and decide explicitly whether to enable them.

## Example

```rust
use neotales_age::{AgeFile, AgeIdentity, AgeKey, AgeRecipient};

let key = AgeKey::generate()?;
let recipient = AgeRecipient::from_public_key(&key.public_key)?;
let identity = AgeIdentity::from_private_key(&key.private_key)?;

let encrypted = AgeFile::encrypt(b"a message", &[recipient])?;
assert_eq!(AgeFile::decrypt(&encrypted, &[identity])?, b"a message");
# Ok::<(), neotales_age::Error>(())
```

The identity is what decrypts and the recipient is what encrypts, which is the
point of the format: give somebody the public half and they can write to you
without being able to read what you wrote.

## What it does not do

- **It does not wrap the `age` CLI.** Its file format implementation is local;
  only the optional plugin protocol starts child processes.
- **It does provide streaming and path APIs.** `AgeFile::encrypt_reader`,
  `decrypt_reader`, and the streaming reader/writer APIs accept caller-owned
  streams. `AgeFile::encrypt_file` and `decrypt_file` create a temporary output
  beside the requested destination and rename it into place. Those path
  functions do not impose the application's owner-only permission or
  no-clobber policy; callers writing secrets must provide those guarantees.
- **It has no keyring integration.** An identity is something the caller supplies.
  Where it came from is not this crate's business.
- **It does not provide application key storage or recipient discovery.**
  Applications supply identities and recipients and control any network lookup.

## What is verified, and what is not

The workspace tests cover native/hybrid keys, SSH keys, passphrases, binary and
armored payloads, streaming, plugin protocol surfaces, parser limits, and
identity/recipient syntax. The current local verification was on Linux.

Interoperation with `rage` is not run by the normal workspace test command.
`tests/interop.rs` contains ignored cases that require the reference CLI; the
workspace does not install it. The 16,384-bit RSA SSH test is also an ignored
slow-lane test.

Fuzzing does not run. The parsers enforce size limits, but bounded parsing is
not a substitute for fuzzing.

## Direct dependencies

Along with the local `neotales-x509` crate, the manifest directly uses `aes`,
`base64`, `cbc`, `chacha20poly1305`, `ctr`, `des`, `ed25519-dalek`, `getrandom`
(0.3 and 0.4), `hkdf`, `hmac`, `hpke`, `md-5`, `p256`, `rsa`, `sad-rsa`,
`scrypt`, `sha2`, `subtle`, `x25519-dalek`, and `zeroize`. The exact versions
and feature flags are in `Cargo.toml`; `Cargo.lock` pins the workspace graph.

## Licence

MIT. See [LICENSE.md](LICENSE.md).
