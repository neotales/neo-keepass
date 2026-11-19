# Cargo packages

Every Cargo package in this repository is a direct child of `crates/`. The
workspace manifest and lockfile remain at the repository root.

[`terminal-password`](terminal-password/README.md) isolates the synchronous
deadline-bounded hidden-input boundary used by `nkp set`, including its Unix
PTY and Windows-console restoration tests.

`neotales-age` and its required `neotales-x509` dependency are vendored from
plab's `rs/lib/crypto/age` and `rs/lib/crypto/x509` at source revision
`18a3375ff15c10ae842fcb1289e573e1eee41bbe`. Both crates carry the MIT license
from the source project in `LICENSE.md`; the original crate READMEs and
dependency declarations are retained.
