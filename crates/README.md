# Cargo packages

Every Cargo package in this repository is a direct child of `crates/`. The
root workspace manifest and lockfile live at the repository root (with
`crates/nkpui/` owning its own isolated nested workspace and lockfile).

[`terminal-password`](terminal-password/README.md) isolates the synchronous
deadline-bounded hidden-input boundary used by `nkp set`, including its Unix
PTY and Windows-console restoration tests.

`neotales-keepass` and `neotales-age` (along with its transitive `neotales-x509`
dependency) are consumed as released crates from crates.io.
