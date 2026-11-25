# Packaging

Status of each package target. Nothing here publishes to any repository,
registry, or store; "functional" means the scripts build a real artifact
locally and it is validated by `validate.sh`.

## Naming: CLI archives and executable use `nkp`; distro package identifiers stay `nkeepass`

The product is **neo-keepass** and its executable is **`nkp`** (Windows:
`nkp.exe`). The CLI distribution archives and the executable use `nkp` —
archive basenames (`nkp-<version>-<triple>.tar.gz`/`.zip`), the archive's
`nkp-<version>-<triple>/` root directory (matching `nkpui-<version>-<triple>`),
and the executable *inside* each container (`nkp` / `nkp.exe`, installed as
`/usr/bin/nkp`). Distro package identifiers deliberately keep the historical
`nkeepass` name — the deb `Package: nkeepass` field and `.deb` file name, the
rpm `Name:`, the pacman `pkgname`/provides/conflicts, and the winget/choco
identifiers (docs under `/usr/share/doc/nkeepass/`). Renaming distro package
identifiers would break existing consumers and package sources for no
functional gain, so it is not done; anything that names the *executable* or CLI
distribution archive must say `nkp`, not `nkeepass`. Human-facing display fields
(winget `PackageName`, choco `<title>`) carry the product name **neo-keepass**;
`validate.sh` asserts both.

| Target   | Status                  | Built by                        | Notes |
|----------|-------------------------|---------------------------------|-------|
| tar.gz   | functional, CI-built    | `scripts/archive.sh`            | `tar -czf`, portable, no deps. |
| zip      | functional, CI-built    | `scripts/archive.sh`            | `zip -r` (Info-ZIP). |
| deb      | functional, CI-built    | `deb/build.sh`                  | `dpkg-deb --build` on Debian/Ubuntu; installs the executable to `/usr/bin/nkp`. Validated with dpkg-deb when present, structurally (ar+tar) otherwise. |
| pacman   | functional, Arch-only   | `pacman/build.sh`               | Generates a PKGBUILD from the crate version + tarball sha256 and runs `makepkg -f`. Requires the tarball's canonical `nkp-<version>-<triple>` basename — nothing from the caller's path reaches the PKGBUILD. Installs the executable to `/usr/bin/nkp`. Tested on an Arch machine; not built in CI (ubuntu runners have no makepkg). Never installed here or anywhere. |
| rpm      | spec only, never built  | `rpm/nkeepass.spec`             | Real spec wired to the crate version and the archive tarball name; installs the executable to `/usr/bin/nkp`; build with `rpmbuild -bb` on a machine with rpm tooling. No such machine exists here or in CI, so it has **never been built — the spec is not build-verified**: the only automated check is the crate-version/archive-name wiring (`validate.sh` manifest check); any package it produces is unverified. |
| winget   | manifest stub           | `winget/Neotales.nkeepass.yaml` | Skeleton with explicit placeholders. **Not** a submittable winget-pkgs manifest: it has no signed installer URL. |
| choco    | nuspec stub             | `choco/nkeepass.nuspec`         | Skeleton; `choco/tools/` is intentionally absent. Not a buildable chocolatey package. |

Version source: `crates/nkeepass/Cargo.toml` (single source of truth; scripts
read it with `scripts/version.sh`). The pacman PKGBUILD is generated per
build from that version; the rpm spec pins it in a `%global crate_version`.

Nothing here uploads anywhere. Release publication is out of scope; artifacts
only ever become CI workflow artifacts.

### Windows artifact notice

The Windows archive includes `WINDOWS-LIMITATIONS.txt` both inside the zip
and alongside it for convenient reading; the verifier checks the copies are
byte-identical and assert the same security contract. Private file writes use
a protected current-user DACL and are allowed only when persistent ACL
enforcement is advertised and security verification succeeds; otherwise nkp
fails closed. The implementation assumes a trusted containing directory and
does not defend against administrators or the same user. Support has not
been established for every filesystem, elevated execution, or every Windows
account/configuration. See the notice itself and `docs/ci-cd.md`; do not
overstate this as universal Windows or Unix-permission parity.

## Layout

- `scripts/version.sh` — prints the crate version.
- `scripts/archive.sh` — builds tar.gz and zip from a built binary.
- `deb/build.sh` — builds a .deb from a built binary (dpkg-deb).
- `pacman/build.sh` — builds a pacman package from a tarball (makepkg).
- `validate.sh` — validates artifacts: complete format set per target with
  expected names, per-container binary extraction (regular file, not a
  symlink, ELF architecture vs triple), sha256 equality across tar/zip/deb
  and vs `--binary` when given, deb/pacman metadata, pacman payload checks
  (regular, ELF, hash identical to the tarball binary — makepkg strip/debug
  stay disabled so no transform is in play), and a timeout-bounded smoke-run
  of the native binary only after ALL checks for that target pass,
  metadata included. Without arguments, manifest syntax and version
  consistency only.
- `test.sh` — self-tests: positive path (real `dpkg-deb` builder when
  available, otherwise a fixture in real Debian structure) plus negative
  cases with asserted rejection reasons (wrong ELF architecture, wrong deb
  architecture/version, missing formats, wrong payload binary, symlink tar
  member, modified/missing pacman payload, hostile pacman filename) and
  smoke-skip assertions proving metadata/binary failures prevent execution.
- `rpm/`, `winget/`, `choco/` — manifests as described above.
