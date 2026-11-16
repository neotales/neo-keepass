# Packaging

Status of each package target. Nothing here publishes to any repository,
registry, or store; "functional" means the scripts build a real artifact
locally and in CI, validated by `validate.sh`.

| Target   | Status          | Built by                            | Notes |
|----------|-----------------|-------------------------------------|-------|
| tar.gz   | functional      | `scripts/archive.sh`                | `tar -czf`, portable, no deps. |
| zip      | functional      | `scripts/archive.sh`                | `zip -r` (Info-ZIP). |
| deb      | functional      | `deb/build.sh`                      | `dpkg-deb --build` on Debian/Ubuntu; installs binary to `/usr/bin/nkeepass`. |
| rpm      | spec only       | `rpm/nkeepass.spec`                 | Real spec; build with `rpmbuild -bb packaging/rpm/nkeepass.spec` on a machine with rpm tooling. Not built in CI. |
| pacman   | PKGBUILD only   | `pacman/PKGBUILD`                   | Real PKGBUILD; build with `makepkg -f` on Arch. Not built in CI. |
| winget   | manifest stub   | `winget/Neotales.nkeepass.yaml`     | Skeleton with explicit placeholders. **Not** a submittable winget-pkgs manifest: it has no signed installer URL. |
| choco    | nuspec stub     | `choco/nkeepass.nuspec`             | Skeleton; `choco/tools/` is intentionally absent. Not a buildable chocolatey package. |

Version source: `crates/nkeepass/Cargo.toml` (single source of truth; scripts
read it with `scripts/version.sh`).

Nothing here uploads anywhere. Release publication is out of scope; artifacts
only ever become CI workflow artifacts.

## Layout

- `scripts/version.sh` — prints the crate version.
- `scripts/archive.sh` — builds tar.gz and zip from a built binary.
- `deb/build.sh` — builds a .deb from a built binary.
- `validate.sh` — validates produced artifacts and manifest syntax.
- `rpm/`, `pacman/`, `winget/`, `choco/` — manifests as described above.
