# Packaging

Status of each package target. Nothing here publishes to any repository,
registry, or store; "functional" means the scripts build a real artifact
locally and it is validated by `validate.sh`.

| Target   | Status                  | Built by                        | Notes |
|----------|-------------------------|---------------------------------|-------|
| tar.gz   | functional, CI-built    | `scripts/archive.sh`            | `tar -czf`, portable, no deps. |
| zip      | functional, CI-built    | `scripts/archive.sh`            | `zip -r` (Info-ZIP). |
| deb      | functional, CI-built    | `deb/build.sh`                  | `dpkg-deb --build` on Debian/Ubuntu; installs binary to `/usr/bin/nkeepass`. Validated with dpkg-deb when present, structurally (ar+tar) otherwise. |
| pacman   | functional, Arch-only   | `pacman/build.sh`               | Generates a PKGBUILD from the crate version + tarball sha256 and runs `makepkg -f`. Requires the tarball's canonical `nkeepass-<version>-<triple>` basename — nothing from the caller's path reaches the PKGBUILD. Tested on an Arch machine; not built in CI (ubuntu runners have no makepkg). Never installed here or anywhere. |
| rpm      | spec only, never built  | `rpm/nkeepass.spec`             | Real spec wired to the crate version and the archive tarball name; build with `rpmbuild -bb` on a machine with rpm tooling. No such machine exists here or in CI, so it has never been built. |
| winget   | manifest stub           | `winget/Neotales.nkeepass.yaml` | Skeleton with explicit placeholders. **Not** a submittable winget-pkgs manifest: it has no signed installer URL. |
| choco    | nuspec stub             | `choco/nkeepass.nuspec`         | Skeleton; `choco/tools/` is intentionally absent. Not a buildable chocolatey package. |

Version source: `crates/nkeepass/Cargo.toml` (single source of truth; scripts
read it with `scripts/version.sh`). The pacman PKGBUILD is generated per
build from that version; the rpm spec pins it in a `%global crate_version`.

Nothing here uploads anywhere. Release publication is out of scope; artifacts
only ever become CI workflow artifacts.

## Layout

- `scripts/version.sh` — prints the crate version.
- `scripts/archive.sh` — builds tar.gz and zip from a built binary.
- `deb/build.sh` — builds a .deb from a built binary (dpkg-deb).
- `pacman/build.sh` — builds a pacman package from a tarball (makepkg).
- `validate.sh` — validates artifacts: complete format set per target with
  expected names, per-container binary extraction (regular file, not a
  symlink, ELF architecture vs triple), sha256 equality across tar/zip/deb
  and vs `--binary` when given, deb/pacman metadata, and a timeout-bounded
  smoke-run of the native binary only after all checks pass. Without
  arguments, manifest syntax and version consistency only.
- `test.sh` — self-tests: positive path (real `dpkg-deb` builder when
  available, otherwise a fixture in real Debian structure) plus negative
  cases with asserted rejection reasons (wrong ELF architecture, wrong deb
  architecture/version, missing formats, wrong payload binary, hostile
  pacman filename).
- `rpm/`, `winget/`, `choco/` — manifests as described above.
