# RPM spec for nkeepass. Build on a machine with rpm tooling:
#   rpmbuild -bb packaging/rpm/nkeepass.spec
# with the tar.gz produced by packaging/scripts/archive.sh for
# x86_64-unknown-linux-gnu placed in the rpmbuild SOURCES directory.
# Not built in CI and not built here: no rpm toolchain is assumed on the CI
# runners or this machine. The spec is real metadata, not a stub: versions
# derive from the crate version below.
#
# RPM forbids dashes in Version:, so the crate's 0.0.0-alpha.25 is translated
# to 0.0.0.alpha.25 for the Version tag while Source0 keeps the dashed name
# the archive script produces.
%global crate_version 0.0.0-alpha.25
%global crate_version_dots %(v=%{crate_version}; echo "${v//-/.}")

Name:           nkeepass
Version:        %{crate_version_dots}
Release:        1%{?dist}
Summary:        Headless KeePass automation CLI and TUI
License:        MIT
URL:            https://github.com/neotales/neokeepass
Source0:        nkeepass-%{crate_version}-x86_64-unknown-linux-gnu.tar.gz
BuildArch:      x86_64

%description
KeePass CLI/TUI for vault navigation and entry operations. KDBX parsing is
delegated to the vendored neotales-keepass crate.

%prep
%setup -q -c -n nkeepass-%{crate_version}-x86_64-unknown-linux-gnu

%install
install -D -m 755 nkeepass %{buildroot}%{_bindir}/nkeepass
install -D -m 644 README.md %{buildroot}%{_docdir}/nkeepass/README.md
install -D -m 644 LICENSE.md %{buildroot}%{_docdir}/nkeepass/LICENSE.md

%files
%{_bindir}/nkeepass
%doc %{_docdir}/nkeepass/README.md
%license %{_docdir}/nkeepass/LICENSE.md

%changelog
* Mon Nov 16 2026 Neotales Packaging <maintainers@neotales.invalid> - %{crate_version_dots}-1
- Initial wiring; built locally from the archive tarball, not published.
