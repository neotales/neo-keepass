# RPM spec for nkeepass. Build on a machine with rpm tooling:
#   rpmbuild -bb --define "_version <version>" packaging/rpm/nkeepass.spec
# pointing the sources at the tar.gz produced by packaging/scripts/archive.sh.
# Not built in CI: no rpm toolchain is assumed on the CI runners.
%global _binary_payload w9.xzdio

Name:           nkeepass
Version:        %{_version}
Release:        1%{?dist}
Summary:        Headless KeePass automation CLI and TUI
License:        MIT
URL:            https://github.com/neotales/neokeepass
Source0:        nkeepass-%{version}-linux.tar.gz
BuildArch:      x86_64

%description
KeePass CLI/TUI for vault navigation and entry operations. KDBX parsing is
delegated to the vendored neotales-keepass crate.

%prep
%setup -q -c

%install
install -D -m 755 nkeepass %{buildroot}%{_bindir}/nkeepass
install -D -m 644 README.md %{buildroot}%{_docdir}/nkeepass/README.md
install -D -m 644 LICENSE.md %{buildroot}%{_docdir}/nkeepass/LICENSE.md

%files
%{_bindir}/nkeepass
%doc %{_docdir}/nkeepass/README.md
%license %{_docdir}/nkeepass/LICENSE.md

%changelog
* Mon Nov 16 2026 Neotales Packaging <maintainers@neotales.invalid> - %{version}-1
- Foundation spec; built locally from the archive tarball, not published.
