# Builds offline from two sources: the release tarball and a tarball of
# `go mod vendor`. `make -f .copr/Makefile srpm` produces both; see
# packaging/rpm/README.md.

%global goipath github.com/neverlless/mokey/v2

Name:           mokey
# Overwritten from the git tag by .copr/Makefile
Version:        2.7.0
Release:        1%{?dist}
Summary:        Self-service account management portal for FreeIPA

# mokey is BSD-3-Clause; the vendored Go modules carry their own licenses
# (vendor/modules.txt lists them)
License:        BSD-3-Clause
URL:            https://github.com/neverlless/mokey
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.xz
Source2:        mokey.sysusers

ExclusiveArch:  %{golang_arches}

BuildRequires:  golang >= 1.26
BuildRequires:  go-rpm-macros
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros
%{?systemd_requires}
%if 0%{?rhel}
# rpm on EL9/EL10 does not create sysusers.d users before installing files,
# so %%attr(,mokey) would fall back to root
Requires(pre):  shadow-utils
%endif

%description
mokey is a web portal for FreeIPA / Red Hat IdM users: password reset,
signup with approval, OTP tokens, passkeys, group self-service and an
admin panel.

%prep
%autosetup -p1 -a1

%build
export GO111MODULE=on GOFLAGS=-mod=vendor GOTOOLCHAIN=local
export GO_BUILDTAGS="sqlite_omit_load_extension"
export GO_LDFLAGS="-X %{goipath}/server.Version=%{version}"
%if 0%{?rhel} == 9
# EL9's %%gobuild reads LDFLAGS instead of GO_LDFLAGS
export LDFLAGS="$GO_LDFLAGS"
%endif
%gobuild -o %{_builddir}/%{name}-bin .

%install
install -Dpm 0755 %{_builddir}/%{name}-bin %{buildroot}%{_bindir}/mokey
install -Dpm 0644 scripts/nfpm/mokey.service %{buildroot}%{_unitdir}/mokey.service
install -Dpm 0644 %{SOURCE2} %{buildroot}%{_sysusersdir}/mokey.conf
install -Dpm 0640 mokey.toml.sample %{buildroot}%{_sysconfdir}/mokey/mokey.toml
install -Dpm 0644 scripts/nfpm/mokey.env %{buildroot}%{_sysconfdir}/default/mokey
install -dm 0750 %{buildroot}%{_sysconfdir}/mokey/private
install -dm 0750 %{buildroot}%{_sharedstatedir}/mokey

%if 0%{?rhel}
%pre
getent group mokey >/dev/null || groupadd -r mokey
getent passwd mokey >/dev/null || \
    useradd -r -g mokey -d %{_sharedstatedir}/mokey -s /usr/sbin/nologin -c "mokey server" mokey
exit 0
%endif

%post
%systemd_post mokey.service

%preun
%systemd_preun mokey.service

%postun
%systemd_postun_with_restart mokey.service

%files
%license LICENSE NOTICE
%doc README.md ChangeLog.md mokey.toml.sample
%{_bindir}/mokey
%{_unitdir}/mokey.service
%{_sysusersdir}/mokey.conf
%dir %{_sysconfdir}/mokey
%dir %attr(0750,root,mokey) %{_sysconfdir}/mokey/private
%config(noreplace) %attr(0640,root,mokey) %{_sysconfdir}/mokey/mokey.toml
%config(noreplace) %{_sysconfdir}/default/mokey
%dir %attr(0750,mokey,mokey) %{_sharedstatedir}/mokey

%changelog
* Sun Nov 08 2026 Maksym Hrytsaienko <hrytsaienko.my@gmail.com> - 2.9.1-1
- Build for EPEL 9 and 10
* Thu Nov 05 2026 Maksym Hrytsaienko <hrytsaienko.my@gmail.com> - 2.7.0-1
- First COPR package
