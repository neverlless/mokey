# COPR "make srpm" entry point; also works locally on Fedora:
#   make -f .copr/Makefile srpm outdir=/tmp/srpm
# The SRPM build has network access, the RPM build does not, so the Go
# modules are vendored here into a second source tarball.

top := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
outdir ?= $(top)/dist/srpm
work := $(outdir)/.work

srpm:
	command -v go >/dev/null && command -v rpmbuild >/dev/null && command -v git >/dev/null || \
		dnf -y install golang rpm-build git
	rm -rf $(work) && mkdir -p $(work)/src
	set -eu; cd $(top); \
	ver=$$(git -c safe.directory='*' describe --tags --match 'v*' | sed 's/^v//; s/-/^/; s/-/./'); test -n "$$ver"; \
	git -c safe.directory='*' archive --prefix=mokey-$$ver/ -o $(work)/src/mokey-$$ver.tar.gz HEAD; \
	tar -xzf $(work)/src/mokey-$$ver.tar.gz -C $(work); \
	cd $(work)/mokey-$$ver && GOTOOLCHAIN=local GOFLAGS=-modcacherw GOPATH=$(work)/gopath go mod vendor; \
	tar -cJf $(work)/src/mokey-$$ver-vendor.tar.xz vendor; \
	cp $(top)/packaging/rpm/mokey.sysusers $(work)/src/; \
	sed "s/^Version:.*/Version:        $$ver/" $(top)/packaging/rpm/mokey.spec > $(work)/mokey.spec; \
	rpmbuild -bs --define "_sourcedir $(work)/src" --define "_srcrpmdir $(outdir)" $(work)/mokey.spec
	rm -rf $(work)

.PHONY: srpm
