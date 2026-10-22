# The builder runs natively and cross-compiles: CGO (sqlite3) under QEMU
# emulation is too slow for CI.
FROM --platform=$BUILDPLATFORM golang:1.27 AS builder

ARG TARGETARCH
ARG BUILDARCH
RUN if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      case "$TARGETARCH" in \
        amd64) gcc=gcc-x86-64-linux-gnu ;; \
        arm64) gcc=gcc-aarch64-linux-gnu ;; \
        *) echo "unsupported TARGETARCH $TARGETARCH" >&2; exit 1 ;; \
      esac; \
      apt-get update && \
      apt-get install -y --no-install-recommends $gcc libc6-dev-$TARGETARCH-cross && \
      rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN if [ "$TARGETARCH" = "$BUILDARCH" ]; then export CC=gcc; \
    elif [ "$TARGETARCH" = amd64 ]; then export CC=x86_64-linux-gnu-gcc; \
    else export CC=aarch64-linux-gnu-gcc; fi && \
    CGO_ENABLED=1 GOOS=linux GOARCH=$TARGETARCH go build \
    -ldflags "-s -w -X github.com/neverlless/mokey/v2/server.Version=${VERSION} -extldflags=-static" \
    -tags "sqlite_omit_load_extension osusergo netgo" \
    -o /mokey .

# ipa-client tools are required for optional container-side FreeIPA
# enrollment and keytab retrieval (see docker/entrypoint.sh)
FROM quay.io/centos/centos:stream9

RUN dnf install -y epel-release && \
    dnf install -y ipa-client curl glibc-langpack-en --nobest --allowerasing && \
    dnf clean all && rm -rf /var/cache/dnf

COPY --from=builder /mokey /usr/bin/mokey
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh && mkdir -p /etc/mokey/private

EXPOSE 8866

ENTRYPOINT ["/entrypoint.sh"]
CMD ["mokey", "serve", "--config=/etc/mokey/mokey.toml"]
