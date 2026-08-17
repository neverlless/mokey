FROM golang:1.26 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=1 go build \
    -ldflags "-s -w -X github.com/neverlless/mokey/server.Version=${VERSION} -extldflags=-static" \
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
