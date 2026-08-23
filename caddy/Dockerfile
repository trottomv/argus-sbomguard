ARG CRS_VERSION=v4.4.0
ARG CADDY_VERSION=2.11.4
ARG XCADDY_VERSION=v0.4.7
ARG GO_VERSION=1.26.7
ARG GO_SHA256=ffb5f8de10c62550dfddab66b36b57030721e0a44a3218e9e1181d7b59f121ca

FROM dhi.io/caddy:2-debian-dev AS builder

ARG GO_VERSION
ARG GO_SHA256
ARG CADDY_VERSION
ARG XCADDY_VERSION

RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates gzip libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz \
    && echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOTOOLCHAIN=local
ENV GOBIN=/usr/local/bin

ARG GO_JOSE_VERSION=v3.0.5
ARG X_CRYPTO_VERSION=v0.52.0
ARG X_NET_VERSION=v0.56.0
ARG X_TEXT_VERSION=v0.39.0
ARG GRPC_VERSION=v1.82.1
ARG OTEL_VERSION=v1.44.0
ARG CHI_VERSION=v5.3.0
ARG KL_POST_VERSION=v1.18.7

RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}

RUN xcaddy build v${CADDY_VERSION} --output /usr/bin/caddy \
    --with github.com/corazawaf/coraza-caddy \
    --with github.com/mholt/caddy-ratelimit \
    --replace github.com/go-jose/go-jose/v3=github.com/go-jose/go-jose/v3@${GO_JOSE_VERSION} \
    --replace golang.org/x/crypto=golang.org/x/crypto@${X_CRYPTO_VERSION} \
    --replace golang.org/x/net=golang.org/x/net@${X_NET_VERSION} \
    --replace golang.org/x/text=golang.org/x/text@${X_TEXT_VERSION} \
    --replace google.golang.org/grpc=google.golang.org/grpc@${GRPC_VERSION} \
    --replace go.opentelemetry.io/otel=go.opentelemetry.io/otel@${OTEL_VERSION} \
    --replace github.com/go-chi/chi/v5=github.com/go-chi/chi/v5@${CHI_VERSION} \
    --replace github.com/klauspost/compress=github.com/klauspost/compress@${KL_POST_VERSION}

FROM alpine:3.23 AS crs

ARG CRS_VERSION
ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz /tmp/crs.tar.gz
RUN mkdir -p /etc/caddy/crs /data /config && \
    tar -xzf /tmp/crs.tar.gz -C /etc/caddy/crs --strip-components=1 && \
    rm /tmp/crs.tar.gz && \
    cp /etc/caddy/crs/crs-setup.conf.example /etc/caddy/crs/crs-setup.conf && \
    chown -R 65532:65532 /data /config

FROM dhi.io/caddy:2

ENV XDG_DATA_HOME=/data

COPY --from=builder /usr/bin/caddy /usr/local/bin/caddy
COPY --from=crs /etc/caddy/crs /etc/caddy/crs
COPY --from=crs /data /data
COPY --from=crs /config /config
COPY Caddyfile /etc/caddy/Caddyfile

USER 65532

EXPOSE 80 443
