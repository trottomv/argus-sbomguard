ARG CRS_VERSION=v4.30.0
ARG CADDY_VERSION=2.11.9
ARG XCADDY_VERSION=v0.4.7
ARG CORAZA_CADDY_VERSION=v1.2.2
ARG CADDY_RATELIMIT_VERSION=v0.1.0
ARG GO_VERSION=1.27.4
ARG GO_SHA256=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840

FROM dhi.io/caddy:2-debian-dev@sha256:cf2bddc2fc2f5e2bdef4983fa240308b2400462bcf9f00a2b9ef409e11c6fd27 AS builder

ARG GO_VERSION
ARG GO_SHA256
ARG CADDY_VERSION
ARG XCADDY_VERSION
ARG CORAZA_CADDY_VERSION
ARG CADDY_RATELIMIT_VERSION

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates gzip \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz \
    && echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOTOOLCHAIN=local
ENV GOBIN=/usr/local/bin

ARG GO_JOSE_VERSION=v3.0.5
ARG X_CRYPTO_VERSION=v0.59.0
ARG X_NET_VERSION=v0.62.0
ARG X_TEXT_VERSION=v0.44.0
ARG GRPC_VERSION=v1.85.0
ARG OTEL_VERSION=v1.47.0
ARG CHI_VERSION=v5.5.0
ARG KL_POST_VERSION=v1.20.4

RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}

RUN xcaddy build v${CADDY_VERSION} --output /usr/bin/caddy \
    --with github.com/corazawaf/coraza-caddy@${CORAZA_CADDY_VERSION} \
    --with github.com/mholt/caddy-ratelimit@${CADDY_RATELIMIT_VERSION} \
    --replace github.com/go-jose/go-jose/v3=github.com/go-jose/go-jose/v3@${GO_JOSE_VERSION} \
    --replace golang.org/x/crypto=golang.org/x/crypto@${X_CRYPTO_VERSION} \
    --replace golang.org/x/net=golang.org/x/net@${X_NET_VERSION} \
    --replace golang.org/x/text=golang.org/x/text@${X_TEXT_VERSION} \
    --replace google.golang.org/grpc=google.golang.org/grpc@${GRPC_VERSION} \
    --replace go.opentelemetry.io/otel=go.opentelemetry.io/otel@${OTEL_VERSION} \
    --replace github.com/go-chi/chi/v5=github.com/go-chi/chi/v5@${CHI_VERSION} \
    --replace github.com/klauspost/compress=github.com/klauspost/compress@${KL_POST_VERSION}

FROM alpine:3.23@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2 AS crs

ARG CRS_VERSION
ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz /tmp/crs.tar.gz
RUN mkdir -p /etc/caddy/crs /data /config && \
    tar -xzf /tmp/crs.tar.gz -C /etc/caddy/crs --strip-components=1 && \
    rm /tmp/crs.tar.gz && \
    cp /etc/caddy/crs/crs-setup.conf.example /etc/caddy/crs/crs-setup.conf && \
    chown -R 65532:65532 /data /config

FROM dhi.io/caddy:2@sha256:630b590767aef8c68030a991e58618680b024d56d2d838526f60ee9dbae87a7a

COPY --from=builder /usr/bin/caddy /usr/local/bin/caddy
COPY --from=crs /etc/caddy/crs /etc/caddy/crs
COPY --from=crs /data /data
COPY --from=crs /config /config
COPY Caddyfile /etc/caddy/Caddyfile

USER 65532

EXPOSE 80 443
