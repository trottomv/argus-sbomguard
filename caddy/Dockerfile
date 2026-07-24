ARG CADDY_VERSION=2.11.3
ARG CRS_VERSION=v4.4.0

FROM caddy:${CADDY_VERSION}-builder AS builder

RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy \
    --replace github.com/go-jose/go-jose/v3=github.com/go-jose/go-jose/v3@v3.0.5

FROM caddy:${CADDY_VERSION}

ARG CRS_VERSION
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz /tmp/crs.tar.gz
RUN mkdir -p /etc/caddy/crs && \
    tar -xzf /tmp/crs.tar.gz -C /etc/caddy/crs --strip-components=1 && \
    rm /tmp/crs.tar.gz && \
    cp /etc/caddy/crs/crs-setup.conf.example /etc/caddy/crs/crs-setup.conf

COPY Caddyfile /etc/caddy/Caddyfile
