# Backup/restore tooling image. The hardened postgres image ships pg_dump, psql
# and gzip but no package manager; openssl is copied from a toolchain stage (the
# libcrypto/libssl it needs are already present in the postgres base). The pure
# backup/restore scripts are baked in and get the database connection and
# BACKUP_* settings from the environment (compose service or k8s manifest).
FROM dhi.io/python:3.15-alpine-dev@sha256:0bb115e0b8c9d3e6856915aa45eb3108245dcc15c3b103e7b19ee703278376f1 AS tools

FROM dhi.io/postgres:18-alpine3.23@sha256:70de64b3f54f1c497267c5520b26c93e25de1dd4e67113557a87c222b6211783

COPY --from=tools /usr/bin/openssl /usr/bin/openssl

COPY scripts/backup.sh scripts/restore.sh /usr/local/bin/

# Tools container only — never start a postgres server here.
ENTRYPOINT ["/bin/sh"]
