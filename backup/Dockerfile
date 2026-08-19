# Backup/restore tooling image. The hardened postgres image ships pg_dump, psql
# and gzip but no package manager; openssl is copied from a toolchain stage (the
# libcrypto/libssl it needs are already present in the postgres base). The pure
# backup/restore scripts are baked in and get the database connection and
# BACKUP_* settings from the environment (compose service or k8s manifest).
FROM dhi.io/python:3.13-alpine-dev AS tools

FROM dhi.io/postgres:18-alpine3.23

COPY --from=tools /usr/bin/openssl /usr/bin/openssl

COPY scripts/backup.sh scripts/restore.sh /usr/local/bin/

# Tools container only — never start a postgres server here.
ENTRYPOINT ["/bin/sh"]
