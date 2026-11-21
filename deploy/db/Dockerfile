# PostgreSQL 17 with pg_tde (Percona Distribution for PostgreSQL, open source).
# The image exists for linux/amd64 and linux/arm64.
FROM percona/percona-distribution-postgresql:17

USER root
# The principal keys of pg_tde live outside the data directory, on their own volume.
RUN mkdir -p /tde-keys && chown 26:26 /tde-keys && chmod 700 /tde-keys
COPY --chown=26:26 initdb/ /docker-entrypoint-initdb.d/
USER 26
VOLUME ["/tde-keys"]

# pg_tde must be loaded at server start.
CMD ["postgres", "-c", "shared_preload_libraries=pg_tde"]
