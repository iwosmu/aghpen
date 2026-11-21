#!/bin/bash
# Runs once, when the data directory is created.
# Enables pg_tde, creates a key provider and the principal keys, and turns on
# WAL encryption. After this script every database of the cluster can create
# tde_heap tables; Czujka creates all its tables with that access method.
set -euo pipefail

KEYRING="${CZUJKA_TDE_KEYRING:-/tde-keys/czujka-keyring.per}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname template1 <<SQL
CREATE EXTENSION IF NOT EXISTS pg_tde;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "${POSTGRES_DB:-postgres}" <<SQL
CREATE EXTENSION IF NOT EXISTS pg_tde;
-- Key provider: a keyring file on a volume of its own (not the data volume).
-- For production replace it with pg_tde_add_global_key_provider_vault_v2 or _kmip.
SELECT pg_tde_add_global_key_provider_file('czujka-keyring', '${KEYRING}');
-- Principal key for table data: the default key of every database of the cluster.
SELECT pg_tde_create_key_using_global_key_provider('czujka-principal-key', 'czujka-keyring');
SELECT pg_tde_set_default_key_using_global_key_provider('czujka-principal-key', 'czujka-keyring');
-- Server key for the write-ahead log.
SELECT pg_tde_create_key_using_global_key_provider('czujka-server-key', 'czujka-keyring');
SELECT pg_tde_set_server_key_using_global_key_provider('czujka-server-key', 'czujka-keyring');
ALTER SYSTEM SET pg_tde.wal_encrypt = on;
-- New tables are encrypted even when a statement names no access method.
ALTER SYSTEM SET default_table_access_method = 'tde_heap';
SQL
