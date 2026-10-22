#!/bin/sh
set -e

# ==============================================================================
# Keycloak Multi-Database Entrypoint
# Dynamically configures Keycloak for PostgreSQL, SQL Server (MSSQL), or Oracle
# based on DB_PROVIDER or KC_DB.
# ==============================================================================

PROVIDER="${DB_PROVIDER:-${KC_DB:-postgres}}"
PROVIDER=$(echo "$PROVIDER" | tr '[:upper:]' '[:lower:]')

case "$PROVIDER" in
  mssql|sqlserver)
    echo ">> [Keycloak Entrypoint] Configuring for Microsoft SQL Server (MSSQL)..."
    export KC_DB="mssql"
    export KC_DB_URL="${KC_DB_URL:-jdbc:sqlserver://${DB_HOST:-mssql-db}:${DB_PORT:-1433};databaseName=${DB_NAME:-keycloak};trustServerCertificate=true}"
    export KC_DB_USERNAME="${KC_DB_USERNAME:-sa}"
    export KC_DB_PASSWORD="${KC_DB_PASSWORD:-SqlPassword123!Safe}"
    ;;
  oracle)
    echo ">> [Keycloak Entrypoint] Configuring for Oracle Database..."
    export KC_DB="oracle"
    export KC_DB_URL="${KC_DB_URL:-jdbc:oracle:thin:@${DB_HOST:-oracle-db}:${DB_PORT:-1521}/${DB_NAME:-XEPDB1}}"
    export KC_DB_USERNAME="${KC_DB_USERNAME:-keycloak}"
    export KC_DB_PASSWORD="${KC_DB_PASSWORD:-keycloak-development-only}"
    ;;
  postgres|postgresql|*)
    echo ">> [Keycloak Entrypoint] Configuring for PostgreSQL (default)..."
    export KC_DB="postgres"
    export KC_DB_URL="${KC_DB_URL:-jdbc:postgresql://${DB_HOST:-postgres-db}:${DB_PORT:-5432}/${DB_NAME:-keycloak}}"
    export KC_DB_USERNAME="${KC_DB_USERNAME:-keycloak}"
    export KC_DB_PASSWORD="${KC_DB_PASSWORD:-keycloak-development-only}"
    ;;
esac

echo ">> [Keycloak Entrypoint] Active KC_DB: $KC_DB"
echo ">> [Keycloak Entrypoint] Active KC_DB_URL: $KC_DB_URL"
echo ">> [Keycloak Entrypoint] Active KC_DB_USERNAME: $KC_DB_USERNAME"

# Execute Keycloak with arguments passed (e.g. start-dev --http-port=8080 --import-realm)
exec /opt/keycloak/bin/kc.sh "$@"
