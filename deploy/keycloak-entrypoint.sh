#!/bin/sh
set -e

# ==============================================================================
# Keycloak Multi-Database Entrypoint
# Dynamically configures Keycloak for PostgreSQL, SQL Server (MSSQL), or Oracle
# based on DB_PROVIDER or KC_DB.
# ==============================================================================

PROVIDER="${DB_PROVIDER:-${KC_DB:-postgres}}"
PROVIDER=$(echo "$PROVIDER" | tr '[:upper:]' '[:lower:]')
SHARED_PASSWORD="${DB_PASSWORD:-KeycloakDev#2026!}"

case "$PROVIDER" in
  mssql|sqlserver)
    echo ">> [Keycloak Entrypoint] Configuring for Microsoft SQL Server (MSSQL)..."
    export KC_DB="mssql"
    export KC_DB_URL="${KC_DB_URL:-jdbc:sqlserver://${DB_HOST:-mssql-db}:${DB_PORT:-1433};databaseName=${DB_NAME:-keycloak};trustServerCertificate=true}"
    export KC_DB_USERNAME="${KC_DB_USERNAME:-sa}"
    export KC_DB_PASSWORD="${KC_DB_PASSWORD:-$SHARED_PASSWORD}"
    ;;
  oracle)
    echo ">> [Keycloak Entrypoint] Configuring for Oracle Database..."
    export KC_DB="oracle"
    export KC_DB_URL="${KC_DB_URL:-jdbc:oracle:thin:@${DB_HOST:-oracle-db}:${DB_PORT:-1521}/${DB_NAME:-XEPDB1}}"
    export KC_DB_USERNAME="${KC_DB_USERNAME:-keycloak}"
    export KC_DB_PASSWORD="${KC_DB_PASSWORD:-$SHARED_PASSWORD}"
    ;;
  postgres|postgresql|*)
    echo ">> [Keycloak Entrypoint] Configuring for PostgreSQL (default)..."
    export KC_DB="postgres"
    export KC_DB_URL="${KC_DB_URL:-jdbc:postgresql://${DB_HOST:-postgres-db}:${DB_PORT:-5432}/${DB_NAME:-keycloak}}"
    export KC_DB_USERNAME="${KC_DB_USERNAME:-keycloak}"
    export KC_DB_PASSWORD="${KC_DB_PASSWORD:-$SHARED_PASSWORD}"
    ;;
esac

echo ">> [Keycloak Entrypoint] Active Database Engine: $KC_DB"
echo ">> [Keycloak Entrypoint] JDBC Connection URL: $KC_DB_URL"
echo ">> [Keycloak Entrypoint] Database Username: $KC_DB_USERNAME"

if [ -f "/opt/keycloak/bin/kc.sh" ]; then
  exec /opt/keycloak/bin/kc.sh "$@"
else
  echo ">> [Keycloak Entrypoint] Local Host Check: /opt/keycloak/bin/kc.sh was not found."
  echo ">> [Keycloak Entrypoint] This entrypoint script is designed to run inside the Keycloak container."
  echo ">> [Keycloak Entrypoint] Variables configured successfully for $KC_DB."
fi
