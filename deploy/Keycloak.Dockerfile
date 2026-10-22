# ==============================================================================
# Multi-Database Keycloak Container
# Supports: PostgreSQL, Microsoft SQL Server (MSSQL), and Oracle Database
# ==============================================================================
ARG KEYCLOAK_VERSION=26.4

# Stage 1: Fetch Oracle JDBC Driver
# Note: PostgreSQL (org.postgresql) and MSSQL (com.microsoft.sqlserver) JDBC drivers
# are already bundled inside official Keycloak images. Oracle driver (ojdbc11) is added
# to /opt/keycloak/providers to enable complete Oracle Database XE / Free support.
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS driver-fetcher
ADD --chmod=0444 https://repo1.maven.org/maven2/com/oracle/database/jdbc/ojdbc11/21.9.0.0/ojdbc11-21.9.0.0.jar /tmp/ojdbc11.jar

# Stage 2: Quarkus Augmentation & Pre-Build
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS builder

# Configurable database target: postgres | mssql | oracle (default: postgres)
ARG DB_VENDOR=postgres
ENV KC_DB=${DB_VENDOR}
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Copy Oracle JDBC driver into providers directory
COPY --from=driver-fetcher /tmp/ojdbc11.jar /opt/keycloak/providers/ojdbc11.jar

# Pre-build Quarkus runtime optimized for the selected database engine
RUN /opt/keycloak/bin/kc.sh build

# Stage 3: Runtime Container
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}

# Copy optimized build artifacts and all providers
COPY --from=builder /opt/keycloak/ /opt/keycloak/
COPY --chmod=0755 deploy/keycloak-entrypoint.sh /opt/keycloak/bin/keycloak-entrypoint.sh

# Entrypoint dynamically resolves connection string for PostgreSQL, MSSQL, or Oracle
ENTRYPOINT ["/opt/keycloak/bin/keycloak-entrypoint.sh"]
