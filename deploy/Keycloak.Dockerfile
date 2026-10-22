# Multi-database Keycloak image supporting PostgreSQL, SQL Server (MSSQL), and Oracle.
# PostgreSQL and MSSQL JDBC drivers are bundled in the official Keycloak image.
# Oracle JDBC driver (ojdbc11) is added to providers so Oracle is supported when selected.
ARG KEYCLOAK_VERSION=26.4
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS driver-fetcher
ADD --chmod=0444 https://repo1.maven.org/maven2/com/oracle/database/jdbc/ojdbc11/21.9.0.0/ojdbc11-21.9.0.0.jar /tmp/ojdbc11.jar

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}
COPY --from=driver-fetcher /tmp/ojdbc11.jar /opt/keycloak/providers/ojdbc11.jar
COPY --chmod=0755 deploy/keycloak-entrypoint.sh /opt/keycloak/bin/keycloak-entrypoint.sh

ENTRYPOINT ["/opt/keycloak/bin/keycloak-entrypoint.sh"]
