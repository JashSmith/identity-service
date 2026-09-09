# Keycloak with Oracle JDBC driver (ojdbc11). Stock quay.io/keycloak images do not bundle it.
ARG KEYCLOAK_VERSION=26.4
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS builder
# Quarkus augmentation needs the driver at build time.
ADD --chmod=0444 https://repo1.maven.org/maven2/com/oracle/database/jdbc/ojdbc11/23.26.3.0.0/ojdbc11-23.26.3.0.0.jar /opt/keycloak/providers/ojdbc11.jar
RUN /opt/keycloak/bin/kc.sh build --db=oracle --health-enabled=true --metrics-enabled=true

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}
COPY --from=builder /opt/keycloak /opt/keycloak
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
