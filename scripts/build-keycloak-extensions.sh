#!/usr/bin/env bash
# Builds the Keycloak extensions (keycloak/extensions) in a Maven container, runs their tests and copies the jar
# to src/Identity.AppHost/Keycloak/Providers, which the AppHost mounts into Keycloak's providers folder.
# Needs only Docker. Restart the stack afterwards so Keycloak loads the new jar.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
# Docker on Windows needs a Windows path for the bind mount; Git Bash must not rewrite it.
if command -v cygpath >/dev/null 2>&1; then src="$(cygpath -w "$root/keycloak/extensions")"; else src="$root/keycloak/extensions"; fi

MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$src:/build" \
  -v avash-keycloak-maven:/root/.m2 \
  -w /build \
  maven:3.9-eclipse-temurin-21 \
  mvn -B -q package

mkdir -p "$root/src/Identity.AppHost/Keycloak/Providers"
cp "$root/keycloak/extensions/target/avash-keycloak-extensions.jar" "$root/src/Identity.AppHost/Keycloak/Providers/"
echo "Built src/Identity.AppHost/Keycloak/Providers/avash-keycloak-extensions.jar"
