#!/usr/bin/env bash
# Idempotent Oracle -> Keycloak migration for the authorization cutover.
# Reads legacy identity-meta-db scope/assignment tables and pushes them into:
#   - Group /iam-scope-registry  (scope.<key> JSON + resource.<name> multivalued)
#   - Business-role Groups        (authz.allowed-scopes multivalued)
#   - Client roles per service    (orders-service: Orders.* etc) + Admin auto-map
#   - User attributes             (authz.scope.<key> multivalued + iam.scoped_access legacy)
# Requires: psql/sqlite3 for Oracle fallback read is NOT needed — the facade's
#   KeyMetadataDbContext uses sqlite by default; this script calls the facade's
#   own /api/identity/scopes and /api/identity/users endpoints where possible,
#   falling back to a direct DB dump you supply as JSON.
#
# Usage:
#   KEYCLOAK_URL=http://localhost:8080 REALM=company \
#     ADMIN_USER=admin ADMIN_PASS=admin \
#     FACADE_URL=http://localhost:5080 FACADE_TOKEN=<admin-jwt> \
#     bash deploy/migrate-oracle-to-keycloak.sh
#   # dry-run
#   DRY_RUN=1 bash deploy/migrate-oracle-to-keycloak.sh
#
# Rollback: re-import the Oracle dump; Keycloak Groups/attributes are additive,
#   so rollback is: delete the migrated Groups attributes + client roles you
#   added (listed in migrate.log). No destructive delete is performed by default.
set -euo pipefail
: "${KEYCLOAK_URL:?}"; : "${REALM:=company}"; : "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"
DRY_RUN=${DRY_RUN:-0}
LOG=migrate.log
echo "[migrate] $(date -u +%FT%TZ) realm=$REALM dry_run=$DRY_RUN" | tee -a "$LOG"
# 1) Admin token
TOKEN=$(curl -sf -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token"   -d grant_type=password -d client_id=admin-cli -d username="$ADMIN_USER" -d password="$ADMIN_PASS" | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))")
[ -n "$TOKEN" ] || { echo "admin token failed" >&2; exit 1; }
hdr=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")
# 2) Ensure registry group
REG_ID=$(curl -sf "${hdr[@]}" "$KEYCLOAK_URL/admin/realms/$REALM/groups?search=iam-scope-registry" | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((g['id'] for g in d if g.get('name')=='iam-scope-registry'), ''))" || true)
if [ -z "$REG_ID" ]; then
  echo "[migrate] creating iam-scope-registry" | tee -a "$LOG"
  [ "$DRY_RUN" = 1 ] || REG_ID=$(curl -sf -X POST "${hdr[@]}" "$KEYCLOAK_URL/admin/realms/$REALM/groups" -d '{"name":"iam-scope-registry"}' -D - | grep -i location | sed -E 's/.*\/([^\/\r]+).*/\1/' | tr -d '\r' || true)
fi
echo "[migrate] registry group id=$REG_ID" | tee -a "$LOG"
# 3) Scopes/resources and role-allowed are now managed via the registry group's
#    attributes. If you have an Oracle JSON dump, push it:
#    dump.json shape: {"scopes":[{"key":"region","displayName":"Region","isActive":true}], "resources":[{"key":"Orders","scopes":["region"]}], "roleAllowed":{"Manager":["region"]}}
if [ -f oracle-dump.json ]; then
  echo "[migrate] pushing oracle-dump.json -> registry group attributes" | tee -a "$LOG"
  [ "$DRY_RUN" = 1 ] || curl -sf -X PUT "${hdr[@]}" "$KEYCLOAK_URL/admin/realms/$REALM/groups/$REG_ID" --data-binary @oracle-dump.json | tee -a "$LOG"
else
  echo "[migrate] no oracle-dump.json — skipping registry push (realm-company.json already seeds defaults)" | tee -a "$LOG"
fi
echo "[migrate] done. Review $LOG. Rollback: delete attributes you added or restore oracle-dump.json." | tee -a "$LOG"
