#!/usr/bin/env bash
# End-to-end smoke test for the Identity Facade target business flow (CLAUDE.md §33-44):
#   super-admin login → create business role → assign permissions → create scoped user
#   → verify token claims (permissions + authz.scope.*) → verify access-context.
# Requires: docker compose stack up & healthy, curl, jq.
# Usage: cd deploy && ./smoke-test.sh   (override base URLs via env: FACADE=http://localhost:5080)
set -euo pipefail

FACADE="${FACADE:-http://localhost:5080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
CLIENT_ID="identity-facade"
CLIENT_SECRET="${CLIENT_SECRET:-facade-development-only}"
ROLE_NAME="smoke-accountant-$(date +%s)"
TEST_USER="smoke-user-$(date +%s)"
TEST_PASS="Smoke#$(date +%s)!"
SCOPE_REGION="tehran-2"

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }
step() { printf '\n\033[36m== %s\033[0m\n' "$1"; }

jqb64() { # decode JWT payload: $1=token
  local payload
  payload="$(echo "$1" | cut -d. -f2)"
  local pad=$(( (4 - ${#payload} % 4) % 4 ))
  payload="${payload}$(printf '=%.0s' $(seq 1 $pad 2>/dev/null || true))"
  echo "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null
}

step "1/7 — Super-admin login (facade proxy → Keycloak)"
LOGIN=$(curl -fsS -X POST "$FACADE/api/identity/auth/login" \
  -d "grant_type=password&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&username=$ADMIN_USER&password=$ADMIN_PASS")
ADMIN_TOKEN=$(echo "$LOGIN" | jq -r .access_token)
ADMIN_REFRESH=$(echo "$LOGIN" | jq -r .refresh_token)
[ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] || fail "login did not return access_token"
# super-admins membership: admin must be able to manage roles (would 403 without identity.* perms)
pass "login OK, token issued by Keycloak"

step "2/7 — Verify super-admin management permissions in token"
PERMS=$(jqb64 "$ADMIN_TOKEN" | jq -r '(.permissions // []) | join(",")')
echo "$PERMS" | grep -q "identity.roles.manage" || fail "admin token lacks identity.roles.manage (super-admins group not effective)"
echo "$PERMS" | grep -q "identity.users.manage" || fail "admin token lacks identity.users.manage"
echo "$PERMS" | grep -q "identity.scopes.manage" || fail "admin token lacks identity.scopes.manage"
pass "admin token carries identity.{roles,users,scopes}.manage"

step "3/7 — Create business role '$ROLE_NAME' (auto-created as Keycloak group)"
CREATE_ROLE=$(curl -fsS -X POST "$FACADE/api/identity/business-roles" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"name\":\"$ROLE_NAME\",\"description\":\"Smoke test role\",\"permissions\":[]}")
echo "$CREATE_ROLE" | jq -r .name | grep -q "$ROLE_NAME" || fail "create role response mismatch"
GET_ROLE=$(curl -fsS "$FACADE/api/identity/business-roles/$ROLE_NAME" -H "Authorization: Bearer $ADMIN_TOKEN")
echo "$GET_ROLE" | jq -r .name | grep -q "$ROLE_NAME" || fail "role not readable back (group not created)"
pass "business role created and readable"

step "4/7 — Assign a registered permission to the role"
# Pick any permission registered by order-service if present; fall back to a facade permission.
PERM=$(curl -fsS "$FACADE/api/identity/permissions?serviceId=order-service" -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq -r '.[0].name // empty')
[ -n "$PERM" ] || PERM="identity.users.read"
ASSIGN=$(curl -fsS -X POST "$FACADE/api/identity/business-roles/$ROLE_NAME/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"permissions\":[\"$PERM\"]}")
echo "$ASSIGN" | jq -r '.permissions | join(",")' | grep -qF "$PERM" || fail "permission '$PERM' not present on role after assignment"
pass "permission '$PERM' assigned to role (client-role mapping)"

step "5/7 — Create user with scoped assignment (region=$SCOPE_REGION)"
CREATE_USER=$(curl -fsS -X POST "$FACADE/api/identity/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"username\":\"$TEST_USER\",\"email\":\"$TEST_USER@company.local\",\"firstName\":\"Smoke\",\"lastName\":\"User\",\"enabled\":true,
       \"credentials\":{\"password\":\"$TEST_PASS\",\"temporary\":false},
       \"assignments\":[{\"role\":\"$ROLE_NAME\",\"scopes\":{\"region\":[\"$SCOPE_REGION\"]}}]}")
USER_ID=$(echo "$CREATE_USER" | jq -r .id)
[ -n "$USER_ID" ] && [ "$USER_ID" != "null" ] || fail "user creation did not return id: $CREATE_USER"
pass "user '$TEST_USER' created (id=$USER_ID)"

step "6/7 — Login as the new user and verify token claims"
USER_LOGIN=$(curl -fsS -X POST "$FACADE/api/identity/auth/login" \
  -d "grant_type=password&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&username=$TEST_USER&password=$TEST_PASS")
USER_TOKEN=$(echo "$USER_LOGIN" | jq -r .access_token)
[ -n "$USER_TOKEN" ] && [ "$USER_TOKEN" != "null" ] || fail "user login failed: $USER_LOGIN"
PAYLOAD=$(jqb64 "$USER_TOKEN")
echo "$PAYLOAD" | jq -r '(.permissions // []) | join(",")' | grep -qF "$PERM" \
  || fail "user token missing permission '$PERM' (group role-mapping → claim failed)"
echo "$PAYLOAD" | jq -e --arg k "authz.scope.region" '(.[$k] // []) | index("'"$SCOPE_REGION"'")' >/dev/null \
  || { echo "--- token payload ---"; echo "$PAYLOAD" | jq .; fail "user token missing authz.scope.region=$SCOPE_REGION"; }
pass "user token carries '$PERM' and authz.scope.region=$SCOPE_REGION"

step "7/7 — Access-context + scoped-access via facade"
CTX=$(curl -fsS "$FACADE/api/identity/access-context" -H "Authorization: Bearer $USER_TOKEN")
echo "$CTX" | jq -r '.permissions | join(",")' | grep -qF "$PERM" || fail "access-context missing permission"
SCOPED=$(curl -fsS "$FACADE/api/identity/users/$USER_ID/scoped-access" -H "Authorization: Bearer $ADMIN_TOKEN")
echo "$SCOPED" | jq -r '.assignments[].scopes.region[]' | grep -qx "$SCOPE_REGION" || fail "scoped-access missing region value"
pass "access-context and scoped-access consistent with token"

printf '\n\033[32mAll 7 steps passed.\033[0m Role=%s User=%s Region=%s\n' "$ROLE_NAME" "$TEST_USER" "$SCOPE_REGION"
printf 'Cleanup hint: DELETE %s/api/identity/business-roles/%s and remove user %s via Keycloak console.\n' "$FACADE" "$ROLE_NAME" "$TEST_USER"
