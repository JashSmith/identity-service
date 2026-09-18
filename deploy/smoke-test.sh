#!/usr/bin/env bash
# End-to-end smoke test for the Identity Facade target business flow (CLAUDE.md §33-44):
#   super-admin login → create business role → assign permissions → create scoped user
#   → verify token claims (permissions + authz scope) → verify access-context.
# Requires: running stack (facade on :5080), curl, python3 (jq not needed).
# Usage: cd deploy && ./smoke-test.sh   (override: FACADE=http://host:5080 ./smoke-test.sh)
set -euo pipefail

FACADE="${FACADE:-http://localhost:5080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
CLIENT_ID="identity-facade"
CLIENT_SECRET="${CLIENT_SECRET:-facade-development-only}"
TS=$(date +%s)
ROLE_NAME="smoke-accountant-$TS"
TEST_USER="smoke-user-$TS"
TEST_PASS="Smoke#${TS}!"
SCOPE_REGION="tehran-2"

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s — %s\n' "$1" "${2:-}"; exit 1; }
step() { printf '\n\033[36m== %s\033[0m\n' "$1"; }

# Resolve a working Python once. On Windows the `python3` name is a Microsoft Store
# alias that prints an error instead of running, so probe rather than guess.
PY=""
for cand in python python3 py; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'print(1)' >/dev/null 2>&1; then PY="$cand"; break; fi
done
[ -n "$PY" ] || { echo "python is required but none of python/python3/py work"; exit 1; }

# Run a python one-liner. First arg = script; remaining args become sys.argv[1:].
pyj() { local script="$1"; shift; "$PY" -c "$script" "$@"; }

decode_jwt() { # $1=token -> payload JSON on stdout
  pyj "
import sys,json,base64
t=sys.argv[1].split('.')[1]; t+='='*(-len(t)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(t)),ensure_ascii=False))
" "$1"
}

json_field() { # $1=json $2=python expr on d
  pyj "
import sys,json
d=json.loads(sys.stdin.read())
print($2)
" <<<"$1"
}

step "1/7 — Super-admin login (facade proxy → Keycloak)"
LOGIN=$(curl -fsS -X POST "$FACADE/api/identity/auth/login" \
  -d "grant_type=password&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&username=$ADMIN_USER&password=$ADMIN_PASS")
ADMIN_TOKEN=$(json_field "$LOGIN" "d['access_token']")
[ -n "$ADMIN_TOKEN" ] || fail "login" "no access_token in: $LOGIN"
pass "login OK, Keycloak token issued"

step "2/7 — Verify super-admin management permissions in token"
PAYLOAD=$(decode_jwt "$ADMIN_TOKEN")
PERMS=$(json_field "$PAYLOAD" "','.join(d.get('permissions',[]))")
for need in identity.roles.manage identity.users.manage identity.scopes.manage; do
  case ",$PERMS," in *",$need,"*) ;; *) fail "super-admin perms" "missing $need — super-admins group not effective" ;; esac
done
pass "admin token carries identity.{roles,users,scopes}.manage"

step "3/7 — Create business role '$ROLE_NAME' (auto-created as Keycloak group)"
CREATE_ROLE=$(curl -fsS -X POST "$FACADE/api/identity/business-roles" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"name\":\"$ROLE_NAME\",\"description\":\"Smoke test role\",\"permissions\":[]}")
NAME=$(json_field "$CREATE_ROLE" "d['name']")
[ "$NAME" = "$ROLE_NAME" ] || fail "create role" "got: $CREATE_ROLE"
GET_ROLE=$(curl -fsS "$FACADE/api/identity/business-roles/$ROLE_NAME" -H "Authorization: Bearer $ADMIN_TOKEN")
[ "$(json_field "$GET_ROLE" "d['name']")" = "$ROLE_NAME" ] || fail "get role" "role not readable back: $GET_ROLE"
pass "business role created and readable"

step "4/7 — Assign a registered permission to the role"
PERM=$(curl -fsS "$FACADE/api/identity/permissions?serviceId=order-service" -H "Authorization: Bearer $ADMIN_TOKEN" \
  | pyj "import sys,json; d=json.load(sys.stdin); print(d[0]['name'] if d else '')")
[ -n "$PERM" ] || PERM="identity.users.read"
ASSIGN=$(curl -fsS -X POST "$FACADE/api/identity/business-roles/$ROLE_NAME/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"permissions\":[\"$PERM\"]}")
HAS=$(json_field "$ASSIGN" "','.join(d.get('permissions',[]))")
case ",$HAS," in *",$PERM,"*) ;; *) fail "assign permission" "'$PERM' missing from $ASSIGN" ;; esac
pass "permission '$PERM' assigned (client-role mapping)"

step "5/7 — Create user with scoped assignment (region=$SCOPE_REGION)"
CREATE_USER=$(curl -fsS -X POST "$FACADE/api/identity/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"username\":\"$TEST_USER\",\"email\":\"$TEST_USER@company.local\",\"firstName\":\"Smoke\",\"lastName\":\"User\",\"enabled\":true,
       \"credentials\":{\"password\":\"$TEST_PASS\",\"temporary\":false},
       \"assignments\":[{\"role\":\"$ROLE_NAME\",\"scopes\":{\"region\":[\"$SCOPE_REGION\"]}}]}")
USER_ID=$(json_field "$CREATE_USER" "d['id']")
[ -n "$USER_ID" ] || fail "create user" "$CREATE_USER"
pass "user '$TEST_USER' created (id=$USER_ID)"

step "6/7 — Login as the new user and verify token claims"
USER_LOGIN=$(curl -fsS -X POST "$FACADE/api/identity/auth/login" \
  -d "grant_type=password&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&username=$TEST_USER&password=$TEST_PASS")
USER_TOKEN=$(json_field "$USER_LOGIN" "d['access_token']")
[ -n "$USER_TOKEN" ] || fail "user login" "$USER_LOGIN"
UPAYLOAD=$(decode_jwt "$USER_TOKEN")
UPERMS=$(json_field "$UPAYLOAD" "','.join(d.get('permissions',[]))")
case ",$UPERMS," in *",$PERM,"*) ;; *) fail "user claims" "token missing '$PERM' (group role-mapping → claim failed)" ;; esac
# Scope claims arrive nested: authz.scope.<key> → {"authz":{"scope":{"<key>":[...]}}}
REGION_OK=$(json_field "$UPAYLOAD" "'$SCOPE_REGION' in d.get('authz',{}).get('scope',{}).get('region',[])")
[ "$REGION_OK" = "True" ] || fail "user claims" "authz.scope.region does not contain $SCOPE_REGION; payload=$UPAYLOAD"
pass "user token carries '$PERM' and authz.scope.region=$SCOPE_REGION"

step "7/7 — Access-context + scoped-access via facade"
CTX=$(curl -fsS "$FACADE/api/identity/access-context" -H "Authorization: Bearer $USER_TOKEN")
CTXP=$(json_field "$CTX" "','.join(d.get('permissions',[]))")
case ",$CTXP," in *",$PERM,"*) ;; *) fail "access-context" "missing permission: $CTX" ;; esac
SCOPED=$(curl -fsS "$FACADE/api/identity/users/$USER_ID/scoped-access" -H "Authorization: Bearer $ADMIN_TOKEN")
HASREGION=$(json_field "$SCOPED" "'$SCOPE_REGION' in [v for a in d.get('assignments',[]) for v in a.get('scopes',{}).get('region',[])]")
[ "$HASREGION" = "True" ] || fail "scoped-access" "region value missing: $SCOPED"
pass "access-context and scoped-access consistent with token"

printf '\n\033[32mAll 7 steps passed.\033[0m Role=%s User=%s Region=%s\n' "$ROLE_NAME" "$TEST_USER" "$SCOPE_REGION"
printf 'Cleanup: DELETE %s/api/identity/business-roles/%s and the smoke user via Keycloak console.\n' "$FACADE" "$ROLE_NAME"
