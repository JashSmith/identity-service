#!/usr/bin/env python3
"""Generates the Postman collection and environment from the gateway's OpenAPI document.

    python scripts/generate-postman.py                         # reads http://localhost:5080/openapi/v1.json
    python scripts/generate-postman.py --openapi openapi.json   # or a saved document

The collection has one folder per API tag, a "Sign in" request that stores the access token, bearer auth on every
request and an optional X-Tenant-Id header. Rerun it whenever endpoints change; do not edit the JSON by hand.
"""
import argparse
import json
import pathlib
import re
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "postman"


def load(source: str) -> dict:
    if source.startswith("http"):
        with urllib.request.urlopen(source, timeout=30) as response:  # noqa: S310 (local dev URL)
            return json.load(response)
    return json.loads(pathlib.Path(source).read_text(encoding="utf-8"))


def example(schema: dict, spec: dict, depth: int = 0):
    """A small example value for a JSON schema (enough to show the shape of a request body)."""
    if depth > 4 or not schema:
        return None
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        return example(spec.get("components", {}).get("schemas", {}).get(name, {}), spec, depth + 1)
    for key in ("oneOf", "anyOf", "allOf"):
        if key in schema:
            options = [s for s in schema[key] if s.get("type") != "null"]
            return example(options[0], spec, depth + 1) if options else None
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), None)
    if kind == "object" or "properties" in schema:
        return {k: example(v, spec, depth + 1) for k, v in schema.get("properties", {}).items()}
    if kind == "array":
        item = example(schema.get("items", {}), spec, depth + 1)
        return [] if item is None else [item]
    if kind == "boolean":
        return False
    if kind in ("integer", "number"):
        return 0
    if kind == "string":
        return {"date": "2026-01-01", "date-time": "2026-01-01T00:00:00Z"}.get(schema.get("format"), "")
    return None


def request_item(path: str, method: str, operation: dict, spec: dict) -> dict:
    segments = [re.sub(r"\{([^}]+)\}", r":\1", s) for s in path.strip("/").split("/")]
    variables = [{"key": p["name"], "value": ""} for p in operation.get("parameters", []) if p.get("in") == "path"]
    query = [{"key": p["name"], "value": "", "disabled": True} for p in operation.get("parameters", []) if p.get("in") == "query"]
    request = {
        "method": method.upper(),
        "header": [{"key": "X-Tenant-Id", "value": "{{tenant}}", "disabled": True,
                    "description": "Only for a non-default tenant (organisation)."}],
        "url": {"raw": "{{gateway}}/" + "/".join(segments), "host": ["{{gateway}}"], "path": segments,
                "variable": variables, "query": query},
    }
    body = operation.get("requestBody", {}).get("content", {})
    if "application/json" in body:
        request["header"].append({"key": "Content-Type", "value": "application/json"})
        request["body"] = {"mode": "raw", "raw": json.dumps(example(body["application/json"].get("schema", {}), spec),
                                                            ensure_ascii=False, indent=2)}
    elif "application/x-www-form-urlencoded" in body:
        request["body"] = {"mode": "urlencoded", "urlencoded": []}
    return {"name": operation.get("operationId") or f"{method.upper()} {path}", "request": request}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--openapi", default="http://localhost:5080/openapi/v1.json")
    spec = load(parser.parse_args().openapi)

    folders: dict[str, list] = {}
    for path, operations in sorted(spec.get("paths", {}).items()):
        for method, operation in operations.items():
            if method not in ("get", "post", "put", "delete", "patch"):
                continue
            tag = (operation.get("tags") or ["Other"])[0]
            folders.setdefault(tag, []).append(request_item(path, method, operation, spec))

    sign_in = {
        "name": "Sign in (stores the token)",
        "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": [
            "const body = pm.response.json();",
            "if (body.access_token) pm.environment.set('token', body.access_token);",
        ]}}],
        "request": {
            "method": "POST",
            "auth": {"type": "noauth"},
            "header": [{"key": "X-Tenant-Id", "value": "{{tenant}}", "disabled": True}],
            "body": {"mode": "urlencoded", "urlencoded": [
                {"key": "grant_type", "value": "password"},
                {"key": "username", "value": "{{username}}"},
                {"key": "password", "value": "{{password}}"},
            ]},
            "url": {"raw": "{{gateway}}/api/identity/auth/login", "host": ["{{gateway}}"], "path": ["api", "identity", "auth", "login"]},
        },
    }
    collection = {
        "info": {
            "name": "Identity Gateway",
            "description": "Generated from the gateway's OpenAPI document by scripts/generate-postman.py. Run \"Sign in\" first.",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}", "type": "string"}]},
        "item": [{"name": "Start here", "item": [sign_in]}] +
                [{"name": tag, "item": items} for tag, items in sorted(folders.items())],
    }
    environment = {
        "name": "Identity Gateway (local)",
        "values": [
            {"key": "gateway", "value": "http://localhost:5080", "enabled": True},
            {"key": "tenant", "value": "avash", "enabled": True},
            {"key": "username", "value": "admin", "enabled": True},
            {"key": "password", "value": "admin", "enabled": True, "type": "secret"},
            {"key": "token", "value": "", "enabled": True, "type": "secret"},
        ],
    }
    OUT.mkdir(exist_ok=True)
    for old in OUT.glob("*.json"):
        old.unlink()
    (OUT / "Identity Gateway.postman_collection.json").write_text(json.dumps(collection, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT / "Identity Gateway.postman_environment.json").write_text(json.dumps(environment, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{sum(len(v) for v in folders.values())} requests in {len(folders)} folders")


if __name__ == "__main__":
    main()
