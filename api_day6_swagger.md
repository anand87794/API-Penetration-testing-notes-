# OpenAPI/Swagger Security: How Specs Expose Your API

> **Series:** 30-Day API Pentesting  
> **Day:** 6 — Week 1: API Fundamentals & Recon  
> **Topic:** Swagger/OpenAPI Spec — What It Reveals to Hackers

---

## What Is Swagger / OpenAPI?

OpenAPI (formerly Swagger) is a standard specification format that documents every API endpoint — routes, methods, parameters, auth requirements, and response schemas. When left exposed in production, it hands attackers a complete blueprint of the entire API.

**Key insight:** Finding swagger.json = instant recon. No guessing. No brute force. Every endpoint, every parameter, every auth requirement — all in one JSON file.

---

## 01 · Finding the Swagger Endpoint

```bash
# Common paths — check ALL of these on every target
for path in \
  swagger swagger.json swagger.yaml swagger.yml \
  swagger-ui swagger-ui.html swagger-ui/index.html \
  api-docs api-docs.json \
  openapi.json openapi.yaml openapi.yml \
  v1/docs v2/docs v3/docs \
  api/v1/docs api/v2/docs \
  docs redoc \
  graphql graphiql playground \
  .well-known/openid-configuration \
  .well-known/jwks.json; do
    code=$(curl -s -o /dev/null -w "%{http_code}" https://target.com/$path)
    [ "$code" = "200" ] && echo "FOUND: /$path [$code]"
done

# ffuf — fuzz for swagger paths
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/swagger-wordlist.txt \
  -mc 200 -o swagger_found.json

# Check on all subdomains
cat live_subs.txt | while read url; do
  code=$(curl -s -o /dev/null -w "%{http_code}" $url/swagger.json)
  [ "$code" = "200" ] && echo "SWAGGER: $url/swagger.json"
done
```

---

## 02 · What Swagger Reveals to Hackers

```yaml
# Example swagger.json reveals:

paths:
  /api/v1/admin/users:        # ← ADMIN endpoint exposed
    get:
      security: []            # ← NO auth required!
      parameters:
        - name: role
          in: query           # ← injectable parameter

  /api/v1/internal/export:   # ← INTERNAL endpoint
    post:
      deprecated: true        # ← forgotten, less maintained
      x-internal: true        # ← dev-only, probably unprotected

  /api/v1/users/{id}:
    get:
      parameters:
        - name: id
          in: path            # ← IDOR candidate
```

```bash
# Parse swagger.json for unauthenticated endpoints
curl -s https://target.com/swagger.json | \
  python3 -c "
import json,sys
spec = json.load(sys.stdin)
for path, methods in spec.get('paths', {}).items():
    for method, details in methods.items():
        sec = details.get('security', ['REQUIRED'])
        if sec == []:
            print(f'NO AUTH: {method.upper()} {path}')
"

# Extract ALL endpoints
curl -s https://target.com/swagger.json | \
  python3 -c "
import json,sys
spec = json.load(sys.stdin)
for path in spec.get('paths', {}).keys():
    print(path)
" | sort -u

# Find deprecated endpoints
curl -s https://target.com/swagger.json | \
  python3 -c "
import json,sys
spec = json.load(sys.stdin)
for path, methods in spec.get('paths', {}).items():
    for method, details in methods.items():
        if details.get('deprecated', False):
            print(f'DEPRECATED: {method.upper()} {path}')
"
```

---

## 03 · Importing Swagger into Burp / Postman

```bash
# Postman — import entire API spec as collection
# 1. Postman → Import → Link
# 2. Paste: https://target.com/swagger.json
# 3. Import → entire collection created with all endpoints
# 4. Set environment: base_url + token
# 5. Collection Runner → test ALL endpoints for auth issues

# Burp Suite — OpenAPI Parser extension
# 1. Extensions → BApp Store → "OpenAPI Parser" → Install
# 2. OpenAPI → Parse → paste URL or JSON
# 3. All endpoints added to Site Map automatically
# 4. Send to Scanner → active scan all endpoints
# 5. Send to Intruder → fuzz all parameters

# Command line — generate curl commands from spec
npm install -g @openapitools/openapi-generator-cli
openapi-generator-cli generate -i swagger.json -g bash -o ./api-tests/
# Creates bash scripts for every endpoint
```

---

## 04 · Hunting Hidden & Deprecated Endpoints

```bash
# Deprecated endpoints = old code = less security attention
curl -s https://target.com/swagger.json | grep -A5 '"deprecated": true'

# x-internal endpoints = developer-only, likely no auth
curl -s https://target.com/swagger.json | grep -B2 '"x-internal"'

# Version differences — what's in v1 that's not in v2?
diff <(curl -s target.com/v1/swagger.json | python3 -c "
import json,sys; [print(p) for p in json.load(sys.stdin)['paths']]
") <(curl -s target.com/v2/swagger.json | python3 -c "
import json,sys; [print(p) for p in json.load(sys.stdin)['paths']]
")
# Endpoints only in v1 = potentially forgotten, less protected

# Debug/internal endpoints to look for in spec:
# /debug /actuator /healthz /metrics /admin /internal
# /export /backup /dump /migrate /seed /reset
```

---

## 05 · Swagger UI Exploitation

```bash
# Swagger UI left in production = live attack surface
# Navigate to: https://target.com/swagger-ui.html

# Direct API calls from the UI:
# 1. Open Swagger UI → find /admin/users endpoint
# 2. Click "Try it out"
# 3. Delete Authorization header value
# 4. Click "Execute"
# 5. If returns 200 → auth bypass!

# CSRF via Swagger UI:
# Some UIs auto-inject saved credentials
# Attacker can craft URL that calls API via Swagger UI
# https://target.com/swagger-ui.html#/admin/deleteUser?id=1

# Check if Swagger UI sends real requests:
# Open DevTools → Network tab
# Execute a request in Swagger UI
# Confirm it calls target.com/api/... directly
```

---

## 06 · Automated Swagger Security Scan

```python
#!/usr/bin/env python3
import requests, json, sys

TARGET = sys.argv[1]
SWAGGER = f"{TARGET}/swagger.json"

# Download spec
resp = requests.get(SWAGGER, verify=False)
spec = resp.json()

base_url = TARGET
servers = spec.get("servers", [])
if servers:
    base_url = servers[0].get("url", TARGET)

findings = []

for path, methods in spec.get("paths", {}).items():
    for method, details in methods.items():
        if method in ["get","post","put","delete","patch"]:
            
            # Check for missing auth
            if details.get("security") == []:
                findings.append(f"NO AUTH: {method.upper()} {path}")
            
            # Check for deprecated
            if details.get("deprecated"):
                findings.append(f"DEPRECATED: {method.upper()} {path}")
            
            # Check for internal
            if details.get("x-internal"):
                findings.append(f"INTERNAL: {method.upper()} {path}")
            
            # Test endpoint with no auth
            url = base_url + path.replace("{id}","1").replace("{userId}","1")
            try:
                r = requests.request(method.upper(), url, 
                                     timeout=5, verify=False)
                if r.status_code in [200, 201]:
                    findings.append(f"ACCESSIBLE NO AUTH: {method.upper()} {url} → {r.status_code}")
            except:
                pass

print("\n=== SWAGGER SECURITY FINDINGS ===")
for f in findings:
    print(f"[!] {f}")
```

---

## Checklist

```
☐  Check all swagger paths — /swagger /api-docs /openapi.json /redoc
☐  Read securitySchemes — find endpoints with security:[] = no auth
☐  Import to Postman/Burp — instant collection of all endpoints
☐  Hunt deprecated paths — old /v1/ endpoints forgotten = vulns
☐  Check x-internal fields — developer-only endpoints in spec
☐  Test Swagger UI directly — execute calls from browser UI
☐  Compare v1 vs v2 spec — endpoints only in old version = forgotten
☐  Extract all params — every param in spec = injection target
```

---

*30-Day API Pentesting Series — follow for more.*
