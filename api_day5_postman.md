# Using Postman for API Penetration Testing: A Practical Guide

> **Series:** 30-Day API Pentesting  
> **Day:** 5 — Week 1: API Fundamentals & Recon  
> **Topic:** Postman for API Security Testing Cheatsheet

---

## Why Postman for API Security Testing?

Postman is the fastest way to test APIs for security issues. Environments, collections, scripts, and the Collection Runner make it easy to automate IDOR, auth bypass, mass assignment, and rate limit testing at scale — no code needed.

---

## 01 · Environment Variables Setup

```javascript
// Create two environments: AccountA and AccountB

// AccountA Environment:
base_url  = https://api.target.com
token     = Bearer eyJhbGciOiJIUzI1NiJ9...  (Account A JWT)
user_id   = 1002
other_id  = 1001

// AccountB Environment:
base_url  = https://api.target.com
token     = Bearer eyJhbGciOiJIUzI1NiJ9...  (Account B JWT)
user_id   = 1001
other_id  = 1002

// Use in requests:
GET {{base_url}}/api/v1/users/{{other_id}}
Authorization: {{token}}

// Switch environment = entire collection now runs as different user
// This is the fastest way to test IDOR/BOLA across all endpoints
```

---

## 02 · Auth Testing — Remove & Swap Tokens

```javascript
// Pre-request Script — remove auth header for this request
pm.request.headers.remove('Authorization');

// Tests tab — assert that endpoint rejects unauthenticated requests
pm.test("Should return 401 without token", function() {
    pm.expect(pm.response.code).to.equal(401);
});

// Tests tab — catch BOLA/auth bypass
pm.test("No cross-account data access", function() {
    var data = pm.response.json();
    pm.expect(pm.response.code).to.not.equal(200);
    // OR check that response doesn't contain victim's data:
    pm.expect(JSON.stringify(data)).to.not.include("victim@target.com");
});

// Collection-level variable — swap for all requests at once
// Collection → Variables → token = {{tokenB}}
// Now run entire collection as Account B against Account A's resources
```

---

## 03 · IDOR Testing at Scale

```javascript
// Step 1: Create a CSV data file (ids.csv):
// id
// 1001
// 1002
// 1003
// ...
// 2000

// Step 2: Create request
GET {{base_url}}/api/v1/invoices/{{id}}
Authorization: {{token}}

// Step 3: Tests tab — flag suspicious responses
pm.test("Check for IDOR", function() {
    if (pm.response.code === 200) {
        var data = pm.response.json();
        // Flag if response belongs to a different user
        if (data.userId && data.userId !== pm.environment.get("user_id")) {
            console.log("IDOR FOUND! ID: " + pm.variables.get("id"));
            console.log("Owner: " + data.userId);
        }
    }
});

// Step 4: Collection Runner
// → Select collection
// → Data: ids.csv
// → Iterations: 1000
// → Delay: 0ms
// → Run Collection

// All 1000 IDs tested in ~2 minutes
// Check console for "IDOR FOUND!" messages
```

---

## 04 · Mass Assignment Testing

```javascript
// Pre-request Script — auto-inject extra params into POST body
var body = JSON.parse(pm.request.body.raw);

// Add privilege escalation params
body.role = "admin";
body.is_admin = true;
body.account_type = "premium";
body.plan = "enterprise";
body.credits = 99999;
body.verified = true;
body.email_verified = true;

pm.request.body.update({
    mode: 'raw',
    raw: JSON.stringify(body)
});

// Tests tab — check if mass assignment worked
pm.test("Mass assignment check", function() {
    var data = pm.response.json();
    if (data.role === "admin" || data.is_admin === true) {
        console.log("MASS ASSIGNMENT VULNERABLE!");
        console.log(JSON.stringify(data));
    }
});

// Manual approach:
// 1. GET /api/me → copy all fields from response
// 2. Add ALL fields to POST /register body
// 3. Send and check if privileged fields were accepted
```

---

## 05 · Rate Limit Testing

```javascript
// Collection Runner setup:
// → Iterations: 100
// → Delay: 0ms (sends as fast as possible)
// → Run on: POST /api/auth/login

// Request body with password variable:
{
    "email": "admin@target.com",
    "password": "{{$randomPassword}}"
}

// Tests tab — track rate limiting
var responses = pm.collectionVariables.get("responses") || [];
responses.push(pm.response.code);
pm.collectionVariables.set("responses", responses);

pm.test("Rate limit check", function() {
    // If 429 not seen after many requests = rate limit missing
    if (pm.response.code !== 429) {
        pm.collectionVariables.set("no_rate_limit", true);
    }
});

// After run: check console
// If 0 requests returned 429 → rate limit missing → report as bug

// Endpoints to always test for rate limiting:
// POST /auth/login
// POST /auth/forgot-password
// POST /auth/verify-otp
// POST /auth/reset-password
// POST /api/redeem-coupon
// GET  /api/check-email?email=x  (email enumeration)
```

---

## 06 · Automated Attack Chains

```javascript
// ── Request 1: Register Account ──
// POST {{base_url}}/api/register
// Tests tab:
pm.test("Register success", function() {
    pm.expect(pm.response.code).to.equal(201);
    var data = pm.response.json();
    pm.environment.set("new_user_id", data.id);
    pm.environment.set("new_email", data.email);
});

// ── Request 2: Login ──
// POST {{base_url}}/api/login
// Tests tab:
pm.test("Login success", function() {
    var data = pm.response.json();
    pm.environment.set("token", "Bearer " + data.access_token);
    pm.environment.set("refresh_token", data.refresh_token);
    pm.environment.set("user_id", data.user.id);
});

// ── Request 3: Test IDOR ──
// GET {{base_url}}/api/users/{{victim_id}}/data
// Authorization: {{token}}
// Tests tab:
pm.test("IDOR check", function() {
    if (pm.response.code === 200) {
        console.log("IDOR VULNERABLE: accessed victim data");
        console.log(pm.response.text());
    } else {
        console.log("IDOR protected: " + pm.response.code);
    }
});

// ── Request 4: Test Mass Assignment ──
// PUT {{base_url}}/api/users/{{user_id}}
// Body: {"name": "test", "role": "admin", "is_admin": true}
// Tests tab:
pm.test("Mass assignment check", function() {
    var data = pm.response.json();
    pm.expect(data.role).to.not.equal("admin");
});

// ── Request 5: Logout + Replay ──
// POST {{base_url}}/api/logout
// Then replay old token — does server still accept it?
```

---

## Essential Postman Scripts Reference

```javascript
// Save access token after login
pm.environment.set("token", "Bearer " + pm.response.json().access_token);

// Remove Authorization header (auth bypass test)
pm.request.headers.remove("Authorization");

// Add Authorization with Account B token
pm.request.headers.upsert({
    key: "Authorization",
    value: "Bearer " + pm.environment.get("tokenB")
});

// Assert 403 (not 200) — detect auth bypass
pm.test("Auth enforced", () => pm.expect(pm.response.code).to.equal(403));

// Log response for review
console.log("Status: " + pm.response.code);
console.log("Body: " + pm.response.text());

// Check response contains no sensitive data
pm.test("No data leak", function() {
    pm.expect(pm.response.text()).to.not.include("password");
    pm.expect(pm.response.text()).to.not.include("ssn");
    pm.expect(pm.response.text()).to.not.include("credit_card");
});

// Set next request in chain
postman.setNextRequest("Test IDOR");  // jump to named request
postman.setNextRequest(null);         // stop chain
```

---

## Checklist

```
☐  Create 2 environments — AccountA + AccountB for IDOR testing
☐  Use {{base_url}} + {{token}} variables in every request
☐  Collection Runner — 100 iterations, 0 delay → test rate limits
☐  Tests tab assertions — pm.expect(response.code).to.equal(403)
☐  Pre-request scripts — auto-inject extra params before each request
☐  Save token in chain — pm.environment.set('token', json.access_token)
☐  Data files (CSV) — test 1000+ IDs with Collection Runner
☐  Export collection — share full test suite with team
```

---

*30-Day API Pentesting Series — follow for more.*
