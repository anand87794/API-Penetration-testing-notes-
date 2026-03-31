# API Pentesting with Burp Suite: Intercepting, Fuzzing & Scanning

> **Series:** 30-Day API Pentesting | **Day 15** | Week 3: Tools & Techniques  
> **Difficulty:** Beginner → Intermediate  
> **Tool:** Burp Suite Pro (Community also works for most things)

---

## What is Burp Suite and Why Do You Need It?

If you're serious about API pentesting, Burp Suite is non-negotiable. Think of it as a **middleman that sits between your browser and the internet** — it captures every single request your browser makes, lets you pause it, modify it, and decide whether to send it.

Without Burp, you're blind. With Burp, every API call your browser makes is right in front of you with full headers, body, and response — ready to be tampered with.

```
Normal flow:   Browser ──────────────────▶ API Server
Burp flow:     Browser ──▶ Burp (8080) ──▶ API Server
                                ↕
                         You modify, 
                         replay, fuzz
                         here
```

---

## Part 1: Setting Up Burp Suite for API Testing

### Step 1: Start the Proxy Listener

When you open Burp Suite, it automatically starts a proxy listener on port 8080. This is the "middleman" port.

```
Burp Suite → Proxy tab → Proxy Settings
→ Proxy Listeners section
→ Should show: 127.0.0.1:8080 (Running ✓)
```

If it's not running, click **Add**, set interface to `127.0.0.1:8080`, save.

### Step 2: Configure Your Browser

Your browser needs to route all traffic through Burp's port 8080.

**Option A: Use Burp's built-in Chromium browser (easiest)**
```
Proxy tab → Open Browser
→ A pre-configured Chromium opens automatically
→ All traffic already routed through Burp — no setup needed
```

**Option B: Configure Firefox manually**
```
Firefox → Settings → Search "proxy" → Network Settings
→ Manual proxy configuration
→ HTTP Proxy: 127.0.0.1  Port: 8080
→ Also use this proxy for HTTPS ✓
→ OK
```

### Step 3: Install the Burp CA Certificate (HTTPS Websites)

Without this, HTTPS websites will show a certificate error. Burp needs to be trusted to read HTTPS traffic.

```
1. Open browser (configured to use Burp proxy)
2. Visit: http://burpsuite  (or http://127.0.0.1:8080)
3. Click "CA Certificate" → download it
4. Firefox: Settings → Privacy → View Certificates → Import → trust for websites ✓
5. Chrome: Settings → Security → Manage certificates → Trusted Root → import
```

After this, all HTTPS traffic is readable by Burp.

### Step 4: Essential Extensions to Install

These four extensions are must-haves for API testing:

```
Burp → Extensions tab → BApp Store → Search and install:

1. InQL              → GraphQL testing (introspection, query generation)
2. Logger++          → Logs ALL requests with timestamps — never miss a call
3. Autorize          → Auto-tests authorization bugs (BOLA/BFLA) across all requests
4. Turbo Intruder    → High-speed fuzzing (much faster than built-in Intruder)
```

**How to install:**
```
Extensions tab → BApp Store tab → Search name → Install
```

---

## Part 2: Burp Proxy — Capturing API Traffic

### How Intercepting Works

When Intercept is ON, every request your browser makes is **paused** and shown to you. You can read it, modify it, then decide to forward or drop it.

```
Proxy tab → Intercept tab → "Intercept is on" button
```

### Practical Workflow for API Testing

```
Step 1: Turn Intercept OFF (let all traffic flow through)
Step 2: Browse the target app normally — log in, use features
Step 3: Check HTTP History tab — EVERY API call is logged there
Step 4: Find the interesting API calls (look for /api/ in the URL)
Step 5: Right-click any request → Send to Repeater
```

### Reading the HTTP History

```
Proxy → HTTP History tab shows:
  #    | Method | Host          | URL              | Status | Length
  ---  | ------ | ----          | ---              | ------  | ------
  1    | GET    | api.target.com| /api/v1/user/me  | 200    | 1.2 KB
  2    | POST   | api.target.com| /api/v1/orders   | 201    | 0.8 KB
  3    | GET    | api.target.com| /api/v1/users/42 | 200    | 0.5 KB
  
Click any row → see full request (left panel) + response (right panel)
```

### Modifying a Request On-The-Fly

```
Turn Intercept ON → browse app → request appears → edit:

Original:  GET /api/v1/users/42 HTTP/1.1
Modified:  GET /api/v1/users/41 HTTP/1.1
           (changed 42 to 41 — trying to access another user)

→ Click Forward → request sent with your modification
→ Read the response — did you get user 41's data? That's BOLA!
```

---

## Part 3: Repeater — Your Most-Used API Testing Tool

Repeater is where you spend 80% of your time. It lets you send the same request over and over with modifications, instantly seeing each response.

### How to Use Repeater

```
Step 1: Find any interesting API request in HTTP History
Step 2: Right-click → Send to Repeater (or press Ctrl+R)
Step 3: Go to Repeater tab — request is there waiting
Step 4: Modify anything in the request
Step 5: Click Send → see response on the right
Step 6: Modify again → Send again — unlimited times
```

### What to Test in Repeater

**Test 1: BOLA (Change Object IDs)**
```
Original request:
GET /api/v1/invoices/1002 HTTP/1.1
Authorization: Bearer YOUR_TOKEN

Modify the ID:
GET /api/v1/invoices/1001 HTTP/1.1    ← changed to another user's ID
Authorization: Bearer YOUR_TOKEN

Send → If response has invoice data → BOLA found!
```

**Test 2: Authentication Bypass (Remove Token)**
```
Original:
GET /api/v1/admin/users HTTP/1.1
Authorization: Bearer ADMIN_TOKEN

Remove the header:
GET /api/v1/admin/users HTTP/1.1
(no Authorization header)

Send → If response is 200 with data → auth bypass found!
```

**Test 3: Mass Assignment (Add Extra Fields)**
```
Original POST body:
{"email": "test@test.com", "name": "Test User"}

Add privileged fields:
{"email": "test@test.com", "name": "Test User", "role": "admin", "is_admin": true}

Send → Then check GET /api/me → did role change to admin?
```

**Test 4: BFLA (Use Wrong Role Token)**
```
Original (admin made this request):
GET /api/v1/admin/export HTTP/1.1
Authorization: Bearer ADMIN_TOKEN

Change token to regular user:
GET /api/v1/admin/export HTTP/1.1
Authorization: Bearer USER_TOKEN

Send → If 200 OK → BFLA! Regular user accessed admin function.
```

**Test 5: Injection Testing**
```
Original:
POST /api/v1/search HTTP/1.1
{"query": "laptop"}

Test SQL injection:
{"query": "laptop'"}              → SQL error? → SQLi possible
{"query": "laptop' OR 1=1--"}    → more data returned? → SQLi confirmed

Test NoSQL injection:
{"query": {"$gt": ""}}           → auth bypass?

Test SSTI:
{"query": "{{7*7}}"}             → response has 49? → SSTI!
```

### Repeater Tab Organization

```
You'll have many tabs open. Name them:
- Right-click tab → Rename
  "BOLA - Invoice IDs"
  "Auth Bypass - Admin"  
  "Mass Assignment - Register"
  
This saves time when bouncing between tests.
```

---

## Part 4: Intruder — Automated Fuzzing at Scale

Intruder takes ONE request and automatically sends it hundreds or thousands of times, swapping in different values at positions you mark. Perfect for IDOR/BOLA testing at scale, rate limit testing, and injection fuzzing.

### Understanding Attack Types

Burp Intruder has 4 attack types:

```
Sniper     → One payload list, one position at a time (most common)
Battering Ram → Same payload in all positions simultaneously  
Pitchfork  → Multiple payload lists, one per position (paired)
Cluster Bomb → All combinations of multiple payload lists (very slow)
```

For API testing, you'll use **Sniper** 90% of the time.

### Workflow: IDOR/BOLA Testing at Scale

```
Step 1: Find a request with an ID in Intruder
  GET /api/v1/invoices/1002

Step 2: Send to Intruder (Ctrl+I or right-click → Send to Intruder)

Step 3: Intruder → Positions tab
  → Click "Clear §" to remove default positions
  → Select the ID "1002" in the request
  → Click "Add §" 
  → It becomes: GET /api/v1/invoices/§1002§

Step 4: Payloads tab
  → Payload type: Numbers
  → From: 1000  To: 2000  Step: 1
  → (This will try IDs 1000, 1001, 1002 ... 2000)

Step 5: Click "Start Attack"
  → Burp sends 1001 requests automatically
  → Sort results by Status code or Length
  → All 200 responses with similar length = BOLA on every ID!
```

### Workflow: Rate Limit Testing

```
Step 1: Send login request to Intruder
  POST /api/v1/auth/login
  {"email": "admin@target.com", "password": "§wrongpass§"}

Step 2: Positions tab → mark §wrongpass§

Step 3: Payloads tab
  → Payload type: Simple list
  → Load password list (or paste common passwords)

Step 4: Options tab
  → Request Engine: Max concurrent requests = 10
  → (Don't hammer too hard to avoid actual harm)

Step 5: Start Attack
  → If you get 200 → password found
  → If you never get 429 → rate limiting is MISSING = bug!
```

### Workflow: Injection Fuzzing All Fields

```
Step 1: Find API endpoint with multiple parameters
  POST /api/v1/search
  {"category": "electronics", "query": "laptop", "sort": "price"}

Step 2: Send to Intruder, mark all string values:
  {"category": "§electronics§", "query": "§laptop§", "sort": "§price§"}
  (Use attack type: Sniper — tests one position at a time)

Step 3: Payloads → Simple List → paste injection payloads:
  '
  ' OR 1=1--
  {"$gt":""}
  {{7*7}}
  <script>alert(1)</script>
  ../../../../etc/passwd
  http://169.254.169.254/latest/meta-data/

Step 4: Start Attack → look for:
  → Different response lengths (more data = injection worked)
  → 500 errors with error messages
  → Response containing "49" (SSTI from {{7*7}})
```

> **Note for Community Burp users:** Free Intruder is throttled (1 request/second). Use **Turbo Intruder** extension instead — it's free and much faster.

---

## Part 5: Scanner — Automated Vulnerability Detection

The Scanner actively sends injection payloads to every parameter and analyzes responses for vulnerabilities. Burp Pro only, but extremely powerful.

### How to Scan an API Endpoint

```
Method 1: Scan a specific request
  HTTP History → right-click any API request → Scan
  → Active scan dialog appears
  → Select "Audit checks - all insertions points"
  → OK → Burp starts injecting payloads

Method 2: Scan entire target
  Target → Site Map → right-click target domain
  → Scan → Configure and start

Method 3: Scan while browsing (crawl + audit)
  Dashboard → New Scan → "Crawl and audit"
  → Set start URL to the API base
  → Burp will crawl all endpoints then audit them
```

### Reading Scanner Results

```
Dashboard tab → Issue activity section shows all findings:

Example findings:
  ⬛ HIGH   SQL injection             /api/v1/search (parameter: query)
  ⬛ HIGH   Stored XSS                /api/v1/comments (parameter: body)
  ⬛ MEDIUM CORS misconfiguration     /api/v1/user
  ⬛ LOW    Verbose error messages    /api/v1/auth

Click any finding → see:
  - Evidence (exact request + response showing the vulnerability)
  - Remediation advice
  - References
```

### Scanner Limitations

The Scanner is great at:
- SQL injection
- XSS
- SSTI
- Path traversal
- XXE
- Command injection

The Scanner **cannot** find:
- BOLA/IDOR (business logic — needs two accounts)
- BFLA (needs to know what roles should/shouldn't access)
- Mass assignment (needs context about valid field names)
- Rate limiting issues
- JWT vulnerabilities

That's why you still need manual testing with Repeater and Autorize.

---

## Part 6: Autorize Extension — Auth Testing on Autopilot

Autorize is the most powerful extension for finding BOLA and BFLA automatically. You give it a low-privilege token, it **automatically replays every single request** you make with that token, and highlights when the access is different.

### Setup Autorize

```
Step 1: Log in with TWO accounts
  Account A (high privilege): Admin account
  Account B (low privilege):  Regular user account

Step 2: Get Account B's token
  Log in as Account B → capture login response → copy JWT token

Step 3: Open Autorize extension tab
  Extensions → Autorize → paste Account B's token in the big text box:
  
  Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.USER_PAYLOAD.SIG
  
Step 4: Make sure "Autorize is on" is toggled ON
```

### Using Autorize

```
Step 5: Now browse as Account A (admin)
  - Visit admin panels
  - View user management
  - Export reports
  - Access settings

Step 6: Autorize automatically replays EVERY request with Account B's token
  - You don't have to do anything manually
  - It shows the result in a table in real-time

Step 7: Read the Autorize table:
  URL                          | Orig. Length | Modified Length | Status
  /api/v1/admin/users          | 4.2 KB       | 4.2 KB          | 🟢 Bypassed!
  /api/v1/admin/export         | 8.1 KB       | 8.1 KB          | 🟢 Bypassed!
  /api/v1/admin/config         | 0.8 KB       | 403             | 🔴 Enforced
  
🟢 Bypassed = same response with low-priv token = BOLA or BFLA found!
🔴 Enforced = got 403 with low-priv token = properly secured
🟡 Is enforced? = different response = manual review needed
```

### Autorize with Unauthenticated Testing

```
You can also test with NO token at all:
  Autorize → Unauth tab → paste same token but make it invalid
  OR
  Check "Intercept requests from Autorize" and remove the header

Now: Admin browsing + Autorize → checks if UNAUTHENTICATED user can access
Green without any token = even more critical finding!
```

---

## Part 7: Turbo Intruder — High-Speed Fuzzing (Free!)

Turbo Intruder is a Burp extension that replaces the slow built-in Intruder for Community users. It can send thousands of requests per second.

### Basic Turbo Intruder Usage

```
Step 1: Right-click any request → Extensions → Send to Turbo Intruder

Step 2: Mark your injection point with %s:
  GET /api/v1/users/%s HTTP/1.1

Step 3: The Python editor shows — modify the script:

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=10,
        requestsPerConnection=100,
        pipeline=False
    )
    
    # For IDOR testing: try IDs 1-1000
    for i in range(1, 1001):
        engine.queue(target.req, str(i))

def handleResponse(req, interesting):
    # Flag 200 responses that aren't yours
    if req.status == 200 and len(req.response) > 100:
        table.add(req)

Step 4: Click "Attack"
→ Sends 1000 requests rapidly
→ Interesting responses appear in the table
```

---

## Part 8: Complete API Testing Workflow — From Zero to Bugs

Here is the exact order of operations when you start testing a new API target:

```
Phase 1: Setup (5 minutes)
  ☐ Open Burp → proxy listener running on 8080
  ☐ Configure browser → 127.0.0.1:8080
  ☐ Install CA cert → HTTPS works without errors
  ☐ Enable Logger++ → captures everything
  ☐ Setup Autorize → paste low-priv token

Phase 2: Passive Recon (15 minutes)
  ☐ Browse ENTIRE app as admin — click everything
  ☐ All API calls now logged in HTTP History + Logger++
  ☐ Note all endpoints with IDs in the URL
  ☐ Note all POST endpoints (create/update operations)
  ☐ Check if /swagger.json exists → import into Postman too

Phase 3: Auth Testing with Autorize (auto, runs in background)
  ☐ Autorize running → browse app → green items = BOLA/BFLA!
  ☐ Check Autorize table after browsing every section

Phase 4: Manual Testing with Repeater (bulk of time)
  ☐ For each ID in URL: test BOLA (change to other user's ID)
  ☐ For each POST: test mass assignment (add role/is_admin/credits)
  ☐ For each auth: test removal + wrong role token
  ☐ For each string param: test injection payloads

Phase 5: Automated Testing
  ☐ Intruder: /users/§ID§ + number range → IDOR at scale
  ☐ Intruder: /login § + 100 iterations → rate limit check
  ☐ Scanner: right-click key POST endpoints → active scan

Phase 6: Documentation
  ☐ For each finding: save request + response in Burp
  ☐ Right-click → Save item → for your report
```

---

## Quick Reference: Keyboard Shortcuts

```
Ctrl + R    → Send to Repeater
Ctrl + I    → Send to Intruder
Ctrl + S    → Send to Scanner
Ctrl + A    → Send to Active Scanner
Ctrl + F    → Search in request/response

In Repeater:
Ctrl + Enter → Send request

In HTTP History:
Ctrl + Click → Select multiple requests
```

---

## Common Mistakes Beginners Make

```
❌ Forgetting to install the CA certificate
   → HTTPS sites show "Certificate error" → fix: install Burp CA

❌ Leaving Intercept ON while browsing
   → Every click pauses waiting for you → turn Intercept OFF while exploring

❌ Not using Logger++
   → Default HTTP History has a limit → Logger++ saves everything indefinitely

❌ Only testing GET requests
   → POST/PUT/DELETE endpoints often have more vulnerabilities

❌ Ignoring the response
   → Always read the FULL response — headers + body reveal sensitive info

❌ Testing in production too aggressively
   → Use delay in Intruder options → don't send 1000 reqs/second to prod
```

---

## Checklist

```
☐  Setup: proxy 127.0.0.1:8080 + CA cert installed + HTTPS working
☐  Extensions: InQL + Logger++ + Autorize + Turbo Intruder installed
☐  Autorize: paste low-priv token + browse as admin → check green items
☐  Repeater: test every ID (BOLA), every auth (bypass), every POST (mass assign)
☐  Intruder: /users/§ID§ + 1-1000 → automated IDOR test
☐  Rate limit: Intruder 100 iterations on /login → check for 429
☐  Scanner: active scan on key POST endpoints → check issues
☐  Save all findings: right-click → Save item for report evidence
```

---

*Written by @anand87794*  
*30-Day API Pentesting Series — Day 15 of 30*
