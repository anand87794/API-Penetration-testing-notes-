# BFLA: Finding Privilege Escalation in API Endpoints
## Complete Study Notes — API Pentesting Day 12

> **Series:** 30-Day API Pentesting  
> **Day:** 12 — Week 2: OWASP API Top 10  
> **OWASP Category:** API5:2023 — Broken Function Level Authorization

---

## 🧠 Core Concept — What is BFLA?

### Definition

**Broken Function Level Authorization (BFLA)** occurs when an API **doesn't check whether the caller has the right ROLE** to execute a specific function (endpoint). The server checks if you're authenticated (have a valid token) but doesn't check if your role is allowed to call that specific endpoint.

### The Key Mental Model

```
Authentication = "Are you logged in?"         ← is your token valid?
Authorization  = "Are you ALLOWED to do this?" ← does your ROLE allow this function?

BFLA = Authentication ✅  but  Authorization ❌
```

### BFLA vs BOLA — Crystal Clear Difference

| | BOLA | BFLA |
|--|------|------|
| **Full name** | Broken Object Level Auth | Broken Function Level Auth |
| **The check missing** | Per-object ownership check | Per-function role check |
| **Attack** | Change object ID to access another user's data | Call admin/restricted function with wrong role |
| **Example** | `GET /invoices/1001` (you own 1002) | `GET /admin/users` (you're a "user", not "admin") |
| **What you access** | Another user's specific data | Admin-level functionality for all data |
| **OWASP rank** | API1 | API5 |

### Real-World Analogy

```
Imagine a hospital:

BOLA = You look at ANOTHER patient's medical file (wrong patient ID)
BFLA = You walk into the DOCTOR'S OFFICE and read ALL patient files (wrong role)

BOLA = specific record, wrong person
BFLA = entire restricted area, wrong role
```

---

## 🔍 Understanding Privilege Levels

### Typical API Role Hierarchy

```
super_admin  → everything
    admin    → manage users, view logs, export data, configure system
    manager  → view reports, moderate content
    user     → own data only
    guest    → public data only
```

### What Each Role Should Access

```
Endpoint                    super_admin  admin  manager  user  guest
GET  /api/admin/users           ✅         ✅      ❌      ❌     ❌
DELETE /api/users/{id}          ✅         ✅      ❌      ❌     ❌
GET  /api/admin/export          ✅         ✅      ❌      ❌     ❌
GET  /api/reports               ✅         ✅      ✅      ❌     ❌
GET  /api/users/me              ✅         ✅      ✅      ✅     ❌
GET  /api/products              ✅         ✅      ✅      ✅     ✅

BFLA = a "user" successfully calls any endpoint marked ❌ for user role
```

---

## 🎯 Finding BFLA — Where to Look

### Step 1: Find ALL Admin/Privileged Endpoints

```bash
# Method 1: Swagger/OpenAPI spec
curl https://target.com/swagger.json | python3 -c "
import json, sys
spec = json.load(sys.stdin)
for path, methods in spec.get('paths', {}).items():
    for method, detail in methods.items():
        # Look for admin/internal/manage/staff in path or tags
        if any(kw in path.lower() for kw in ['admin','internal','manage','staff','system','config']):
            print(f'{method.upper()} {path}')
"

# Method 2: JavaScript source mining
grep -r "admin\|/manage\|/staff\|/internal\|/system" *.js | \
    grep -oE '"/api/[^"]*"' | sort -u

# Method 3: Brute force with admin-specific wordlist
ffuf -u https://target.com/api/FUZZ \
    -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
    -mc 200,401,403 \
    -fc 404

# Method 4: Create admin account, browse entire app, capture with Burp
# → In Burp: Target → Site Map → filter by "admin" in URL

# Common admin endpoint patterns to test:
ADMIN_PATHS=(
    "/admin"
    "/api/admin"
    "/api/v1/admin"
    "/manage"
    "/api/manage"
    "/internal"
    "/api/internal"
    "/staff"
    "/api/staff"
    "/system"
    "/api/system"
    "/api/users/all"
    "/api/admin/users"
    "/api/admin/export"
    "/api/admin/config"
    "/api/admin/logs"
    "/api/admin/reports"
    "/api/admin/stats"
    "/api/admin/dashboard"
)
```

### Step 2: Test Each Endpoint with Lower Privilege Token

```bash
TARGET="https://api.target.com"
ADMIN_TOKEN="eyJhbGc..."   # Your admin account JWT
USER_TOKEN="eyJhbGc..."    # Your regular user JWT

# List of admin endpoints you found
ADMIN_ENDPOINTS=(
    "GET /api/admin/users"
    "GET /api/admin/export"
    "DELETE /api/users/1"
    "PUT /api/users/1/role"
    "GET /api/admin/logs"
    "GET /api/admin/config"
)

for endpoint in "${ADMIN_ENDPOINTS[@]}"; do
    METHOD=$(echo $endpoint | cut -d' ' -f1)
    PATH=$(echo $endpoint | cut -d' ' -f2)
    
    # Test with admin token (should work)
    ADMIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X $METHOD "$TARGET$PATH" \
        -H "Authorization: Bearer $ADMIN_TOKEN")
    
    # Test with user token (should be 403)
    USER_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X $METHOD "$TARGET$PATH" \
        -H "Authorization: Bearer $USER_TOKEN")
    
    # Test with no token (should be 401)
    NOAUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X $METHOD "$TARGET$PATH")
    
    echo "$METHOD $PATH → Admin:$ADMIN_CODE | User:$USER_CODE | NoAuth:$NOAUTH_CODE"
    
    # Flag vulnerabilities
    [ "$USER_CODE" = "200" ] && echo "  🚨 BFLA! User token accesses admin endpoint!"
    [ "$NOAUTH_CODE" = "200" ] && echo "  🚨 CRITICAL! No auth needed for admin endpoint!"
done
```

---

## 🔬 HTTP Method BFLA

### Concept

Even if `GET /api/users/1001` is allowed for regular users, `DELETE /api/users/1001` should not be.

```bash
# Test all HTTP methods on every endpoint
ENDPOINT="https://api.target.com/api/users/1001"
USER_TOKEN="eyJhbGc..."

for METHOD in GET POST PUT PATCH DELETE OPTIONS HEAD; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X $METHOD "$ENDPOINT" \
        -H "Authorization: Bearer $USER_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"role":"admin","is_admin":true}')
    echo "$METHOD $ENDPOINT → $CODE"
done

# Expected results:
# GET    /api/users/1001 → 200 (allowed - read own data)
# DELETE /api/users/1001 → 403 (forbidden - can't delete)
# PUT    /api/users/1001 → 403 (forbidden - can't modify role)

# BFLA if DELETE/PUT/PATCH returns 200/204!
```

---

## ⬆️ Vertical vs Horizontal Privilege Escalation

### Horizontal Privilege Escalation (= BOLA)
```
Same role, different user's data
User A (role: user, id: 1002) → reads User B's data (id: 1001)
→ This is BOLA (API1)
```

### Vertical Privilege Escalation (= BFLA)
```
Different role, restricted function
User (role: user) → calls admin-only function
→ This is BFLA (API5)
```

### Chaining Both for Maximum Impact

```bash
# Step 1: BFLA to get admin user list
curl -H "Authorization: Bearer USER_TOKEN" \
    https://api.target.com/api/admin/users
# → Returns: [{id:1, email:"admin@target.com", role:"admin"}, ...]

# Step 2: BOLA to read/modify admin's data
curl -H "Authorization: Bearer USER_TOKEN" \
    https://api.target.com/api/users/1   # admin's ID = 1

# Step 3: Chain to account takeover
# Use forgot-password with admin's email from BFLA result
# Combined BFLA + BOLA = Critical severity chain
```

---

## 🔧 BFLA in API Versions

### Old Versions Often Missing Auth Checks

```bash
# If /api/v3/admin/users is properly protected:
curl -H "Authorization: Bearer USER_TOKEN" \
    https://api.target.com/api/v3/admin/users
# → 403 Forbidden (patched)

# Check old versions:
for v in v1 v2 beta alpha; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer USER_TOKEN" \
        https://api.target.com/api/$v/admin/users)
    echo "api/$v/admin/users → $CODE"
done
# api/v1/admin/users → 200   ← BFLA in old version!
# api/v2/admin/users → 403
# api/v3/admin/users → 403
```

---

## 🕸️ BFLA in GraphQL

### Testing GraphQL Admin Mutations

```graphql
# Test as regular user — these should all return errors

# Admin user management
mutation {
  deleteUser(id: 1) { success }
}

mutation {
  updateUserRole(userId: 1, role: "admin") { 
    id role 
  }
}

mutation {
  banUser(userId: 1, reason: "test") { 
    success 
  }
}

mutation {
  createAdminAccount(email: "hack@hack.com", role: "admin") {
    id token
  }
}

# Admin data access
query {
  allUsers { id email role password }
}

query {
  adminDashboard { totalUsers revenue config }
}

query {
  exportDatabase { url expiresAt }
}
```

```bash
# Test with curl
curl -X POST https://api.target.com/graphql \
    -H "Authorization: Bearer USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query":"mutation{deleteUser(id:1){success}}"}'

# Expected: {"errors":[{"message":"Forbidden: admin role required"}]}
# BFLA if: {"data":{"deleteUser":{"success":true}}}
```

---

## 📊 Severity Assessment

| BFLA Finding | Severity |
|-------------|----------|
| Regular user access to GET /admin/users (PII of all users) | High |
| Regular user can DELETE any user account | Critical |
| Regular user can export full database | Critical |
| Regular user can change any user's role | Critical |
| Regular user can access admin config/secrets | High |
| No auth needed for admin endpoints | Critical |
| Old API version exposes admin functions | High |

---

## 📝 Bug Report Template

```
Title: BFLA — Regular User Can Access GET /api/v1/admin/users 
       Exposing PII of All Platform Users

Severity: High

CVSS Score: 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

Description:
The GET /api/v1/admin/users endpoint, which is intended to be 
accessible only by administrators, can be accessed by any 
authenticated regular user. The API validates that the user has 
a valid authentication token but fails to verify that the user's 
role is "admin" before returning the full user list with PII.

Steps to Reproduce:
1. Register two accounts: admin@test.com (admin) and user@test.com (user)
2. Login as regular user → obtain USER_TOKEN
3. Send request:
   GET /api/v1/admin/users
   Authorization: Bearer USER_TOKEN

4. Observe 200 OK response containing full user list:
   [
     {"id":1, "email":"admin@target.com", "role":"admin"},
     {"id":2, "email":"john@target.com",  "ssn":"123-45-6789"},
     ...10,000 more users with PII...
   ]

Proof of Concept:
[Screenshot of request with USER_TOKEN and 200 response with user list]

Impact:
Any authenticated regular user can enumerate the complete user 
database, accessing email addresses, names, and potentially 
sensitive PII of all platform users. This violates user privacy 
and constitutes a data breach.

Remediation:
- Implement role-based access control (RBAC) middleware
- Check req.user.role === 'admin' before processing admin endpoints
- Apply authorization middleware to all /admin/* routes
- Conduct audit of all admin endpoints for consistent authorization
```

---

## ✅ Final Checklist

```
☐  Find admin endpoints — Swagger, JS files, ffuf, Burp Spider
☐  Replay with user token — every admin endpoint → test with regular user Bearer
☐  Test all HTTP methods — GET allowed? Try POST/PUT/DELETE on same endpoint
☐  Test without any token — Remove Authorization header → should return 401
☐  Test old API versions — /api/v1/admin might work even if /v3/admin is fixed
☐  GraphQL admin mutations — deleteUser, updateRole, banUser with regular token
☐  Chain BFLA + BOLA — use admin user list from BFLA for targeted BOLA
☐  Document role hierarchy — show admin vs user response difference in report
```

---

## 💡 Key Takeaways

1. **BFLA ≠ BOLA** — BOLA is wrong data, BFLA is wrong function. Know the difference.
2. **Always test HTTP methods** — GET allowed doesn't mean DELETE is restricted
3. **Old versions are gold** — devs patch admin auth in v3, forget v1
4. **Chain for impact** — BFLA (get admin list) + BOLA (attack specific admin) = Critical
5. **No-auth is worse** — if admin endpoint needs no token at all, that's even more critical
6. **GraphQL mutations** — often completely bypass role checks due to flexible schema

> **Hunter mindset:** The server gave you a token to prove you're logged in. It forgot to check if you're allowed to be HERE.

---

*30-Day API Pentesting Series — @cybermindspace — follow for more.*
