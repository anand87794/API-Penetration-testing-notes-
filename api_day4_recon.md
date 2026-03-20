# API Recon: How to Find Hidden Endpoints Before Attacking

> **Series:** 30-Day API Pentesting  
> **Day:** 4 — Week 1: API Fundamentals & Recon  
> **Topic:** API Recon Methodology Flow Diagram

---

## The 6-Step API Recon Flow

```
Step 01 → Passive Discovery      (zero touch)
Step 02 → Subdomain Enumeration  (find all API surfaces)
Step 03 → Endpoint Discovery     (find every route)
Step 04 → Traffic Interception   (capture real API calls)
Step 05 → JavaScript Analysis    (mine JS for hidden routes)
Step 06 → API Fingerprinting     (know what you're attacking)
```

---

## Step 01 — Passive Discovery

```bash
# Shodan — find exposed API servers
shodan search "hostname:target.com"
shodan search 'org:"Target Inc" http.title:api'
shodan search 'ssl.cert.subject.cn:target.com port:8443'

# crt.sh — SSL certificate transparency
curl -s "https://crt.sh/?q=%.target.com&output=json" \
  | jq '.[].name_value' | tr -d '"' | sort -u > subdomains.txt

# Google Dorks
site:target.com inurl:api
site:target.com inurl:/v1/ OR inurl:/v2/ OR inurl:/v3/
site:target.com filetype:json
site:target.com "api_key" OR "apikey"

# Wayback Machine — historical endpoints
gau target.com | grep -E 'api|v[0-9]' | sort -u
waybackurls target.com | grep api
curl "https://web.archive.org/cdx/search/cdx?url=target.com/api/*&output=text&fl=original&collapse=urlkey"

# GitHub — leaked API endpoints and keys
site:github.com "target.com" api
site:github.com "target.com" "api_key" OR "apikey" OR "secret"
trufflehog github --org=targetorg
```

---

## Step 02 — Subdomain Enumeration

```bash
# Passive enum — no DNS queries to target
subfinder -d target.com -silent -o subs.txt
amass enum -passive -d target.com -silent >> subs.txt
sort -u subs.txt -o subs.txt

# Check which subdomains are live + have APIs
cat subs.txt | httpx -silent -path /api/v1 -mc 200,401,403 -o live_api.txt
cat subs.txt | httpx -silent -path /swagger.json -mc 200 -o swagger_found.txt

# DNS brute force for API-specific subdomains
dnsx -d target.com -w api-subdomains.txt
# Wordlist: api, api1, api2, dev-api, staging-api, internal-api, beta-api

# Check for wildcards
dig *.target.com
# If wildcard exists → focus on content-based filtering

# Interesting subdomain patterns to look for:
# api.target.com, api2.target.com, api-v2.target.com
# dev.target.com, staging.target.com, beta.target.com
# internal.target.com, admin-api.target.com
# mobile-api.target.com, m.target.com
```

---

## Step 03 — Endpoint Discovery

```bash
# Check for API documentation first (jackpot if found)
for path in swagger swagger.json swagger.yaml api-docs openapi.json \
            openapi.yaml v1/docs v2/docs graphql graphiql playground \
            .well-known/openid-configuration redoc docs; do
  curl -s -o /dev/null -w "$path: %{http_code}\n" https://target.com/$path
done

# ffuf — fuzz for API endpoints
ffuf -u https://target.com/api/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
  -mc 200,201,401,403 \
  -o endpoints.json

# API version enumeration
for v in v1 v2 v3 v4 beta alpha dev internal; do
  curl -s -o /dev/null -w "/$v: %{http_code}\n" https://target.com/api/$v/users
done

# gobuster — directory enumeration
gobuster dir -u https://target.com/api \
  -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
  -x json,xml -t 30

# Recursive discovery with feroxbuster
feroxbuster -u https://target.com/api \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt \
  --filter-status 404 -d 3
```

---

## Step 04 — Traffic Interception

```bash
# Burp Suite setup:
# 1. Proxy → Options → Add listener 127.0.0.1:8080
# 2. Browser → Proxy settings → 127.0.0.1:8080
# 3. Browse entire app normally
# 4. Every API call captured in Proxy → HTTP History
# 5. Filter by: /api/ to see only API traffic

# Mobile app interception:
# 1. Device → WiFi settings → Manual proxy → Burp IP:8080
# 2. Install Burp CA certificate on device
# 3. Use app normally → all API calls captured
# 4. For SSL pinning bypass: Frida + ssl-kill-switch2

# Chrome DevTools approach:
# F12 → Network tab → Filter: Fetch/XHR
# Use app → all API calls visible with full request/response

# Export captured endpoints
# Burp → Target → Site Map → Right click → Copy URLs in this host
# Or use Burp extension: Logger++, Turbo Intruder

# Capture mobile API with mitmproxy
mitmproxy --mode transparent --listen-port 8080
```

---

## Step 05 — JavaScript Analysis

```bash
# LinkFinder — extract endpoints from JS files
git clone https://github.com/GerbenJavado/LinkFinder
pip3 install jsbeautifier

# Single JS file
python3 linkfinder.py -i https://target.com/static/app.js -o cli

# All JS files on domain
python3 linkfinder.py -i https://target.com -d -o results.html

# Manual grep approach
curl -s https://target.com/app.js | grep -oE '"/api/[^"]*"' | sort -u
curl -s https://target.com/app.js | grep -oE "'(v[0-9]|api)[^']*'" | sort -u

# Find all JS files first
gau target.com | grep "\.js$" | sort -u > js_files.txt

# Download and analyze each
while read url; do
  curl -s "$url" | grep -oE '("|'"'"')/api/[^"'"'"']+' | tr -d '"'"'"
done < js_files.txt | sort -u

# Look for:
# API base URLs: "https://api.target.com"
# Endpoints: "/api/v1/users", "/admin/delete"
# Keys: "api_key", "apiKey", "API_KEY", "secret"
# Internal IPs: "http://10.0.0.1", "http://192.168."
```

---

## Step 06 — API Fingerprinting

```bash
# Technology detection
whatweb https://target.com/api/v1/users
whatweb -v https://target.com  # verbose

# HTTP headers analysis
curl -I https://target.com/api/v1/
# Look for:
# Server: nginx/1.14.0       → check nginx CVEs
# X-Powered-By: Express      → Node.js/Express backend
# X-Powered-By: PHP/7.4.3    → PHP 7.4 → check CVEs
# X-Framework: Laravel        → Laravel-specific attacks
# X-RateLimit-Limit: 100      → rate limit present

# Error-based fingerprinting
curl https://target.com/api/v1/notexist
# Django: "DoesNotExist: User matching query does not exist"
# Laravel: "Illuminate\Database\Eloquent\ModelNotFoundException"
# Express: "Cannot GET /api/v1/notexist"
# Flask: "404 Not Found: The requested URL was not found"

# WAF detection
wafw00f https://target.com
# Know the WAF → research bypass techniques

# Framework-specific paths to test after fingerprinting:
# Laravel: /telescope, /horizon, /debugbar
# Django: /django-admin, /admin
# Rails: /rails/info, /sidekiq
# Spring: /actuator, /actuator/env, /actuator/beans
# Express: /__express__, stack traces on errors
```

---

## Complete Recon Script

```bash
#!/bin/bash
TARGET=$1
echo "[*] Starting API recon for $TARGET"

# Passive
echo "[1] Passive discovery..."
subfinder -d $TARGET -silent | tee subs.txt
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | jq -r '.[].name_value' >> subs.txt
sort -u subs.txt -o subs.txt
echo "    Found $(wc -l < subs.txt) subdomains"

# Live check
echo "[2] Checking live hosts..."
cat subs.txt | httpx -silent -status-code -title -o live.txt

# API docs check
echo "[3] Checking API documentation..."
for sub in $(awk '{print $1}' live.txt); do
  for path in swagger.json api-docs openapi.json graphql; do
    code=$(curl -s -o /dev/null -w "%{http_code}" $sub/$path)
    [ "$code" = "200" ] && echo "    FOUND: $sub/$path"
  done
done

# JS analysis
echo "[4] Extracting JS endpoints..."
gau $TARGET | grep "\.js$" | head -20 | while read url; do
  curl -s "$url" | grep -oE '"/api/[^"]*"' | tr -d '"'
done | sort -u | tee js_endpoints.txt

echo "[+] Done! Check: subs.txt, live.txt, js_endpoints.txt"
```

---

## Checklist

```
☐  crt.sh first — %.target.com reveals all subdomains passively
☐  Check /swagger /api-docs /openapi.json on every subdomain
☐  Run app with Burp proxy — capture every hidden API call
☐  Mine every JS bundle with LinkFinder
☐  WAF/CDN fingerprint — wafw00f before attacking
☐  Version every service — whatweb + error responses → CVEs
☐  Check Wayback Machine — gau + waybackurls for historical endpoints
☐  Version enumerate — /api/v1 /v2 /v3 /beta /internal
```

---

*30-Day API Pentesting Series — follow for more.*
