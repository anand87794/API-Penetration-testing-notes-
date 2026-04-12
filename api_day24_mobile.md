# Mobile API Security: Extracting Secrets from APKs & Bypassing SSL Pinning

> **Series:** 30-Day API Pentesting | **Day 24** | Week 4: Advanced Attacks  
> **Difficulty:** Intermediate  
> **Topic:** Mobile API Security — APK Recon, SSL Pinning Bypass, Secret Extraction

---

## Why Mobile APIs Are a Different Beast

Every vulnerability we've covered so far — BOLA, BFLA, injection, race conditions — applies to mobile apps too. But mobile adds a completely unique attack surface: **the binary ships with the keys**.

When a developer builds a mobile app, they compile everything — API keys, endpoint URLs, debug tokens, internal addresses — into a binary distributed to millions of devices. Every device now holds the company's internal API map.

```
What an APK gives you that web doesn't:
  API keys hardcoded in source (sk_live_xxx, AKIA..., Firebase keys)
  Mobile-only API endpoints never linked from web
  Debug endpoints left in production builds
  Third-party credentials (Stripe, Twilio, AWS)
  Authentication logic — HOW tokens are generated/validated
  SSL pinning implementation — so you can bypass it
```

---

## Part 1: Getting and Extracting the APK

```bash
# Connect Android device via USB, enable USB debugging
adb devices  # should show device

# Find package name
adb shell pm list packages | grep target

# Get path and pull APK
adb shell pm path com.target.app
adb pull /data/app/com.target.app-1/base.apk ./target.apk

# APK = ZIP file — extract directly
unzip target.apk -d apk_extracted/

# Key files inside:
# AndroidManifest.xml       → permissions, exported components, deep links
# classes.dex               → compiled Java code (needs jadx to read)
# assets/index.android.bundle → React Native JS (goldmine of endpoints)
# res/values/strings.xml    → API URLs, environment config
# lib/                      → native .so libraries
```

---

## Part 2: Static Analysis — Mining for Secrets

### Decompile with jadx

```bash
# Install jadx from https://github.com/skylot/jadx/releases
jadx -d ./output/ target.apk
# Converts .dex bytecode → readable Java source code

# Key files to check first:
# output/com/target/app/BuildConfig.java   → env flags, debug mode
# output/com/target/app/Config.java        → API keys, base URLs
# output/com/target/app/api/ApiClient.java → base URL + auth logic
# output/com/target/app/api/AuthInterceptor.java → token injection
```

### Grep Everything for Secrets

```bash
# API keys and credentials
grep -r "api_key\|api_secret\|apiKey" output/ --include="*.java"
grep -r "password\|PASSWORD" output/ --include="*.java" | grep '= "'
grep -r "secret\|SECRET" output/ --include="*.java" | grep '= "'

# Cloud provider keys
grep -r "AKIA" output/ -r       # AWS access key prefix
grep -r "sk_live\|pk_live" output/ -r  # Stripe
grep -r "AC[0-9a-f]{32}" output/ -r   # Twilio

# Firebase config (often in strings.xml or google-services.json)
cat apk_extracted/res/values/strings.xml | grep -i "firebase\|google\|api_key"

# Internal network addresses
grep -r "http://10\.\|http://192\.168\." output/ -r
grep -r "\.internal\|\.corp\|localhost" output/ -r
```

### Extract All API Endpoints

```bash
# Fast — no decompilation needed
strings target.apk | grep -E "https?://[a-zA-Z0-9./_-]+" | sort -u > all_urls.txt
grep -E "/api/|/v[0-9]+/|/graphql" all_urls.txt

# React Native apps — full JS bundle
unzip target.apk "assets/index.android.bundle" -d ./rn/
grep -oE "https?://[^\"'\`]+" rn/assets/index.android.bundle | sort -u
grep -E "\"/api/[a-zA-Z0-9/{}_-]+\"" rn/assets/index.android.bundle | sort -u
```

### AndroidManifest Security Checks

```bash
cat apk_extracted/AndroidManifest.xml | grep -E \
    "exported|allowBackup|debuggable|cleartext|scheme"

# BUGS TO FLAG:
# android:exported="true" on Activity/Service  → any app can call it
# android:allowBackup="true"                  → adb backup leaks all app data
# android:debuggable="true"                   → attacker can attach debugger
# android:usesCleartextTraffic="true"         → app sends HTTP (not HTTPS)
```

---

## Part 3: Bypassing SSL Pinning

### What is SSL Pinning?

```
Without pinning:
  App → validates Burp cert → Burp CA is trusted → traffic visible ✓

With pinning:
  App → checks cert fingerprint → "Not api.target.com's real cert!" → REFUSED ✗
```

### Method 1: objection (Easiest, No Root Required)

```bash
# Install objection
pip3 install objection

# Patch the APK to embed Frida gadget
objection patchapk --source target.apk
# Creates: target.objection.apk

# Install patched APK on device
adb install target.objection.apk

# Connect to running app
objection -g com.target.app explore

# Inside objection → disable all SSL pinning
android sslpinning disable

# Configure Android WiFi proxy → 192.168.x.x:8080 → Burp sees all traffic!
```

### Method 2: Frida Script

```bash
# Push Frida server to device
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# ssl_unpin.js — bypasses OkHttp + TrustManager pinning
cat > ssl_unpin.js << 'EOF'
Java.perform(function() {
    // Bypass OkHttp CertificatePinner (most common)
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload("java.lang.String","java.util.List").implementation
            = function(str, list) {
                console.log("[SSL] Bypassed OkHttp pin for: " + str);
            };
    } catch(e) {}

    // Bypass X509TrustManager
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(a,b,c,d,e,f) {
            return a;
        };
    } catch(e) {}

    console.log("[SSL] Pinning disabled — route traffic through Burp!");
});
EOF

# Attach to running app
frida -U -l ssl_unpin.js com.target.app
```

---

## Part 4: Intercepting and Testing Mobile API Traffic

### Burp Setup for Android

```bash
# 1. Burp → Proxy → Options → Add listener: 0.0.0.0:8080
# 2. Install Burp CA on Android device
#    → Burp → Proxy → Options → Export CA cert → save as .crt
#    → adb push burp_ca.crt /sdcard/
#    → Android Settings → Security → Install certificate
# 3. Android WiFi settings → Manual proxy → YOUR_IP:8080
# 4. Browse app → traffic flows through Burp
```

### What to Look For in Captured Traffic

```bash
# 1. Mobile-only endpoints (not in web Swagger docs)
# GET /api/mobile/admin
# GET /api/internal/config
# POST /api/app/debug

# 2. Weaker rate limiting on mobile auth
# /api/login via mobile → no 429 after 100 requests

# 3. Missing CSRF tokens
# Mobile POST requests often skip CSRF

# 4. Device-ID based authentication
X-Device-ID: abc123  # → can you use someone else's device ID?

# 5. Version-based feature gates
X-App-Version: 1.0   # → older version skips security checks?

# Test by spoofing headers in Burp Repeater:
# Change User-Agent to: TargetApp/2.1 (Android 13; Pixel 7)
# Add: X-Platform: android, X-App-Version: 2.1
# → Some endpoints respond differently or become accessible
```

### User-Agent Spoofing Without a Device

```bash
# Find correct User-Agent from APK
grep -r "User-Agent\|userAgent" output/ --include="*.java" | head -10

# Test from curl — no Android device needed
curl https://api.target.com/api/v1/users \
    -H "Authorization: Bearer TOKEN" \
    -H "User-Agent: TargetApp/3.2.1 (Android 13; Pixel 7)" \
    -H "X-Platform: android" \
    -H "X-App-Version: 3.2.1"

# Compare with web user-agent — different behavior? More data? New endpoints?
# Try every mobile-only URL discovered from APK strings
```

---

## Part 5: Insecure Local Data Storage

### SharedPreferences — Plaintext Token Storage

```bash
# With adb shell (root or debuggable app):
adb shell cat /data/data/com.target.app/shared_prefs/*.xml

# Common findings:
# <string name="auth_token">Bearer eyJhbGciOiJIUzI1NiJ9...</string>
# <string name="user_id">1337</string>
# <string name="user_email">admin@target.com</string>

# Without root — if allowBackup=true:
adb backup -f backup.ab com.target.app
# Convert to tar → inspect XML files for stored tokens
```

### SQLite Databases

```bash
# Pull all databases from app
adb pull /data/data/com.target.app/databases/ ./db_dump/

# Read with sqlite3
sqlite3 db_dump/app.db
.tables
SELECT * FROM sessions;
SELECT * FROM cached_data;    # often stores full API responses with PII
SELECT * FROM credentials;    # some apps cache passwords!
```

### Logcat — Debug Logs Leaking Secrets

```bash
# Real-time log capture
adb logcat | grep -iE "token|password|auth|secret|api_key"

# Dump and analyze
adb logcat -d > all_logs.txt
grep -iE "token|password|auth|secret" all_logs.txt

# Common findings in debug builds:
# D/Auth: Login: user=admin@target.com pass=Password123
# D/Network: Request: GET /api/user?access_token=abc123
# D/Database: Executing: SELECT * FROM users WHERE password='cleartext'
```

---

## Checklist

```
☐  Get APK — adb pull or APKPure, no device needed for static analysis
☐  Decompile with jadx — jadx -d output/ target.apk → readable Java
☐  Grep for API keys — grep -r 'api_key\|AKIA\|sk_live\|secret' output/
☐  Extract all URLs — strings target.apk | grep 'https://' | sort -u
☐  Check AndroidManifest — exported=true, allowBackup, debuggable flags
☐  Bypass SSL pinning — objection: android sslpinning disable
☐  Set up Burp proxy — intercept ALL mobile API traffic
☐  Test mobile-only endpoints — URLs from APK not in web Swagger docs
☐  Spoof User-Agent — TargetApp/2.1 Android/13 → different behavior?
☐  Check local storage — SharedPrefs, SQLite, logcat for plaintext secrets
```

---

*Written by @anand87794*  
*30-Day API Pentesting Series — Day 24 of 30*
