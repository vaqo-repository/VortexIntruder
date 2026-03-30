import json, re, sys

JS_FILE = r'c:/Users/Vaqif/AppData/Roaming/Code/User/workspaceStorage/90328434d3cbcc3f09357d5fbbcf3b81/GitHub.copilot-chat/chat-session-resources/208d5361-4c76-4408-8815-9c36de6ef239/toolu_bdrk_01VGH46npnhD9wzNuwP7CUzM__vscode-1774509285518/content.json'

with open(JS_FILE) as fh:
    js = json.load(fh)['result']

print('=== ALL UNIQUE API ENDPOINTS ===')
apis = sorted(set(re.findall(r'["\x27](/api/[a-zA-Z0-9/_\-?=&.:]{3,120})["\x27`]', js)))
for a in apis:
    print(a)
print(f'\nTotal: {len(apis)}')

print('\n=== AUTH/USER/ADMIN ENDPOINTS ===')
auth_kw = r'(?:auth|login|logout|account|admin|register|otp|password|token|session|profile|verify|signup|signin|2fa|mfa|reset)'
auth = sorted(set(re.findall(r'["\x27](/api/[^"\x27 \n]{0,120}' + auth_kw + r'[^"\x27 \n]{0,60})["\x27`]', js, re.I)))
auth2 = sorted(set(re.findall(r'["\x27](/api/' + auth_kw + r'[^"\x27 \n]{0,80})["\x27`]', js, re.I)))
combined = sorted(set(auth + auth2))
for a in combined:
    print(a)

print('\n=== ENVIRONMENT VARIABLES ===')
envs = sorted(set(re.findall(r'REACT_APP_[A-Z_]+', js)))
for e in envs:
    print(e)

print('\n=== reCAPTCHA SITE KEYS ===')
for k in sorted(set(re.findall(r'6Le[A-Za-z0-9_\-]{30,50}', js))):
    print(k)

print('\n=== FIREBASE CONFIG ===')
patterns = [
    r'"apiKey"\s*:\s*"([^"]+)"',
    r'"projectId"\s*:\s*"([^"]+)"',
    r'"storageBucket"\s*:\s*"([^"]+)"',
    r'"messagingSenderId"\s*:\s*"([^"]+)"',
    r'"appId"\s*:\s*"([^"]+)"',
    r'"measurementId"\s*:\s*"([^"]+)"',
    r'"databaseURL"\s*:\s*"([^"]+)"',
    r'"authDomain"\s*:\s*"([^"]+)"',
]
for p in patterns:
    for m in sorted(set(re.findall(p, js))):
        key = p.split('"')[1]
        print(f'{key}: {m}')

print('\n=== HARDCODED EXTERNAL URLS ===')
urls = sorted(set(re.findall(r'https?://[a-zA-Z0-9._\-]+(?:\.az|\.com|\.net|\.io|\.org)[a-zA-Z0-9/._\-?=&%]{0,80}', js)))
for u in urls[:40]:
    print(u)

print('\n=== POTENTIAL SECRETS (key=value patterns) ===')
secrets = sorted(set(re.findall(r'(?:apiKey|api_key|secret|password|privateKey|client_secret)\s*[=:]\s*["\x27]([a-zA-Z0-9_\-\.]{16,100})["\x27]', js, re.I)))
for s in secrets[:20]:
    print(s)

print('\n=== PAYMENT ENDPOINTS ===')
pay = sorted(set(re.findall(r'["\x27](/api/[^"\x27 ]{0,80}(?:payment|pay|checkout|order|cart|invoice)[^"\x27 ]{0,40})["\x27`]', js, re.I)))
for p in pay:
    print(p)
