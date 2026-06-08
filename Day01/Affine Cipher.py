alpha = "abcdefghijklmnopqrstuvwxyz"
# ax + b % 26
# ((y-b) * a^-1) %26

def encrypt(plain,a,b):
    dec  = ""
    for ch in plain:
        if ch ==" " or ch == "." or ch == ",":
            dec = dec + ch
            continue
        idx = a * (alpha.index(ch.lower())) + b
        dec = dec+ alpha[(idx%26)]
    return dec 
print(encrypt("HELLO",5,8))

def decrypt(cipher,a,b):
    dec = ""
    for ch in cipher:
        if ch ==" " or ch == "." or ch == ",":
            dec = dec + ch
            continue
        idx = (alpha.index(ch.lower())-b)*(26-a)
        dec = dec + alpha[(idx)%26]
    return dec
print(decrypt("rclla",5,8))