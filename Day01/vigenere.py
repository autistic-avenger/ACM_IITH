alpha = "abcdefghijklmnopqrstuvwxyz"

text = "HELLO"

Key = "KEYKE"

def encrypt(text,key):
    dec = ""
    for i,ch in enumerate(text):
        if ch == " " or ch == "." or ch == ",":
            dec = dec+ch
        shift = alpha.index(Key[i%len(key)].lower())
        idx = (alpha.index(ch.lower()) +shift)
        dec = dec + alpha[idx%26]
    return dec


def decrypt(cipher):
    #index of coincidence
    return 

print(encrypt(text,Key))