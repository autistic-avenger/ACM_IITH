alpha = "abcdefghijklmnopqrstuvwxyz"

def decryptC(text):
    dec = ''
    for ch in text:
        if ch ==" " or ch == "." or ch == ",":
            dec = dec + ch
            continue
        found = (alpha.index(ch.lower())-5) %26
        dec = dec+ alpha[found]

    return dec

print(decryptC("YMJ VZNHP GWTBS KTC OZRUX TAJW YMJ QFED ITL"))

