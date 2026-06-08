alpha = "abcdefghijklmnopqrstuvwxyz"

def decryptC(text):
    dec = ''
    for ch in text:
        if ch ==" " or ch == "." or ch == ",":
            dec = dec + ch
            continue
        found = (alpha.index(ch.lower())-3) %26
        dec = dec+ alpha[found]
    return dec

print(decryptC("Fdhvdu flskhu lv rqh ri wkh hduolhvw dqg vlpsohvw phwkrgv ri hqfubswlrq. Lw zrunv eb vkliwlqj hdfk ohwwhu lq wkh sodlqwhaw eB d ilahg qxpehu ri srvlwlrqv lq wkh doskdehw. Dowkrxjk lw lv hdvb wr lpsohphqw, lw surylghv yhub olwwoh vhfxulwb djdlqvw prghuq fubswdqdobvlv whfkqltxhv. Qhyhuwkhohvv, lw uhpdlqv d xvhixo hgxfdwlrqdo wrro iru xqghuvwdqglqj wkh edvlf frqfhswv ri fodvvlfdo fubswrjudskb"))

