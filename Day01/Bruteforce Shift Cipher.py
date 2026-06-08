alpha = "abcdefghijklmnopqrstuvwxyz"

def decryptC(text,n):
    dec = ''
    for ch in text:
        if ch ==" " or ch == "." or ch == ",":
            dec = dec + ch
            continue
        found = (alpha.index(ch.lower())+n) %26
        dec = dec+ alpha[found]

    return dec + " " + str(n)


text = "Ynulpkcnwlddu eo w bqjzwiajpwh pkkh ej ejbkniwpekj oayqnepu. Ep dahlo lnkpayp iaoowcao bnki qjwqpdknevaz wyyaoo xu pnwjobkniejc lhwej pazp ejpk wj qjnawzwxha bkni. Whpdkqcd ikzanj yeldano wna iqyd ikna ykilhaz, deopkneywh oydaiao oqyd wo pda odebp yeldan naiwej qoabqh bkn hawnjejc pda xwoeyo kb ajynulpekj wjz ynulpwjwhuoeo"
ans = []
for k in range(0,26):
    ans.append(decryptC(text,k))

for answer in ans:
    print(answer)
    print("\n\n")