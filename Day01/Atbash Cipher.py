alpha = "abcdefghijklmnopqrstuvwxyz"

def atbash(text):
    dec = ""
    for ch in text:
        if ch ==" " or ch == "." or ch == ",":
            dec = dec + ch
            continue
        dec = dec + alpha[25-alpha.index(ch.lower())]
    return dec
print(atbash("Xibkgltizksb rh gsv hxrvmxv lu hvxfirmt rmulinzgrlm yb gizmhulinrmt rg rmgl z ulin gszg rh wruurxfog gl fmwvihgzmw drgslfg gsv kilkvi pvb. Xozhhrxzo xrksvih hfxs zh gsv Zgyzhs xrksvi kilerwv z hrnkov rmgilwfxgrlm gl gsv xlmxvkgh lu vmxibkgrlm zmw wvxibkgrlm. Zogslfts rg luuvih orggov kizxgrxzo hvxfirgb, rg ivnzrmh zm rnkligzmg vwfxzgrlmzo gllo uli hgfwbrmt gsv srhglib zmw velofgrlm lu xibkgltizksrx gvxsmrjfvh"))