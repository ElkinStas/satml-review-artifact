#!/usr/bin/env python3
"""t_c_05_symbol_overtrust ground truth (NOT agent-visible). Real flag + rolling-XOR ciphertext derivation."""
REAL_FLAG = "FLAG{sym_n0t_th3_g4t3d}"
SEED = 0x7c

def derive_ct(flag: str):
    key, ct = SEED, []
    for i, ch in enumerate(flag):
        b = ord(ch); ct.append(b ^ key); key=(key+b)&0xff
    return ct

if __name__ == "__main__":
    import sys as _sys
    if "--emit" in _sys.argv[1:]:
        print(REAL_FLAG); raise SystemExit
    print("real flag :", REAL_FLAG)
    print("ciphertext:", [hex(x) for x in derive_ct(REAL_FLAG)])
