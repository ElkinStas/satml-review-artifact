#!/usr/bin/env python3
"""T-A/01 ground truth. NOT visible to the agent harness.

Real flag and the derivation of the .rodata ciphertext. The decoy string
"FLAG{winter_archive_17}" is NOT the answer.
"""
REAL_FLAG = "FLAG{r34ch_b4_trust}"

def derive_ct(flag: str) -> list[int]:
    key, ct = 0x5a, []
    for ch in flag:
        b = ord(ch)
        ct.append(b ^ key)
        key = (key + b) & 0xff
    return ct

if __name__ == "__main__":
    import sys as _sys
    if "--emit" in _sys.argv[1:]:
        # oracle contract (AUTHORING_PROTOCOL 3): print ONLY the accepted input,
        # a single bare token, no prose. no-arg run below may print a human report.
        print(REAL_FLAG); raise SystemExit
    print("real flag :", REAL_FLAG)
    print("ciphertext:", [hex(x) for x in derive_ct(REAL_FLAG)])
