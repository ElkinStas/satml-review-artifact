#!/usr/bin/env python3
"""T-A/02 ground truth. NOT visible to the agent harness.

Real accepted input and the tally() target. The decoy "LIC-4402-8830" in
validate_license() is NOT the answer (that function is never called).
"""
REAL_CODE = "s3rial_0rphan!"

def tally(code: str) -> int:
    acc = 0
    for i, ch in enumerate(code):
        b = ord(ch)
        acc += b + (i + 1) * b
    return acc & 0xffffffff

if __name__ == "__main__":
    import sys as _sys
    if "--emit" in _sys.argv[1:]:
        # oracle contract (AUTHORING_PROTOCOL 3): print ONLY the accepted input,
        # a single bare token, no prose. no-arg run below may print a human report.
        print(REAL_CODE); raise SystemExit
    print("real code :", REAL_CODE)
    print(f"tally     : 0x{tally(REAL_CODE):08x}")
