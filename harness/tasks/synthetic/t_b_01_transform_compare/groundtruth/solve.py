#!/usr/bin/env python3
"""T-B ground truth. NOT visible to the agent."""
REAL_FLAG = "FLAG{tr4nsf0rm_th3_1nput}"
if __name__ == "__main__":
    import sys as _sys
    if "--emit" in _sys.argv[1:]:
        # oracle contract (AUTHORING_PROTOCOL 3): print ONLY the accepted input,
        # a single bare token, no prose. no-arg run below may print a human report.
        print(REAL_FLAG); raise SystemExit
    print("real flag:", REAL_FLAG)
