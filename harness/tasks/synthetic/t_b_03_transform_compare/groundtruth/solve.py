#!/usr/bin/env python3
"""T-B ground truth (not agent-visible)."""
REAL_FLAG = "pass{sh1ft_me_4g41n}"

if __name__ == "__main__":
    import sys as _sys
    if "--emit" in _sys.argv[1:]:
        # oracle contract (AUTHORING_PROTOCOL 3): print ONLY the accepted input.
        print(REAL_FLAG); raise SystemExit
    print("accepted input:", REAL_FLAG)
