#!/usr/bin/env python3
# Scrambles a detection pattern for agent/scan.go sig(): python3 scripts/sig.py 'pattern'
import sys
k = b"sudowhizzy"
print(bytes(c ^ k[i % len(k)] for i, c in enumerate(sys.argv[1].encode())).hex())
