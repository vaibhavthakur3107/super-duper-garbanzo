#!/usr/bin/env python3
import hashlib
import base64
import json
import struct
import zlib
import itertools

# Target hashes
MASTER_KEY_HASH = "520f338cfd46a7619e13c517192b3dd2"
GHOST_KEY_HASH = "d8a00486e0fe98ae86c126cacf61afb5"

# Generate comprehensive wordlist
def generate_wordlist():
    base_words = [
        'phantom', 'ph4nt0m', 'PH4NT0M', 'PHANTOM',
        'ghost', 'GH0ST', 'GHOST', 'gh0st',
        'master', 'M4STER', 'M4ST3R', 'MASTER', 'm4ster', 'm4st3r',
        'key', 'KEY', 'K3Y', 'k3y',
        'secret', 'SECRET', 'S3CR3T', 's3cr3t',
        'root', 'ROOT', 'R00T', 'r00t',
        'password', 'PASSWORD', 'P4SSW0RD', 'p4ssw0rd',
        'tricky', 'TRICKY', 'TR1CKY', 'tr1cky',
        'happy', 'HAPPY', 'H4PPY', 'h4ppy',
        'full', 'FULL', 'FU11', 'fu11',
        'find', 'FIND', 'F1ND', 'f1nd',
        'the', 'THE', 'TH3', 'th3',
    ]
    
    wordlist = set(base_words)
    
    # Two-word combinations
    for w1, w2 in itertools.product(base_words[:20], base_words[:20]):
        if w1 != w2:
            wordlist.add(f"{w1}{w2}")
            wordlist.add(f"{w1}_{w2}")
            wordlist.add(f"{w1}-{w2}")
            wordlist.add(f"{w1}{w2}".upper())
            wordlist.add(f"{w1}_{w2}".upper())
    
    return wordlist

def crack_hash(target_hash, wordlist):
    for word in wordlist:
        if hashlib.md5(word.encode()).hexdigest() == target_hash:
            return word
    return None

print("Generating wordlist...")
wordlist = generate_wordlist()
print(f"Generated {len(wordlist)} words")

print("\nCracking MASTER_KEY...")
master_key = crack_hash(MASTER_KEY_HASH, wordlist)
if master_key:
    print(f"✓ MASTER_KEY found: {master_key}")
else:
    print("✗ MASTER_KEY not found in wordlist")
    master_key = "PLACEHOLDER_MASTER"  # Use placeholder to continue

print("\nCracking GHOST_KEY...")
ghost_key = crack_hash(GHOST_KEY_HASH, wordlist)
if ghost_key:
    print(f"✓ GHOST_KEY found: {ghost_key}")
else:
    print("✗ GHOST_KEY not found in wordlist")
    ghost_key = "PLACEHOLDER_GHOST"  # Use placeholder to continue

print(f"\nUsing keys:")
print(f"  MASTER: {master_key}")
print(f"  GHOST: {ghost_key}")
