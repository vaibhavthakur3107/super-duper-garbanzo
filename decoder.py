#!/usr/bin/env python3
"""
Silent Prompt Injection - Automated Decoder
Attempts various cipher methods to decode the reward string
"""

import string
import base64
from itertools import cycle

# The encoded reward string from the JavaScript
ENCODED = "l5VKR[9`b1/4axikt52,e>.{N#K3u*KUL)sf&kASAJ!/%NKUPGKb@,ESc!m/LvBRDJab,fP1G$X%i9tout0=|<}YA1Z%`8{i2a/2b"


def xor_single_byte(data, key):
    """XOR with a single byte key"""
    return ''.join(chr(ord(c) ^ key) for c in data)


def xor_multi_byte(data, key):
    """XOR with a multi-byte repeating key"""
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, cycle(key)))


def caesar_shift(text, shift):
    """Apply Caesar cipher shift to alphabetic characters"""
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr((ord(char) - 65 + shift) % 26 + 65)
            else:
                result += chr((ord(char) - 97 + shift) % 26 + 97)
        else:
            result += char
    return result


def rot47(text):
    """Apply ROT47 cipher (printable ASCII rotation)"""
    result = ""
    for char in text:
        if 33 <= ord(char) <= 126:
            result += chr(33 + ((ord(char) + 14) % 94))
        else:
            result += char
    return result


def vigenere_decode(text, key):
    """Decode using Vigenère cipher"""
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            key_char = key[key_index % len(key)]
            if char.islower():
                base = ord('a')
                result += chr((ord(char) - base - (ord(key_char.upper()) - ord('A'))) % 26 + base)
            else:
                base = ord('A')
                result += chr((ord(char) - base - (ord(key_char.upper()) - ord('A'))) % 26 + base)
            key_index += 1
        else:
            result += char
    return result


def atbash(text):
    """Apply Atbash cipher (reverse alphabet)"""
    result = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                result += chr(ord('z') - (ord(char) - ord('a')))
            else:
                result += chr(ord('Z') - (ord(char) - ord('A')))
        else:
            result += char
    return result


def is_printable(text, threshold=0.9):
    """Check if text is mostly printable ASCII"""
    printable_count = sum(1 for c in text if 32 <= ord(c) <= 126)
    return (printable_count / len(text)) >= threshold


def contains_flag(text):
    """Check if text contains FLAG{ pattern"""
    clean = ''.join(c if 32 <= ord(c) <= 126 else '' for c in text)
    return "FLAG{" in clean


def main():
    print("=" * 70)
    print("Silent Prompt Injection - Automated Decoder")
    print("=" * 70)
    print(f"\nEncoded string: {ENCODED}")
    print(f"Length: {len(ENCODED)} characters\n")
    
    # Try single-byte XOR
    print("\n[1] Testing Single-Byte XOR (0-255)...")
    for key in range(256):
        result = xor_single_byte(ENCODED, key)
        if contains_flag(result) and is_printable(result, 0.7):
            print(f"    ✓ KEY {key} (0x{key:02x}): {result}")
    
    # Try common multi-byte XOR keys
    print("\n[2] Testing Multi-Byte XOR with Common Keys...")
    test_keys = [
        "SCORPIO", "HIGHWAY", "RUNNER", "FLAG", "KEY", "PASSWORD", 
        "SECRET", "91", "SCORPIO91", "HIGHWAY91", "MAHINDRA"
    ]
    for key in test_keys:
        result = xor_multi_byte(ENCODED, key)
        if contains_flag(result):
            clean = ''.join(c if 32 <= ord(c) <= 126 else '?' for c in result)
            print(f"    ✓ KEY '{key}': {clean}")
    
    # Try Caesar shifts
    print("\n[3] Testing Caesar Shifts (0-25)...")
    for shift in range(26):
        result = caesar_shift(ENCODED, shift)
        if contains_flag(result):
            print(f"    ✓ SHIFT {shift}: {result}")
    
    # Try ROT47
    print("\n[4] Testing ROT47...")
    result = rot47(ENCODED)
    if contains_flag(result):
        print(f"    ✓ {result}")
    
    # Try Vigenère with keywords
    print("\n[5] Testing Vigenère Cipher...")
    for key in ["SCORPIO", "HIGHWAY", "RUNNER", "MAHINDRA"]:
        result = vigenere_decode(ENCODED, key)
        if contains_flag(result):
            print(f"    ✓ KEY '{key}': {result}")
    
    # Try Atbash
    print("\n[6] Testing Atbash...")
    result = atbash(ENCODED)
    if contains_flag(result):
        print(f"    ✓ {result}")
    
    # Try reverse
    print("\n[7] Testing Reverse...")
    result = ENCODED[::-1]
    if contains_flag(result):
        print(f"    ✓ {result}")
    
    # Show XOR key pattern for FLAG{
    print("\n[8] XOR Key Analysis (assuming plaintext starts with 'FLAG{')...")
    target = "FLAG{"
    keys = [ord(ENCODED[i]) ^ ord(target[i]) for i in range(min(5, len(ENCODED)))]
    print(f"    Key bytes: {keys}")
    print(f"    Key chars: {[chr(k) if 32 <= k <= 126 else f'[{k}]' for k in keys]}")
    
    # Try this derived key as repeating pattern
    result = ''.join(chr(ord(ENCODED[i]) ^ keys[i % len(keys)]) for i in range(len(ENCODED)))
    clean = ''.join(c if 32 <= ord(c) <= 126 else '?' for c in result)
    print(f"    Result with repeating key: {clean}")
    
    print("\n" + "=" * 70)
    print("Decoding complete. If no flag was found, manual analysis required.")
    print("=" * 70)


if __name__ == "__main__":
    main()
