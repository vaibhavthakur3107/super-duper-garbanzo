#!/usr/bin/env python3
"""
Parse cipher verses properly
"""

def parse_cipher_verses():
    """Parse cipher_verses.txt to get the full cipher"""

    with open('cipher_verses.txt', 'r') as f:
        lines = f.readlines()

    cipher = {}

    # Start from line 19 (after the separator)
    i = 19
    while i < len(lines):
        line = lines[i].strip()

        # Skip empty lines and separators
        if not line or line.startswith('━'):
            i += 1
            continue

        # Check if this line starts a new verse (capital letter)
        if line and line[0].isalpha() and line[0].isupper():
            letter = line[0]
            description = line

            # Collect continuation lines
            i += 1
            while i < len(lines):
                next_line = lines[i].rstrip()
                if next_line and next_line[0].isalpha() and next_line[0].isupper():
                    # Next verse starts
                    break
                if next_line.startswith('━'):
                    break
                if next_line.strip():
                    description += " " + next_line.strip()
                i += 1

            cipher[letter] = description

        i += 1

    return cipher

if __name__ == '__main__':
    cipher = parse_cipher_verses()
    print(f"Found {len(cipher)} letters in cipher")
    print("\nCipher key:")
    for letter in sorted(cipher.keys()):
        desc = cipher[letter][:100]
        print(f"{letter}: {desc}")
