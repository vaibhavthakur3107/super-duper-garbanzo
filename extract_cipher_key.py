#!/usr/bin/env python3
"""
Extract cipher key from cipher_verses.txt
"""

def extract_cipher_key():
    """Extract the cipher key from the verses"""

    with open('cipher_verses.txt', 'r') as f:
        content = f.read()

    # The verses start after line 18
    lines = content.split('\n')

    # Parse each verse
    cipher_key = {}
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Each verse starts with a capital letter
        if line and line[0].isupper() and len(line) > 5 and line[1:].startswith('scending') or \
           line and line[0].isupper() and len(line) > 5 and 'alanced' in line or \
           line and line[0].isupper() and len(line) > 5 and 'rossing' in line or \
           line and line[0].isupper() and len(line) > 5 and 'ramatically' in line:

            letter = line[0]
            description = line

            # Collect all lines for this verse
            i += 1
            while i < len(lines) and lines[i].strip():
                if lines[i][0].isupper() and len(lines[i]) > 2:
                    break
                description += " " + lines[i].strip()
                i += 1

            cipher_key[letter] = description
            # Don't increment i here as the loop will do it
        else:
            i += 1

    return cipher_key

def print_cipher_key(cipher_key):
    """Print the cipher key in a readable format"""
    for letter in sorted(cipher_key.keys()):
        print(f"{letter}: {cipher_key[letter][:100]}...")

if __name__ == '__main__':
    key = extract_cipher_key()
    print(f"Extracted {len(key)} cipher entries")
    print("\n" + "="*70)
    for letter in sorted(key.keys()):
        desc = key[letter][:80]
        print(f"{letter}: {desc}...")
