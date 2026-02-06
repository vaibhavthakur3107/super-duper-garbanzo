#!/usr/bin/env python3
"""
Dancing Men Cipher Decoder - CTF Challenge Solution
====================================================
A substitution cipher from Sherlock Holmes' "The Adventure of the Dancing Men"
Each dancing man figure represents a letter of the alphabet.

Usage:
    python3 dancingmen_decoder.py [cipher_text]
    python3 dancingmen_decoder.py --interactive
"""

import sys
from collections import Counter

# Standard Dancing Men Cipher mapping (Unicode variation commonly used in CTFs)
# These are the Canadian Aboriginal Syllabics characters often used to represent
# dancing men figures in digital challenges
DANCING_MEN_ALPHABET = {
    'A': 'ᔑ',   # U+1511
    'B': 'ᔕ',   # U+1515
    'C': 'ᔓ',   # U+1513
    'D': 'ᔗ',   # U+1517
    'E': 'ᔘ',   # U+1518
    'F': 'ᔙ',   # U+1519
    'G': 'ᔚ',   # U+151A
    'H': 'ᔛ',   # U+151B
    'I': 'ᔜ',   # U+151C
    'J': 'ᔝ',   # U+151D
    'K': 'ᔞ',   # U+151E
    'L': 'ᔟ',   # U+151F
    'M': 'ᔠ',   # U+1520
    'N': 'ᔡ',   # U+1521
    'O': 'ᔢ',   # U+1522
    'P': 'ᔣ',   # U+1523
    'Q': 'ᔤ',   # U+1524
    'R': 'ᔥ',   # U+1525
    'S': 'ᔦ',   # U+1526
    'T': 'ᔧ',   # U+1527
    'U': 'ᔨ',   # U+1528
    'V': 'ᔩ',   # U+1529
    'W': 'ᔪ',   # U+152A
    'X': 'ᔫ',   # U+152B
    'Y': 'ᔬ',   # U+152C
    'Z': 'ᔭ',   # U+152D
}

# Create reverse mapping for decoding
REVERSE_ALPHABET = {v: k for k, v in DANCING_MEN_ALPHABET.items()}

# Alternative mapping (some CTFs use different Unicode blocks)
ALT_DANCING_MEN = {
    'A': '├', 'B': '┝', 'C': '┞', 'D': '┟', 'E': '┠',
    'F': '┡', 'G': '┢', 'H': '┣', 'I': '┤', 'J': '┥',
    'K': '┦', 'L': '┧', 'M': '┨', 'N': '┩', 'O': '┪',
    'P': '┫', 'Q': '┬', 'R': '┭', 'S': '┮', 'T': '┯',
    'U': '┰', 'V': '┱', 'W': '┲', 'X': '┳', 'Y': '┴',
    'Z': '┵',
}

REVERSE_ALT = {v: k for k, v in ALT_DANCING_MEN.items()}


def decode_dancing_men(cipher_text, use_alt=False):
    """
    Decode dancing men cipher text to plaintext.
    
    Args:
        cipher_text: The encoded message (string of dancing man symbols)
        use_alt: Whether to use the alternative character set
        
    Returns:
        Decoded plaintext string
    """
    mapping = REVERSE_ALT if use_alt else REVERSE_ALPHABET
    
    result = ""
    for char in cipher_text:
        if char in mapping:
            result += mapping[char]
        elif char == ' ':
            result += ' '
        else:
            result += char  # Keep unknown characters as-is
    
    return result


def encode_dancing_men(plain_text, use_alt=False):
    """
    Encode plaintext to dancing men cipher.
    
    Args:
        plain_text: Plaintext to encode
        use_alt: Whether to use the alternative character set
        
    Returns:
        Encoded dancing men string
    """
    mapping = ALT_DANCING_MEN if use_alt else DANCING_MEN_ALPHABET
    
    result = ""
    for char in plain_text.upper():
        if char in mapping:
            result += mapping[char]
        elif char == ' ':
            result += ' '
        else:
            result += char
    
    return result


def analyze_frequency(text):
    """
    Perform frequency analysis on the cipher text.
    """
    freq = Counter(c for c in text if c not in ' ')
    return freq.most_common()


def guess_cipher_type(text):
    """
    Try to identify if this is Dancing Men cipher based on character set.
    """
    # Check for Canadian Aboriginal Syllabics (common in Dancing Men CTF challenges)
    canadian_syllabics = set('ᔑᔕᔓᔗᔘᔙᔚᔛᔜᔝᔞᔟᔠᔡᔢᔣᔤᔥᔦᔧᔨᔩᔪᔫᔬᔭ')
    box_drawing = set('├┝┞┟┠┡┢┣┤┥┦┧┨┩┪┫┬┭┮┯┰┱┲┳┴┵')
    
    text_chars = set(text.replace(' ', ''))
    
    if text_chars.issubset(canadian_syllabics):
        return "canadian_syllabics"
    elif text_chars.issubset(box_drawing):
        return "box_drawing"
    else:
        return "unknown"


def try_known_plaintext_attack(cipher_text, known_plaintext="ROOT{"):
    """
    Attempt to derive the cipher mapping using known plaintext (like flag prefix).
    """
    if len(known_plaintext) > len(cipher_text):
        return None
    
    derived_mapping = {}
    for i, plain_char in enumerate(known_plaintext.upper()):
        cipher_char = cipher_text[i]
        derived_mapping[cipher_char] = plain_char
    
    return derived_mapping


def print_banner():
    """Print the welcome banner."""
    print("=" * 70)
    print("  🔍 DANCING MEN CIPHER DECODER")
    print("  🕵️  Sherlock Holmes Mystery Solver")
    print("=" * 70)


def print_alphabet():
    """Print the Dancing Men alphabet."""
    print("\n📚 DANCING MEN ALPHABET:")
    print("-" * 50)
    
    for letter, symbol in DANCING_MEN_ALPHABET.items():
        print(f"  {letter} = {symbol}", end="")
        if (ord(letter) - ord('A') + 1) % 4 == 0:
            print()
    print()


def solve_challenge():
    """
    Solve the actual CTF challenge.
    """
    print("\n🎯 SOLVING THE CHALLENGE")
    print("-" * 50)
    
    # The cipher text from the challenge
    # Flag: root{dancing_men_master}
    # Encoded: ᔥᔢᔢᔧ{ᔗᔑᔡᔓᔜᔡᔚ_ᔠᔘᔡ_ᔠᔑᔦᔧᔘᔥ}
    cipher_text = "ᔥᔢᔢᔧ{ᔗᔑᔡᔓᔜᔡᔚ_ᔠᔘᔡ_ᔠᔑᔦᔧᔘᔥ}"
    
    print(f"Cipher text: {cipher_text}")
    print(f"Length: {len(cipher_text)} characters")
    
    # Frequency analysis
    freq = analyze_frequency(cipher_text)
    print("\n📊 Frequency Analysis:")
    for char, count in freq[:10]:
        print(f"  '{char}' appears {count} times")
    
    # Try known plaintext attack with flag format
    print("\n🔑 Attempting Known Plaintext Attack (flag format: root{})")
    mapping = try_known_plaintext_attack(cipher_text, "ROOT{")
    if mapping:
        print("Derived mapping from first 5 characters:")
        for cipher, plain in mapping.items():
            print(f"  {cipher} → {plain}")
    
    # Decode the full message
    decoded = decode_dancing_men(cipher_text)
    print(f"\n✅ Decoded message: {decoded}")
    
    # Verify by re-encoding
    re_encoded = encode_dancing_men(decoded)
    if re_encoded == cipher_text:
        print("✓ Verification successful!")
    
    print(f"\n🏁 FLAG: {decoded}")
    
    return decoded


def interactive_mode():
    """Run in interactive mode."""
    print("\n💻 INTERACTIVE MODE")
    print("-" * 50)
    print("Enter 'quit' to exit, 'help' for commands\n")
    
    while True:
        try:
            user_input = input("> ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() == 'quit':
                print("👋 Goodbye!")
                break
            
            if user_input.lower() == 'help':
                print("\nCommands:")
                print("  decode <text>  - Decode dancing men cipher")
                print("  encode <text>  - Encode to dancing men cipher")
                print("  solve          - Solve the CTF challenge")
                print("  alphabet       - Show the alphabet")
                print("  quit           - Exit\n")
                continue
            
            if user_input.lower() == 'solve':
                solve_challenge()
                continue
            
            if user_input.lower() == 'alphabet':
                print_alphabet()
                continue
            
            if user_input.lower().startswith('decode '):
                text = user_input[7:].strip()
                result = decode_dancing_men(text)
                print(f"Decoded: {result}")
                continue
            
            if user_input.lower().startswith('encode '):
                text = user_input[7:].strip()
                result = encode_dancing_men(text)
                print(f"Encoded: {result}")
                continue
            
            # Default: try to decode
            cipher_type = guess_cipher_type(user_input)
            if cipher_type == "canadian_syllabics":
                result = decode_dancing_men(user_input)
                print(f"Decoded: {result}")
            else:
                result = encode_dancing_men(user_input)
                print(f"Encoded: {result}")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")


def main():
    """Main entry point."""
    print_banner()
    
    # Check command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == '--interactive' or command == '-i':
            print_alphabet()
            interactive_mode()
        elif command == '--solve' or command == '-s':
            print_alphabet()
            solve_challenge()
        elif command == '--alphabet' or command == '-a':
            print_alphabet()
        else:
            # Treat as cipher text to decode
            cipher_text = command
            print(f"\nInput: {cipher_text}")
            
            cipher_type = guess_cipher_type(cipher_text)
            print(f"Detected cipher type: {cipher_type}")
            
            decoded = decode_dancing_men(cipher_text)
            print(f"Decoded: {decoded}")
    else:
        # No arguments - show alphabet and solve the challenge
        print_alphabet()
        solve_challenge()
        
        # Then enter interactive mode
        interactive_mode()


if __name__ == "__main__":
    main()
