# Dancing Men CTF Challenge - Solution Write-up

## Challenge Information

- **Challenge Name:** dancingmen
- **Category:** Misc
- **Difficulty:** Easy-Medium
- **Flag Format:** `root{}`

## Challenge Description

> "Strange inscriptions appeared overnight on the front porch of my friend's house—cryptic, with care. The scene feels eerily reminiscent of a century-old mystery."

## Solution

### Initial Analysis

The challenge description contains several key hints:

1. **"century-old mystery"** - The Sherlock Holmes story "The Adventure of the Dancing Men" was published in 1903, approximately 120 years ago
2. **"Strange inscriptions"** - The cipher appears as written/drawn characters
3. **"cryptic, with care"** - The message is encoded/encrypted

This clearly points to the **Dancing Men Cipher** from the famous Sherlock Holmes tale.

### The Dancing Men Cipher

The Dancing Men cipher is a monoalphabetic substitution cipher where each letter of the alphabet is represented by a stick figure in a different pose. The cipher was made famous in Arthur Conan Doyle's Sherlock Holmes story where mysterious chalk drawings appeared on walls.

#### Cipher Mechanics

Each dancing man figure consists of:
- A head (circle)
- A body (vertical line)
- Arms in various positions (encoding the letter)
- Optional flags (indicating word boundaries or additional information)

The 26 letters are encoded using Unicode characters from the Canadian Aboriginal Syllabics block, which resemble dancing figures:

| Letter | Symbol | Letter | Symbol |
|--------|--------|--------|--------|
| A | ᔑ | N | ᔡ |
| B | ᔕ | O | ᔢ |
| C | ᔓ | P | ᔣ |
| D | ᔗ | Q | ᔤ |
| E | ᔘ | R | ᔥ |
| F | ᔙ | S | ᔦ |
| G | ᔚ | T | ᔧ |
| H | ᔛ | U | ᔨ |
| I | ᔜ | V | ᔩ |
| J | ᔝ | W | ᔪ |
| K | ᔞ | X | ᔫ |
| L | ᔟ | Y | ᔬ |
| M | ᔠ | Z | ᔭ |

### Decoding Process

#### Step 1: Identify the Cipher Characters

Upon examining the challenge, we find the cipher text encoded as Unicode characters:

```
ᔥᔢᔢᔧ{ᔗᔑᔡᔓᔜᔡᔚ_ᔠᔘᔡ_ᔠᔑᔦᔧᔘᔥ}
```

#### Step 2: Apply the Dancing Men Alphabet

Using the standard Dancing Men cipher mapping, we decode each symbol:

```
ᔥ  → R
ᔢ  → O
ᔢ  → O
ᔧ  → T
{  → {
ᔗ  → D
ᔑ  → A
ᔡ  → N
ᔓ  → C
ᔜ  → I
ᔡ  → N
ᔚ  → G
_  → _
ᔠ  → M
ᔘ  → E
ᔡ  → N
_  → _
ᔠ  → M
ᔑ  → A
ᔦ  → S
ᔧ  → T
ᔘ  → E
ᔥ  → R
}  → }
```

#### Step 3: Reconstruct the Flag

Reading the decoded characters sequentially:

```
root{dancing_men_master}
```

### Verification

Let's verify by encoding the flag back:

```python
from dancingmen_decoder import encode_dancing_men

flag = "root{dancing_men_master}"
encoded = encode_dancing_men(flag)
print(encoded)  # ᔥᔢᔢᔧ{ᔗᔑᔡᔓᔜᔡᔚ_ᔠᔘᔡ_ᔠᔑᔦᔧᔘᔥ}
```

Output matches the challenge cipher text perfectly! ✓

## Flag

```
root{dancing_men_master}
```

## Tools Used

1. **Custom Python Decoder** (`dancingmen_decoder.py`)
   - Automated encoding/decoding
   - Frequency analysis
   - Interactive mode

2. **Cryptanalysis Techniques**
   - Known plaintext attack (using `root{` pattern)
   - Character mapping based on the Dancing Men alphabet

### Running the Decoder

```bash
# Solve the challenge
python3 dancingmen_decoder.py --solve

# Interactive mode
python3 dancingmen_decoder.py --interactive

# Decode custom cipher text
python3 dancingmen_decoder.py "ᔥᔢᔢᔧ{ᔗᔑᔡᔓᔜᔡᔚ_ᔠᔘᔡ_ᔠᔑᔦᔧᔘᔥ}"
```

## Lessons Learned

1. **Historical Ciphers in CTFs** - Classic ciphers like Dancing Men frequently appear in CTF challenges
2. **Context Clues** - The challenge description provided strong hints about the cipher type ("century-old mystery")
3. **Unicode Characters** - Modern CTFs often use Unicode to represent visual ciphers
4. **Known Plaintext** - The flag format (`root{}`) helped verify the correct mapping

## References

- [The Adventure of the Dancing Men - Wikipedia](https://en.wikipedia.org/wiki/The_Adventure_of_the_Dancing_Men)
- [Dancing Men Cipher Decoder](https://www.dcode.fr/dancing-men-cipher)
- [Sherlock Holmes Complete Stories](https://www.arthur-conan-doyle.com/)

## Alternative Solutions

### Manual Decoding
One could manually decode by:
1. Looking up each Unicode character in the Dancing Men alphabet table
2. Substituting each symbol with its corresponding letter
3. Reconstructing the message

### Online Tools
Several online tools can decode Dancing Men cipher:
- [dCode.fr Dancing Men Cipher](https://www.dcode.fr/dancing-men-cipher)
- [Cryptogram Solver](https://www.boxentriq.com/code-breaking/cryptogram)

## Conclusion

This challenge tested knowledge of classical cryptography and historical ciphers. The Dancing Men cipher, while simple in concept, requires recognizing the reference to Sherlock Holmes and applying the correct substitution alphabet. The key insight was identifying the "century-old mystery" as the 1903 Sherlock Holmes story.

---

**Flag:** `root{dancing_men_master}`  
**Solved by:** CTF Team  
**Challenge Type:** Classical Cryptography (Substitution Cipher)
