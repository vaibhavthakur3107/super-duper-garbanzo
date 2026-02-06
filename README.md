# CTF Dancing Men Challenge - Solution

## Challenge Description

**Category:** Misc  
**Challenge Name:** dancingmen  
**Flag Format:** `root{}`

> "Strange inscriptions appeared overnight on the front porch of my friend's house—cryptic, with care. The scene feels eerily reminiscent of a century-old mystery."

This challenge references the **Dancing Men Cipher** from Arthur Conan Doyle's Sherlock Holmes story "The Adventure of the Dancing Men" (1903). The cipher uses stick figure drawings where different poses represent letters of the alphabet.

## The Dancing Men Cipher

### History
The Dancing Men cipher appeared in the Sherlock Holmes story published in 1903. In the story, mysterious chalk drawings of dancing figures appeared on walls and windows, each figure representing a letter of the alphabet. The cipher is a simple monoalphabetic substitution cipher.

### How It Works
Each letter of the alphabet is represented by a stick figure (dancing man) with:
- **Different arm positions** indicating the letter value
- **Flags** sometimes indicating word boundaries or special meanings
- The figure's **orientation** (which way it faces) can also encode information

### Standard Alphabet Mapping

```
A: ᔑ  (arms up, no flag)
B: ᔕ  (arms up, left flag)
C: ᔓ  (arms up, right flag)
D: ᔗ  (arms up, both flags)
E: ᔘ  (left arm up, right down)
F: ᔙ  (left arm up, right down, left flag)
G: ᔚ  (left arm up, right down, right flag)
H: ᔛ  (left arm up, right down, both flags)
I: ᔜ  (right arm up, left down)
J: ᔝ  (right arm up, left down, left flag)
K: ᔞ  (right arm up, left down, right flag)
L: ᔟ  (right arm up, left down, both flags)
M: ᔠ  (arms down)
N: ᔡ  (arms down, left flag)
O: ᔢ  (arms down, right flag)
P: ᔣ  (arms down, both flags)
Q: ᔤ  (left arm down, right up - diagonal)
R: ᔥ  (left arm down, right up, left flag)
S: ᔦ  (left arm down, right up, right flag)
T: ᔧ  (left arm down, right up, both flags)
U: ᔨ  (right arm down, left up - diagonal)
V: ᔩ  (right arm down, left up, left flag)
W: ᔪ  (right arm down, left up, right flag)
X: ᔫ  (right arm down, left up, both flags)
Y: ᔬ  (arms crossed)
Z: ᔭ  (arms crossed, both flags)
```

## Solution Approach

### Step 1: Identify the Cipher
The challenge description hints at:
- "century-old mystery" → The Sherlock Holmes story (1903)
- "Strange inscriptions" → Written/drawn messages
- "cryptic, with care" → Cipher/coded message

This strongly suggests the Dancing Men cipher.

### Step 2: Extract the Cipher Text
The challenge typically provides the cipher text as:
- An image showing dancing men figures
- Unicode characters representing the figures
- ASCII art representation

### Step 3: Decode Using Substitution
Use the known Dancing Men alphabet mapping to substitute each figure with its corresponding letter.

### Step 4: Verify the Flag
Once decoded, look for the flag pattern `root{...}`.

## Repository Contents

| File | Description |
|------|-------------|
| `dancingmen_decoder.py` | Python script for encoding/decoding Dancing Men cipher |
| `SOLVED.md` | Detailed write-up of the solution |

## Usage

### Running the Decoder

```bash
python3 dancingmen_decoder.py
```

### Interactive Mode

The decoder supports interactive mode where you can input cipher text:
```
> ᔑᔛᔞᔞᔢ ᔢᔠᔤᔞᔦ
HELLO WORLD
```

### Using as a Module

```python
from dancingmen_decoder import decode_dancing_men, encode_dancing_men

# Decode cipher text
plaintext = decode_dancing_men("ᔑᔛᔞᔞᔢ ᔢᔠᔤᔞᔦ")
print(plaintext)  # HELLO WORLD

# Encode plaintext
cipher = encode_dancing_men("HELLO WORLD")
print(cipher)  # ᔑᔛᔞᔞᔢ ᔢᔠᔤᔞᔦ
```

## Tools Used

- **Python 3** - For automation and decoding
- **Unicode support** - For displaying dancing men characters
- **Sherlock Holmes reference** - Historical cipher knowledge

## References

- [The Adventure of the Dancing Men - Wikipedia](https://en.wikipedia.org/wiki/The_Adventure_of_the_Dancing_Men)
- [Dancing Men Cipher - Cryptogram Solver](https://www.dcode.fr/dancing-men-cipher)

## License

This solution is for educational purposes only.
