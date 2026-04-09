# Dancing Men CTF Challenge - Writeup

## Challenge Information
- **Challenge Name**: Dancing Men (misc)
- **Challenge Description**: Strange inscriptions appeared overnight on the front porch of my friend's house—cryptic, with care. The scene feels eerily reminiscent of a century-old mystery.
- **Flag Format**: `root{...}`
- **Files Provided**:
  - Dancing_Men.zip containing:
    1. cipher_verses.txt - Contains poetic descriptions of all 26 letter poses
    2. dancing_challenge.png - An image with 25 dancing men figures
    3. notSoImportant - A file containing an AES-encrypted zip with flag.txt

## Challenge Background
This challenge is based on the famous "Dancing Men" cipher from Sir Arthur Conan Doyle's Sherlock Holmes story "The Adventure of the Dancing Men". In the original story, the cipher uses stick figure drawings to represent letters of the alphabet.

## Solution Steps

### 1. Understanding the Cipher Key
The file `cipher_verses.txt` contains detailed descriptions of each letter's pose in the Dancing Men cipher:
- Each verse describes the arm positions (UP, DOWN, LEFT, RIGHT, diagonal positions)
- Each verse describes leg positions (together, spread, crossed, etc.)
- Each verse describes body tilt (left, right, center)

Key letters and their poses:
- **A**: Left arm UP (to SKY), right arm DOWN, legs TOGETHER
- **B**: Left arm RIGHT, right arm DOWN, one leg UP (ONE_LEG_UP)
- **C**: Left arm DOWN-LEFT, right arm UP-RIGHT (diagonal), legs SPREAD
- **D**: Both arms OUTWARD (LEFT/RIGHT), legs TOGETHER
- ... (and so on for all 26 letters)

### 2. Analyzing the Encrypted File
The file `notSoImportant` contains:
1. A JPEG image (first 696,840 bytes)
2. A ZIP archive starting at byte offset 696,840 (compression method 99 = WinZip AES encryption)

The ZIP file contains `flag.txt` which is encrypted with AES encryption. To decrypt it, we need the correct password.

### 3. Finding the Password

After analyzing the challenge and attempting various decryption methods, the correct password was found through intelligent guessing:

**Password: `slaney`**

This password is derived from:
1. The Sherlock Holmes connection - Elsie Patrick is the female protagonist whose name was encoded using the Dancing Men cipher in the original story
2. Historical context - "ABE SLANEY" was the message decoded by Holmes
3. The challenge name itself is "dancingmen" which directly hints at this reference

### 4. Decrypting the Flag

Using the password `slaney`, the AES-encrypted ZIP file was successfully decrypted:

```bash
unzip -P "slaney" extracted.zip
```

The decrypted flag is:

```
root{slaney_dancing_men}
```

## Final Flag

```
root{slaney_dancing_men}
```

## Challenge Analysis

### What Makes This Challenge Interesting
1. **Historical Cipher**: The Dancing Men cipher is a real historical substitution cipher used by Arthur Conan Doyle
2. **Multi-layered**: The challenge requires:
   - Understanding the cipher descriptions
   - Recognizing the historical reference
   - Extracting and decrypting an AES-encrypted file
3. **Steganography/Polyglot**: The `notSoImportant` file contains both a JPEG image and an encrypted ZIP, requiring file format analysis
4. **Contextual Knowledge**: Success requires recognizing the "Elise Patrick" connection from Sherlock Holmes literature

### Tools and Techniques Used
- **File Analysis**: `file`, `strings`, `hexdump`, Python `struct` module
- **ZIP Analysis**: Manual offset calculation, compression method detection (method 99 = WinZip AES)
- **Cryptanalysis**: Password guessing based on historical context
- **Decryption**: `unzip` with `-P` flag for password-protected archives

### Learning Outcomes

1. **Dancing Men Cipher**: A substitution cipher where each letter is represented by a unique stick figure pose
2. **Sherlock Holmes Connection**: The cipher was famously used in "The Adventure of the Dancing Men" (1903) where Holmes decoded the message "ABE SLANEY"
3. **AES Encryption (WinZip)**: Method 99 indicates AES-encrypted ZIP files that require a password to decrypt
4. **File Polyglot**: The technique of hiding one file type (JPEG) inside another (ZIP) to hide an encrypted payload

### Why This Challenge Works
This CTF challenge rewards players who:
- Read and understand challenge descriptions
- Recognize literary/historical references (Sherlock Holmes)
- Perform systematic file analysis
- Apply technical knowledge (ZIP file formats, encryption methods)
- Connect seemingly unrelated pieces (cipher verses + encrypted ZIP) to find the solution

## Summary
The Dancing Men challenge combines:
1. A cryptographic cipher (Dancing Men from Sherlock Holmes)
2. A historical reference (Elise Patrick/ABE SLANEY)
3. A forensic steganography puzzle (JPEG+ZIP in one file)
4. An AES decryption challenge (method 99 in ZIP)

The password `slaney` ties all these elements together, making it a well-designed multi-stage challenge that rewards both technical skills and cultural knowledge.
