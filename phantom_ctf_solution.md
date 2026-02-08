# Phantom Protocol CTF Challenge - Solution Writeup

## Challenge Overview

The Phantom Protocol CTF challenge involves extracting and decrypting fragmented data scattered across multiple file formats to reconstruct a flag in the format `root{...}` (35 characters total).

## Files Provided

1. **challenge.png** - PNG image with embedded tEXt chunks
2. **memory.dump** - 8KB memory dump file  
3. **chain.json** - Blockchain-style JSON with payload fragments
4. **container.phtm** - Custom container format with compressed data
5. **protocol.spec** - Assembly specification document
6. **hints.json** - Encoded hints (Base85)
7. **verify.json** - Flag verification hash

## Protocol Specification Analysis

According to `protocol.spec`, the flag is assembled from 4 fragments:

### Fragment 1: Memory Dump
- **Location**: `memory.dump` at computed offset
- **Offset Algorithm**: `SHA256("phantom_offset_v2")[0:2] -> (byte0 * 32 + byte1) % 7000`
- **Decryption**: `XOR(GHOST) -> REV_CIPHER(7) -> XOR(MASTER)`

### Fragment 2: Blockchain Chain
- **Location**: `chain.json` blocks [2,4].payload  
- **Process**: `CONCAT_B85 -> DECODE -> XOR(MASTER) -> REV_CIPHER(11)`
- **Extracted**: `1G$gY` + `4<yf|` = Base85 encoded
- **Decoded**: `03b98fd50f24cfa4` (hex)

### Fragment 3: PNG Metadata
- **Location**: PNG tEXt chunk labeled "Data"
- **Process**: `HEX_DECODE -> XOR("SP3CT3R") -> B85_DECODE -> REV_CIPHER(17) -> XOR(GHOST)`
- **Extracted**: `233e67013e782f3f02642300` (hex)

### Fragment 4: Custom Container
- **Location**: `container.phtm` encrypted_fragment field
- **Process**: `HEX_DECODE -> B85_DECODE -> REV_POS_ADD(7) -> XOR(GHOST) -> REV_CIPHER(23) -> XOR(MASTER)`
- **Container Format**: PHTM magic bytes (50 48 54 4D), contains zlib-compressed data

## Key Discovery Challenge

The challenge requires two keys to decrypt the fragments:

1. **MASTER_KEY**: MD5 hash = `520f338cfd46a7619e13c517192b3dd2`
2. **GHOST_KEY**: MD5 hash = `d8a00486e0fe98ae86c126cacf61afb5`

### Hint Analysis

The main hint states:
> "Gaze the site where phantom letters breathe,  
> pluck the pauses — spaces, commas — and trade them for quieter things;  
> stitch the altered syllables until the mask falls away,  
> and from that threaded hush the Master Key will bloom."

**Observations**:
- The website footer contains unusual CSS classes: `ms-2 tr-4 ky-2 hn-4 t-2 h-0 p-3 y-0 u-1 ll-0 f-1 nd-0 th-3 m-4 st-3 rk-3`
- When extracted: `tr`, `ky`, `hn`, `t`, `h`, `p`, `y`, `u`, `ll`, `f`, `nd`, `th`, `m`, `st`, `rk`
- The numbers might indicate ordering or substitution
- Possible interpretation: "tricky hint happy full find the master key"

### Ghost Key Discovery

From `chain.json` block 1:
- Payload: `R0gwU1RfWDBS` (Base64 encoded)
- Decoded: `GH0ST_X0R`
- However, MD5(`GH0ST_X0R`) ≠ expected hash

This suggests the actual keys may require:
1. Additional transformation of the decoded values
2. Combination of multiple data sources
3. Solving the "pluck the pauses" riddle more literally

## Technical Implementation

### Tools Used
- Python 3 with hashlib, base64, json, struct, zlib
- Binary analysis tools (od, file)
- PNG chunk parsers
- MD5 rainbow table lookups

### Container Analysis

The `container.phtm` file structure:
```
Offset  Content
0x00    50 48 54 4D (PHTM magic)
0x04    02 00 (version?)
0x06    08 00 (flags?)  
0x08    80 00 00 00 (size?)
0x0C    1d 00 00 00 (length?)
0x10    78 9c ... (zlib compressed data)
0x90    Final encrypted fragment (hex bytes)
```

### Cipher Operations

**REV_CIPHER(n)**: Reverse substitution cipher with rotation `n`
- Likely involves rotating characters by `n` positions
- Applied in reverse during decryption

**REV_POS_ADD(n)**: Reverse positional addition
- Each byte at position `i` has `(n * i) % 256` added to it
- Reverse operation subtracts instead

**XOR Operations**: Standard bitwise XOR with key bytes

## Solution Strategy

1. ✓ Download all artifacts
2. ✓ Parse protocol specification
3. ✓ Extract Fragment 2 (partial - needs MASTER key)
4. ✓ Extract Fragment 3 data (needs decryption)
5. ✓ Analyze container format
6. ⚠️ Crack/discover MASTER_KEY and GHOST_KEY
7. ⚠️ Decrypt all fragments
8. ⚠️ Concatenate and verify flag

## Challenges Encountered

1. **Key Cracking**: The MD5 hashes for both keys don't match common wordlists
2. **Hint Interpretation**: The "pluck the pauses" hint requires creative interpretation
3. **Custom Cipher**: REV_CIPHER implementation details not fully specified
4. **Multiple Encoding Layers**: Base85, hex, zlib compression, XOR - complex chain

## Next Steps

To complete the challenge:

1. **Brute Force Approach**: Use hashcat with extended wordlists
   ```bash
   hashcat -m 0 -a 3 master_hash.txt ?a?a?a?a?a?a?a?a
   ```

2. **Hint Solving**: Analyze the website HTML source more carefully for:
   - Zero-width characters
   - Hidden form fields
   - JavaScript-embedded keys
   - Steganography in images

3. **Rainbow Tables**: Query online MD5 databases (cmd5.org, crackstation.net)

4. **Reverse Engineering**: If keys can't be found, reverse engineer from:
   - Expected flag format: `root{...}`
   - Known fragment patterns
   - Hash verification data

## Flag Verification

Once the flag is assembled:
```python
import hashlib
flag = "root{...}"
expected_hash = "d2622943e8acd74e5c45e07841e0a5ea71d4b5f72f16df26c131299655ca9f46"
assert hashlib.sha256(flag.encode()).hexdigest() == expected_hash
```

## Conclusion

This is a well-designed multi-stage CTF challenge requiring:
- Cryptographic analysis
- File format parsing
- Puzzle solving (the hint riddle)
- Programming skills
- Persistence

The main bottleneck is discovering the MASTER_KEY and GHOST_KEY, which are intentionally obfuscated through the "phantom letters" hint mechanism.
