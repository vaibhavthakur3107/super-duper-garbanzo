# Phantom Protocol CTF Challenge

This repository contains the solution and documentation for the "Phantom Protocol" CTF challenge from phantom.codewin.tech.

## Challenge Files

All challenge files are stored in the `phantom_ctf/` directory:

- `challenge.png` - PNG image with embedded metadata
- `memory.dump` - Binary memory dump (8KB)
- `chain.json` - Blockchain-style JSON with encoded fragments
- `container.phtm` - Custom container format
- `protocol.spec` - Protocol specification document
- `hints.json` - Base85-encoded hints
- `verify.json` - Flag verification data

## Solution Files

- `phantom_ctf_solution.md` - Complete writeup and analysis
- `phantom_ctf_solver.py` - Python solver implementation
- `README.md` - This file

## Quick Start

### Prerequisites

```bash
python3 -m pip install --upgrade pip
# No additional dependencies required - uses stdlib only
```

### Running the Solver

```bash
cd /path/to/repository
python3 phantom_ctf_solver.py
```

**Note**: The solver requires the MASTER_KEY and GHOST_KEY to be discovered first. See the writeup for details on the key discovery process.

## Challenge Overview

The Phantom Protocol challenge is a multi-stage CTF that requires:

1. **Cryptographic Analysis** - MD5 hash cracking for key discovery
2. **File Format Parsing** - PNG, custom PHTM container, memory dumps
3. **Decryption** - Multiple cipher layers (XOR, substitution, Base85)
4. **Puzzle Solving** - Interpreting the "phantom letters" hint
5. **Assembly** - Combining 4 fragments to construct the final flag

### Flag Format

```
root{...}
```

Length: 35 characters  
SHA256: `d2622943e8acd74e5c45e07841e0a5ea71d4b5f72f16df26c131299655ca9f46`

## Protocol Specification

The challenge follows a strict decryption protocol defined in `protocol.spec`:

### Fragment Assembly

```
FINAL_FLAG = FRAG_1 + FRAG_2 + FRAG_3 + FRAG_4
```

### Decryption Keys

Two keys are required:

- **MASTER_KEY**: MD5 = `520f338cfd46a7619e13c517192b3dd2`
- **GHOST_KEY**: MD5 = `d8a00486e0fe98ae86c126cacf61afb5`

### Fragment Sources

1. **Fragment 1**: Memory dump at computed offset
   - Offset = `SHA256("phantom_offset_v2")[0:2] -> (byte0 * 32 + byte1) % 7000`
   - Decrypt: `XOR(GHOST) -> REV_CIPHER(7) -> XOR(MASTER)`

2. **Fragment 2**: Blockchain payload concatenation  
   - Source: `chain.json` blocks [2,4]
   - Decrypt: `B85_DECODE -> XOR(MASTER) -> REV_CIPHER(11)`

3. **Fragment 3**: PNG metadata
   - Source: tEXt chunk "Data"
   - Decrypt: `HEX_DECODE -> XOR("SP3CT3R") -> B85_DECODE -> REV_CIPHER(17) -> XOR(GHOST)`

4. **Fragment 4**: Custom container
   - Source: `container.phtm` encrypted section
   - Decrypt: `B85_DECODE -> REV_POS_ADD(7) -> XOR(GHOST) -> REV_CIPHER(23) -> XOR(MASTER)`

## Key Discovery

The main challenge is discovering the MASTER_KEY and GHOST_KEY. The challenge provides a cryptic hint:

> "Gaze the site where phantom letters breathe,  
> pluck the pauses — spaces, commas — and trade them for quieter things;  
> stitch the altered syllables until the mask falls away,  
> and from that threaded hush the Master Key will bloom."

### Analysis Approaches

1. **Website Source Code Analysis**
   - Examine CSS classes in the footer: `tr-4 ky-2 hn-4 t-2 h-0 p-3 y-0 u-1 ll-0 f-1 nd-0 th-3 m-4 st-3 rk-3`
   - Look for zero-width characters or steganography
   - Check JavaScript code for embedded keys

2. **Rainbow Table Lookup**
   - Query MD5 databases (cmd5.org, crackstation.net, md5decrypt.net)
   - Use hashcat or John the Ripper for brute force

3. **hints.json Decoding**
   - The hints are Base85-encoded
   - May contain clues to key derivation

## Tools and Techniques

### Recommended Tools

- **Parrot OS** (as suggested in the challenge)
- **hashcat** - GPU-accelerated hash cracking
- **John the Ripper** - Password cracking
- **pngcheck** - PNG analysis
- **binwalk** - Binary file analysis
- **strings** - Extract printable strings
- **xxd/hexdump** - Hex analysis

### Python Libraries Used

- `hashlib` - MD5/SHA256 hashing
- `base64` - Base85 encoding/decoding
- `json` - JSON parsing
- `struct` - Binary data parsing
- `zlib` - Compression handling

## Current Status

✅ Challenge files downloaded and analyzed  
✅ Protocol specification understood  
✅ Fragment extraction logic implemented  
✅ Custom container format parsed  
⚠️ Key discovery in progress  
⏳ Flag assembly pending key discovery  

## Contributing

To complete this challenge:

1. Crack the MD5 hashes for MASTER_KEY and GHOST_KEY
2. Update the keys in `phantom_ctf_solver.py`
3. Run the solver to extract and verify the flag
4. Update the writeup with the solution

## Resources

- Challenge URL: https://phantom.codewin.tech/
- Flag Verification: SHA256 hash provided in `verify.json`
- Support: Check hints.json for additional clues

## License

This solution is provided for educational purposes as part of CTF competition participation.

---

**Status**: 🔴 In Progress - Keys not yet discovered  
**Difficulty**: ⭐⭐⭐⭐ Advanced  
**Tags**: cryptography, forensics, steganography, reverse-engineering
