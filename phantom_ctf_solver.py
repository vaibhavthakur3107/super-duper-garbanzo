#!/usr/bin/env python3
"""
Phantom Protocol CTF Solver
Complete implementation of the decryption protocol
"""

import hashlib
import base64
import json
import struct
import zlib
from typing import Tuple, Optional

# ============================================================================
# CONFIGURATION
# ============================================================================

MASTER_KEY_HASH = "520f338cfd46a7619e13c517192b3dd2"
GHOST_KEY_HASH = "d8a00486e0fe98ae86c126cacf61afb5"
FLAG_HASH = "d2622943e8acd74e5c45e07841e0a5ea71d4b5f72f16df26c131299655ca9f46"

# TODO: These need to be discovered/cracked
MASTER_KEY = None  # MD5 hash: 520f338cfd46a7619e13c517192b3dd2
GHOST_KEY = None    # MD5 hash: d8a00486e0fe98ae86c126cacf61afb5

# ============================================================================
# CIPHER IMPLEMENTATIONS
# ============================================================================

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR data with repeating key"""
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def rev_cipher(data: bytes, shift: int) -> bytes:
    """Reverse substitution cipher with rotation"""
    # This is a placeholder implementation
    # The actual implementation depends on the specific cipher used
    result = bytearray(data)
    for i in range(len(result)):
        # Simple rotation cipher (may need adjustment)
        result[i] = (result[i] - shift) % 256
    return bytes(result)

def rev_pos_add(data: bytes, n: int) -> bytes:
    """Reverse positional addition cipher"""
    result = bytearray(data)
    for i in range(len(result)):
        result[i] = (result[i] - (n * i)) % 256
    return bytes(result)

# ============================================================================
# FRAGMENT EXTRACTORS
# ============================================================================

def extract_fragment1(memory_file: str, ghost_key: bytes, master_key: bytes) -> Optional[bytes]:
    """Extract Fragment 1 from memory dump"""
    # Calculate offset
    offset_seed = b"phantom_offset_v2"
    hash_bytes = hashlib.sha256(offset_seed).digest()
    offset = (hash_bytes[0] * 32 + hash_bytes[1]) % 7000
    
    print(f"Fragment 1: offset = {offset}")
    
    # Read from memory dump
    with open(memory_file, 'rb') as f:
        f.seek(offset)
        encrypted = f.read(8)  # Assuming 8 bytes, adjust as needed
    
    # Decrypt: XOR(GHOST) -> REV_CIPHER(7) -> XOR(MASTER)
    step1 = xor_bytes(encrypted, ghost_key)
    step2 = rev_cipher(step1, 7)
    step3 = xor_bytes(step2, master_key)
    
    return step3

def extract_fragment2(chain_file: str, master_key: bytes) -> Optional[bytes]:
    """Extract Fragment 2 from blockchain"""
    with open(chain_file, 'r') as f:
        chain = json.load(f)
    
    # Get blocks 2 and 4
    payload1 = chain[2]['data']['payload']
    payload2 = chain[4]['data']['payload']
    
    print(f"Fragment 2: {payload1} + {payload2}")
    
    # CONCAT_B85 -> DECODE -> XOR(MASTER) -> REV_CIPHER(11)
    concatenated = payload1 + payload2
    decoded = base64.b85decode(concatenated)
    step1 = xor_bytes(decoded, master_key)
    step2 = rev_cipher(step1, 11)
    
    return step2

def extract_fragment3(png_file: str, ghost_key: bytes) -> Optional[bytes]:
    """Extract Fragment 3 from PNG tEXt chunk"""
    with open(png_file, 'rb') as f:
        data = f.read()
    
    # Parse PNG chunks to find tEXt
    pos = 8  # Skip PNG signature
    text_data = None
    
    while pos < len(data):
        if pos + 8 > len(data):
            break
        length = struct.unpack('>I', data[pos:pos+4])[0]
        chunk_type = data[pos+4:pos+8].decode('ascii')
        chunk_data = data[pos+8:pos+8+length]
        
        if chunk_type == 'tEXt':
            # Find the "Data" chunk
            if chunk_data.startswith(b'Data\x00'):
                text_data = chunk_data[5:]  # Skip "Data\x00"
                break
        
        pos += 12 + length
    
    if not text_data:
        print("ERROR: tEXt chunk not found!")
        return None
    
    print(f"Fragment 3: {text_data}")
    
    # HEX_DECODE -> XOR("SP3CT3R") -> B85_DECODE -> REV_CIPHER(17) -> XOR(GHOST)
    step1 = bytes.fromhex(text_data.decode())
    step2 = xor_bytes(step1, b"SP3CT3R")
    step3 = base64.b85decode(step2)
    step4 = rev_cipher(step3, 17)
    step5 = xor_bytes(step4, ghost_key)
    
    return step5

def extract_fragment4(container_file: str, ghost_key: bytes, master_key: bytes) -> Optional[bytes]:
    """Extract Fragment 4 from custom container"""
    with open(container_file, 'rb') as f:
        data = f.read()
    
    # Parse PHTM container
    # Format: PHTM magic (4) + version (2) + flags (2) + size (4) + length (4) + compressed_data + encrypted_fragment
    
    if data[:4] != b'PHTM':
        print("ERROR: Invalid PHTM magic!")
        return None
    
    # Skip to encrypted fragment (last bytes)
    # The encrypted fragment appears to start around offset 0x90
    encrypted = data[0x90:]
    
    print(f"Fragment 4: {len(encrypted)} bytes")
    
    # HEX_DECODE -> B85_DECODE -> REV_POS_ADD(7) -> XOR(GHOST) -> REV_CIPHER(23) -> XOR(MASTER)
    # Note: The data is already binary, so skip HEX_DECODE
    try:
        step1 = base64.b85decode(encrypted)
    except:
        step1 = encrypted  # Already decoded
    
    step2 = rev_pos_add(step1, 7)
    step3 = xor_bytes(step2, ghost_key)
    step4 = rev_cipher(step3, 23)
    step5 = xor_bytes(step4, master_key)
    
    return step5

# ============================================================================
# MAIN SOLVER
# ============================================================================

def solve(master_key: str, ghost_key: str) -> Optional[str]:
    """Main solving function"""
    master_bytes = master_key.encode()
    ghost_bytes = ghost_key.encode()
    
    print("=" * 70)
    print("PHANTOM PROTOCOL - CTF SOLVER")
    print("=" * 70)
    
    # Verify keys
    if hashlib.md5(master_bytes).hexdigest() != MASTER_KEY_HASH:
        print(f"WARNING: MASTER_KEY hash mismatch!")
    if hashlib.md5(ghost_bytes).hexdigest() != GHOST_KEY_HASH:
        print(f"WARNING: GHOST_KEY hash mismatch!")
    
    print(f"\nUsing keys:")
    print(f"  MASTER: {master_key}")
    print(f"  GHOST: {ghost_key}")
    print()
    
    # Extract all fragments
    print("Extracting fragments...")
    print("-" * 70)
    
    try:
        frag1 = extract_fragment1('phantom_ctf/memory.dump', ghost_bytes, master_bytes)
        print(f"✓ Fragment 1: {frag1.hex() if frag1 else 'FAILED'}")
    except Exception as e:
        print(f"✗ Fragment 1: {e}")
        frag1 = None
    
    try:
        frag2 = extract_fragment2('phantom_ctf/chain.json', master_bytes)
        print(f"✓ Fragment 2: {frag2.hex() if frag2 else 'FAILED'}")
    except Exception as e:
        print(f"✗ Fragment 2: {e}")
        frag2 = None
    
    try:
        frag3 = extract_fragment3('phantom_ctf/challenge.png', ghost_bytes)
        print(f"✓ Fragment 3: {frag3.hex() if frag3 else 'FAILED'}")
    except Exception as e:
        print(f"✗ Fragment 3: {e}")
        frag3 = None
    
    try:
        frag4 = extract_fragment4('phantom_ctf/container.phtm', ghost_bytes, master_bytes)
        print(f"✓ Fragment 4: {frag4.hex() if frag4 else 'FAILED'}")
    except Exception as e:
        print(f"✗ Fragment 4: {e}")
        frag4 = None
    
    # Assemble flag
    print("\n" + "=" * 70)
    if all([frag1, frag2, frag3, frag4]):
        flag_bytes = frag1 + frag2 + frag3 + frag4
        flag = flag_bytes.decode('utf-8', errors='ignore')
        
        print(f"Assembled flag: {flag}")
        
        # Verify
        flag_hash = hashlib.sha256(flag.encode()).hexdigest()
        if flag_hash == FLAG_HASH:
            print("✓ FLAG VERIFIED!")
            return flag
        else:
            print(f"✗ Hash mismatch:")
            print(f"  Expected: {FLAG_HASH}")
            print(f"  Got:      {flag_hash}")
            return None
    else:
        print("✗ Failed to extract all fragments")
        return None

# ============================================================================
# KEY CRACKER (Placeholder)
# ============================================================================

def crack_keys():
    """Attempt to crack the MD5 hashes"""
    print("Attempting to crack keys...")
    print(f"MASTER_KEY hash: {MASTER_KEY_HASH}")
    print(f"GHOST_KEY hash:  {GHOST_KEY_HASH}")
    print()
    print("This requires:")
    print("  1. Rainbow table lookup")
    print("  2. Hashcat/John the Ripper brute force")
    print("  3. Solving the 'pluck the pauses' hint")
    print()
    
    # TODO: Implement actual key cracking
    return None, None

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    if MASTER_KEY and GHOST_KEY:
        flag = solve(MASTER_KEY, GHOST_KEY)
        if flag:
            print(f"\n🎉 SUCCESS! Flag: {flag}")
    else:
        print("Keys not yet discovered. Run crack_keys() or manually set MASTER_KEY and GHOST_KEY.")
        master, ghost = crack_keys()
        if master and ghost:
            flag = solve(master, ghost)
