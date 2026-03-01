# Binary Analysis & Digital Forensics Methodology

## Phase 1 – File Identification
```bash
file BINARY              # file type, architecture, linking
exiftool BINARY          # all embedded metadata
strings -n 8 BINARY      # printable strings (look for flags, creds)
checksec --file=BINARY   # security mitigations (NX, PIE, ASLR, canary, RELRO)
xxd BINARY | head -20    # hex dump of file header
```

## Phase 2 – Static Analysis

### Radare2 Quick Reference
```bash
r2 -A BINARY             # auto-analyse
afl                      # list all functions
pdf @ main               # disassemble main()
iz                       # strings in binary
ii                       # imports
iE                       # exports
axt sym.main             # cross-references to main
```

### Ghidra (headless)
```bash
ghidra_server.sh PROJECT_DIR
analyzeHeadless PROJECT_DIR PROJECT_NAME -import BINARY -postScript PrintAST.java
```

### Common Patterns to Look For
- `strcmp`, `strncmp` → potential hardcoded password comparisons
- `system()`, `execve()` → command execution sinks
- `strcpy()`, `gets()`, `sprintf()` without bounds → buffer overflow candidates
- `rand()` seeded with time → predictable random numbers

## Phase 3 – Dynamic Analysis

### GDB Quick Reference
```bash
gdb BINARY
b main                   # breakpoint at main
r $(python3 -c "print('A'*100)")   # run with payload
info registers           # register state
x/20xw $rsp             # examine stack
backtrace                # call stack
```

### strace / ltrace
```bash
strace ./BINARY          # trace syscalls
ltrace ./BINARY          # trace library calls
strace -e trace=open,read,write ./BINARY
```

## Phase 4 – Exploit Development

### Buffer Overflow (64-bit Linux)
```python
from pwn import *
p = process('./vulnerable')
payload = b'A' * OFFSET
payload += p64(RIP_CONTROL)
p.sendline(payload)
p.interactive()
```

### ROP Chain Discovery
```bash
ROPgadget --binary BINARY --rop
ropper -f BINARY --search "pop rdi"
one_gadget libc.so.6     # find one-shot RCE gadgets
```

### Pwntools Common Patterns
```python
from pwn import *
context.arch = 'amd64'
elf = ELF('./binary')
libc = ELF('./libc.so.6')
p = process('./binary')
# or: p = remote('host', port)
```

## Phase 5 – Memory Forensics (Volatility 3)
```bash
python3 vol.py -f MEMORY_DUMP windows.pslist.PsList
python3 vol.py -f MEMORY_DUMP windows.netscan.NetScan
python3 vol.py -f MEMORY_DUMP windows.cmdline.CmdLine
python3 vol.py -f MEMORY_DUMP windows.dumpfiles.DumpFiles --pid PID
python3 vol.py -f MEMORY_DUMP windows.hashdump.Hashdump
python3 vol.py -f MEMORY_DUMP linux.bash.Bash     # bash history
```

## Phase 6 – File Carving & Steganography
```bash
foremost -i DISK_IMAGE -o /tmp/output    # file carving
binwalk -e FIRMWARE.bin                  # embedded file extraction
steghide info IMAGE.jpg                  # steganography detection
steghide extract -sf IMAGE.jpg           # extract hidden data
zsteg -a IMAGE.png                       # PNG/BMP steg analysis
exiftool IMAGE.jpg                       # metadata inspection
```

### Common CTF Steganography Patterns
- LSB (Least Significant Bit) encoding in RGB channels
- Hidden data in audio (spectrograms via Audacity/Sonic Visualizer)
- ZIP/archive embedded at end of file (check binwalk first)
- Base64/hex/morse in metadata fields

## Common CTF Hash Types
| Hash Length | Format | Likely Type |
|---|---|---|
| 32 chars | hex | MD5 |
| 40 chars | hex | SHA1 |
| 64 chars | hex | SHA256 |
| 60 chars | $2y$... | bcrypt |
| Starts $1$ | | MD5crypt |
| Starts $6$ | | SHA512crypt |

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt   # MD5
hashcat -m 1800 hash.txt wordlist.txt                      # SHA512crypt
```
