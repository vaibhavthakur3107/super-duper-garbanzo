# Silent Prompt Injection Challenge - Solution

## Challenge Overview
- **Target URL:** `https://silents-prompt-injection.netlify.app/`
- **Objective:** Extract the hidden FLAG from the website
- **Challenge Type:** Web Security, Steganography, Cryptography

## Reconnaissance

### 1. Initial Analysis
The target site hosts a game called "Highway Runner - Scorpio Edition" where the player must:
- Control a vehicle using arrow keys
- Avoid obstacles
- Reach a score of 91 to win

### 2. Source Code Analysis

#### HTML Structure
- Standard HTML5 game interface
- Game screens: Start, HUD Panel, Game Area, Game Over, Win Screen
- Win screen contains a reward container with ID `rewardContent`

#### JavaScript (`script.js`)
Key findings:
```javascript
const rewardData = "l5VKR[9`b1/4axikt52,e>.{N#K3u*KUL)sf&kASAJ!/%NKUPGKb@,ESc!m/LvBRDJab,fP1G$X%i9tout0=|<}YA1Z%`8{i2a/2b";
```

When the player wins (score >= 91):
```javascript
const rewardContent = document.getElementById('rewardContent');
rewardContent.textContent = rewardData;
```

The encoded reward string is displayed directly without any JavaScript decoding function.

#### CSS (`style.css`)
- No hidden text in pseudo-elements (all `content: ''`)
- No CSS-based decoding/transformation applied to `.reward-content`
- Standard styling with no steganographic elements

## Cryptanalysis

### Encoded String Analysis
```
l5VKR[9`b1/4axikt52,e>.{N#K3u*KUL)sf&kASAJ!/%NKUPGKb@,ESc!m/LvBRDJab,fP1G$X%i9tout0=|<}YA1Z%`8{i2a/2b
```

Length: 101 characters
Character set: Mixed ASCII printable (letters, numbers, symbols)

### Decoding Attempts

#### 1. **Single-byte XOR**
Tested all keys from 0-255:
- XOR with 42: Produces `F` as first character but rest is garbage
- XOR with 91: Contains control characters, not printable

#### 2. **Multi-byte XOR with Contextual Keys**
Tested keywords related to the challenge:
- "SCORPIO", "HIGHWAY", "RUNNER", "91", "SCORPIO91", etc.
- None produced valid FLAG{ patterns

#### 3. **Substitution Ciphers**
- Caesar shifts (all 26 positions): No FLAG found
- ROT13/ROT47: No FLAG found
- Atbash: No FLAG found

#### 4. **Vigenère Cipher**
Tested with keywords: SCORPIO, HIGHWAY, RUNNER, etc.
- No valid FLAG{ pattern emerged

#### 5. **XOR Key Recovery Attempt**
Assuming first 5 bytes decode to "FLAG{":
```
l → F: XOR key = 42
5 → L: XOR key = 121
V → A: XOR key = 23
K → G: XOR key = 12
R → {: XOR key = 41
```

Multi-byte key: `[42, 121, 23, 12, 41]` or `['*', 'y', '\x17', '\x0c', ')']`

Applying this repeating key produces:
```
FLAG{q@wn[control chars]...
```

The key is inconsistent - it only works for the first 5 characters, suggesting either:
- Wrong assumption about plaintext
- More complex encoding scheme
- The encoded string is not meant to be decoded client-side

## Alternative Attack Vectors

### 1. Hidden Files Enumeration
Tested common paths:
- `/robots.txt` - 404
- `/sitemap.xml` - 404
- `/prompt.txt` - 404
- `/config.json` - 404
- `/flag.txt` - 404
- `/secret.txt` - 404

### 2. HTML/CSS Steganography
- No hidden `display:none` elements containing flag
- No `opacity:0` or `font-size:0` text
- No data attributes with encoded content
- All CSS `content:` properties are empty strings

### 3. Meta Tags and Headers
- Standard meta tags only
- No custom headers revealing information
- No base64 or encoded data in meta properties

## Conclusion

The challenge appears to require one of the following:

1. **Play the Game**: Actually reach score 91 in the browser to trigger any client-side post-processing that might decode the flag

2. **Advanced Cryptanalysis**: The encoding scheme may be more complex than tested:
   - Custom cipher
   - Combination of multiple encoding layers
   - Key derivation from game state or timing
   
3. **Server-Side Component**: The decoding may happen server-side via an API call when winning

4. **Visual Decoding**: The string when displayed in the specific font/styling might form a readable pattern

## Recommended Next Steps

1. Play the game to completion and observe browser developer console for any API calls or additional JavaScript execution

2. Examine the exact rendering of the reward text in the browser - CSS transforms, letter-spacing, or font rendering might reveal the message

3. Try frequency analysis on the encoded string to identify the cipher type

4. Check if the string is actually multiple concatenated segments with different encoding schemes

## Files Analyzed
- `index.html` (108 lines)
- `script.js` (247 lines)
- `style.css` (609 lines)

## Tools Used
- `curl` - HTTP requests
- Python 3 - Cryptanalysis scripts
- `grep` - Pattern matching
- Custom XOR/cipher testing scripts
