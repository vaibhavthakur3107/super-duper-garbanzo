# Silent Prompt Injection Challenge Analysis

This repository contains analysis and tooling for the "Silent Prompt Injection" CTF challenge hosted at `https://silents-prompt-injection.netlify.app/`.

## Challenge Description

The challenge presents a browser-based game called "Highway Runner - Scorpio Edition" where players must navigate a vehicle to reach a score of 91. Upon winning, an encoded reward string is displayed that allegedly contains the flag.

**Key Indicators:**
- Challenge name suggests prompt injection vulnerability
- Description mentions "smallest details" hinting at steganography
- Encoded reward string stored in client-side JavaScript
- No obvious decoding mechanism in the source code

## Repository Contents

### `SOLUTION.md`
Comprehensive write-up documenting:
- Reconnaissance findings
- Source code analysis (HTML, JavaScript, CSS)
- Cryptanalysis attempts and results
- Alternative attack vectors explored
- Conclusions and recommendations

### `decoder.py`
Automated Python script that attempts multiple decoding methods:
- Single-byte XOR (all 256 keys)
- Multi-byte XOR with contextual keywords
- Caesar cipher (all shifts)
- ROT47
- Vigenère cipher
- Atbash cipher
- XOR key derivation from known plaintext

## Usage

### Run the Decoder

```bash
python3 decoder.py
```

The script will systematically test various decoding methods and report any findings.

### Manual Analysis

1. **Access the Challenge:**
   ```bash
   curl -s https://silents-prompt-injection.netlify.app/ > challenge.html
   curl -s https://silents-prompt-injection.netlify.app/script.js > script.js
   curl -s https://silents-prompt-injection.netlify.app/style.css > style.css
   ```

2. **Extract the Encoded String:**
   ```bash
   grep "rewardData" script.js
   ```

3. **Test Custom Decoding:**
   ```python
   encoded = "l5VKR[9`b1/4axikt52,e>.{N#K3u*KUL)sf&kASAJ!/%NKUPGKb@,ESc!m/LvBRDJab,fP1G$X%i9tout0=|<}YA1Z%`8{i2a/2b"
   # Your decoding logic here
   ```

## Challenge Insights

### Encoded String Properties
- **Length:** 101 characters
- **Character Set:** Mixed ASCII printable (letters, digits, punctuation)
- **Entropy:** High, suggesting strong encryption or encoding
- **Context:** Displayed in-game after reaching score 91

### Failed Approaches
1. **Simple Ciphers:** Caesar, ROT13, ROT47, Atbash - no valid output
2. **Single-byte XOR:** Tested all 256 keys - no clean FLAG{ pattern
3. **Contextual Multi-byte XOR:** Keywords like SCORPIO, HIGHWAY, 91 - no success
4. **Hidden Content:** No steganography in CSS/HTML
5. **Hidden Files:** Common paths (robots.txt, flag.txt, etc.) return 404

### Potential Solutions

1. **Play to Win:** Complete the game in-browser to trigger any dynamic decoding
2. **Advanced Cryptanalysis:** The cipher may be custom or layered
3. **Server-Side Decoding:** An API endpoint might process the score/time
4. **Visual Rendering:** The font/styling might encode the message when displayed

## Technical Details

### Game Mechanics
- Arrow keys control vehicle movement
- Three lanes of traffic
- Obstacles spawn randomly
- Score increases with distance traveled
- Win condition: Score ≥ 91

### Source Files
- `index.html`: 108 lines
- `script.js`: 247 lines  
- `style.css`: 609 lines

### Encoded Reward Location
```javascript
// In script.js
const rewardData = "l5VKR[9`b1/4axikt52,e>.{N#K3u*KUL)sf&kASAJ!/%NKUPGKb@,ESc!m/LvBRDJab,fP1G$X%i9tout0=|<}YA1Z%`8{i2a/2b";

// Displayed on win
function endGame(isWin) {
    if (isWin) {
        const rewardContent = document.getElementById('rewardContent');
        rewardContent.textContent = rewardData;
        winScreen.classList.add('active');
    }
}
```

## Tools & Technologies

- **Python 3:** Cryptanalysis and automation
- **curl:** HTTP requests and file retrieval
- **grep:** Pattern matching and extraction
- **Standard crypto libraries:** base64, itertools

## Contributing

If you solve this challenge or discover new attack vectors, please document your findings and submit a pull request.

## License

This analysis is for educational purposes only. All rights to the original challenge belong to its creator.

## Contact

For questions or collaboration, open an issue in this repository.
