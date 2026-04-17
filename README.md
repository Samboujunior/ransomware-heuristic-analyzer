# Ransomware Heuristic Analyzer

## Overview
This project implements a lightweight ransomware detection system using static analysis and heuristic scoring. The goal is to identify suspicious executable files without executing them, based on observable features such as entropy, API usage, and embedded strings.

The system analyzes binaries and assigns a score that reflects how likely a file is to behave like ransomware.

---

## Features
- Entropy analysis (detects packed/encrypted files)
- Import Address Table (IAT) inspection (detects suspicious APIs)
- String extraction (detects indicators like "bitcoin", ".onion", etc.)
- Behavioral workflow approximation (file enumeration, modification, deletion)
- Heuristic scoring system

---

## Project Structure

Ransomware-Heuristic-Analyzer/
├── scorecard_detector.py
├── entropy_checker.py
├── string_checker.py
├── workflow_checker.py
├── README.md
└── screenshots/


---

## How to Run

1. Create the following folders on your system:

C:\Sample\Ransomware sample
C:\Sample\benign\


2. Place files:
- Put ransomware samples (.bin or .exe) inside:
  `C:\Sample\Ransomware sample\`
- Put benign files (e.g., calc.exe, cmd.exe, notepad.exe) inside:
  `C:\Sample\benign\`

3. Run the script:

python scorecard_detector.py


---

## Scoring System

The detection system assigns points based on extracted features:

- Entropy > 7.0 → +3
- Crypto APIs → +2
- Enumeration APIs → +1
- Manipulation APIs → +1
- Destruction APIs → +1
- Suspicious strings → +2 to +5

### Decision Rule
- Score ≥ 7 → Ransomware / Highly Suspicious
- Score < 7 → Likely Benign

---

## Results

- Most benign files were correctly classified with low scores
- Some benign files produced moderate scores due to normal file operations (false positives)
- Some ransomware samples were only partially detected due to obfuscation or lack of visible features

This demonstrates that detection is not perfect and depends on observable characteristics.


## Notes

- Malware samples are NOT included for safety reasons
- Public datasets such as TheZoo can be used to reproduce results
- Files can be renamed to `.bin` to avoid antivirus interference

---

## Conclusion

This project demonstrates that ransomware detection can be approximated using static heuristic analysis. While the system can identify certain suspicious behaviors, it also highlights limitations such as false positives and undetected malware.

The results show that combining multiple features improves detection, but no single method is sufficient. This approach can serve as a simple and interpretable first layer of defense.