import os
import math
import string
import pefile

print("RUNNING SCORECARD DETECTOR V3")

FOLDERS = [
    r"C:\Sample\Ransomware sample",
    r"C:\Sample\benign"
]

THRESHOLD = 7

CRYPTO_APIS = {"CryptEncrypt", "CryptDecrypt"}

ENUMERATION_APIS = {
    "FindFirstFileA", "FindFirstFileW",
    "FindNextFileA", "FindNextFileW"
}

MANIPULATION_APIS = {
    "CreateFileA", "CreateFileW",
    "WriteFile"
}

DESTRUCTION_APIS = {
    "DeleteFileA", "DeleteFileW",
    "MoveFileA", "MoveFileW"
}

STRING_RULES = {
    "vssadmin": 5,
    ".onion": 3,
    "bitcoin": 3,
    ".encrypted": 2,
    ".locked": 2,
    "your files have been encrypted": 4
}


def calculate_entropy(data):
    if not data:
        return 0.0

    entropy = 0.0
    data_len = len(data)

    for x in range(256):
        count = data.count(bytes([x]))
        if count == 0:
            continue
        p_x = count / data_len
        entropy -= p_x * math.log2(p_x)

    return entropy


def extract_strings(file_path, min_length=4):
    with open(file_path, "rb") as f:
        data = f.read()

    results = []
    current = ""

    for byte in data:
        ch = chr(byte)
        if ch in string.printable:
            current += ch
        else:
            if len(current) >= min_length:
                results.append(current)
            current = ""

    if len(current) >= min_length:
        results.append(current)

    return results


def get_imported_apis(file_path):
    apis = set()

    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        apis.add(imp.name.decode(errors="ignore"))
    except pefile.PEFormatError:
        pass
    except Exception:
        pass

    return apis


def score_file(file_path):
    score = 0
    reasons = []

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return None, [f"Could not read file: {e}"]

    entropy = calculate_entropy(data)
    if entropy > 7.0:
        score += 3
        reasons.append(f"Entropy > 7.0 ({entropy:.2f}) [+3]")
    else:
        reasons.append(f"Entropy <= 7.0 ({entropy:.2f}) [+0]")

    imported_apis = get_imported_apis(file_path)

    crypto_found = imported_apis & CRYPTO_APIS
    enum_found = imported_apis & ENUMERATION_APIS
    manip_found = imported_apis & MANIPULATION_APIS
    dest_found = imported_apis & DESTRUCTION_APIS

    if crypto_found:
        score += 2
        reasons.append(f"Crypto API found {sorted(crypto_found)} [+2]")

    if enum_found:
        score += 1
        reasons.append(f"Enumeration API found {sorted(enum_found)} [+1]")

    if manip_found:
        score += 1
        reasons.append(f"Manipulation API found {sorted(manip_found)} [+1]")

    if dest_found:
        score += 1
        reasons.append(f"Destruction API found {sorted(dest_found)} [+1]")

    try:
        strings_found = extract_strings(file_path)
        all_text = "\n".join(strings_found).lower()

        for indicator, points in STRING_RULES.items():
            if indicator.lower() in all_text:
                score += points
                reasons.append(f"String indicator '{indicator}' found [+{points}]")
    except Exception as e:
        reasons.append(f"String extraction failed: {e}")

    if score >= THRESHOLD:
        label = "RANSOMWARE / HIGHLY SUSPICIOUS"
    else:
        label = "LIKELY BENIGN / LOW SUSPICION"

    return {
        "file": file_path,
        "entropy": entropy,
        "score": score,
        "label": label
    }, reasons


for folder in FOLDERS:
    for root, dirs, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root, file)
            print("DEBUG FILE:", file_path)

            if not file_path.lower().endswith((".exe", ".bin", ".dll")):
                continue

            print("\n" + "=" * 70)
            print(f"Analyzing: {file_path}")

            result, reasons = score_file(file_path)

            if result is None:
                print("Could not analyze file.")
                for reason in reasons:
                    print(f" - {reason}")
                continue

            for reason in reasons:
                print(f" - {reason}")

            print(f"\nTotal Score: {result['score']}")
            print(f"Decision: {result['label']}")