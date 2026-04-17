import os
import string

SUSPICIOUS_STRINGS = [
    ".onion",
    ".encrypted",
    ".locked",
    "bitcoin",
    "ransom",
    "decrypt",
    "payment",
    "your files",
    "recover files"
]

def extract_strings(file_path, min_length=4):
    with open(file_path, "rb") as f:
        data = f.read()

    result = []
    current = ""

    for byte in data:
        char = chr(byte)
        if char in string.printable:
            current += char
        else:
            if len(current) >= min_length:
                result.append(current)
            current = ""

    return result


def analyze_strings(file_path):
    print(f"\n--- Analyzing: {file_path} ---")

    try:
        strings = extract_strings(file_path)

        found = []

        for s in strings:
            for keyword in SUSPICIOUS_STRINGS:
                if keyword.lower() in s.lower():
                    found.append(s)

        if found:
            print("Suspicious strings found:")
            for s in found[:10]:  # limit output
                print(f"  -> {s}")
        else:
            print("No suspicious strings found.")

    except Exception as e:
        print(f"Error: {e}")


folders = [
    r"C:\Sample\Ransomware sample",
    r"C:\Sample\benign"
]

for folder in folders:
    for root, dirs, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root, file)
            analyze_strings(file_path)