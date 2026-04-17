import math
import os

def calculate_entropy(data):
    if not data:
        return 0

    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)

    return entropy


def analyze_file(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    entropy = calculate_entropy(data)
    print(f"{file_path} → Entropy: {entropy:.2f}")


# 🔥 CHANGE THESE PATHS IF NEEDED
folders = [
    r"C:\Sample\Ransomware sample",
    r"C:\Sample\benign"
]

for folder in folders:
    for file in os.listdir(folder):
        file_path = os.path.join(folder, file)
        analyze_file(file_path)