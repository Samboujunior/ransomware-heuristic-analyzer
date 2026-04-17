import pefile
import os

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

folders = [
    r"C:\Sample\Ransomware sample",
    r"C:\Sample\benign"
]

def analyze_workflow(file_path):
    print(f"\n--- Analyzing: {file_path} ---")

    try:
        pe = pefile.PE(file_path)

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            print("No imports found.")
            return

        found_enum = False
        found_manip = False
        found_dest = False

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    api = imp.name.decode(errors="ignore")

                    if api in ENUMERATION_APIS:
                        found_enum = True
                    if api in MANIPULATION_APIS:
                        found_manip = True
                    if api in DESTRUCTION_APIS:
                        found_dest = True

        print(f"Enumeration: {found_enum}")
        print(f"Manipulation: {found_manip}")
        print(f"Destruction: {found_dest}")

        score = 0
        if found_enum:
            score += 1
        if found_manip:
            score += 1
        if found_dest:
            score += 2

        print(f"Workflow score: {score}")

        if score >= 4:
            print("🚨 Strong ransomware indicator")
        elif score >= 3:
            print("⚠️ Suspicious behavior")
        else:
            print("No strong ransomware workflow detected")

    except pefile.PEFormatError:
        print("Not a PE file. Skipping.")
    except Exception as e:
        print(f"Error: {e}")

for folder in folders:
    for file in os.listdir(folder):
        file_path = os.path.join(folder, file)

        if file_path.lower().endswith((".exe", ".bin")):
            analyze_workflow(file_path)
        else:
            print(f"\nSkipping non-PE file: {file_path}")