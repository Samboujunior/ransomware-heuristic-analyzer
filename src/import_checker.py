import pefile
import os

SUSPICIOUS_APIS = {
    "CryptEncrypt",
    "CryptDecrypt",
    "FindFirstFileA",
    "FindFirstFileW",
    "FindNextFileA",
    "FindNextFileW",
    "CreateFileA",
    "CreateFileW",
    "WriteFile",
    "DeleteFileA",
    "DeleteFileW",
    "MoveFileA",
    "MoveFileW",
    "TerminateProcess",
    "ShellExecuteA",
    "ShellExecuteW"
}

folders = [
    r"C:\Sample\Ransomware sample",
    r"C:\Sample\benign"
]

def analyze_imports(file_path):
    print(f"\n--- Analyzing: {file_path} ---")

    try:
        pe = pefile.PE(file_path)

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            print("No import table found.")
            return

        found_suspicious = []

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore")
            print(f"[DLL] {dll_name}")

            for imp in entry.imports:
                if imp.name:
                    api_name = imp.name.decode(errors="ignore")
                    print(f"    {api_name}")

                    if api_name in SUSPICIOUS_APIS:
                        found_suspicious.append(api_name)

        if found_suspicious:
            print("Suspicious APIs found:")
            for api in sorted(set(found_suspicious)):
                print(f"  -> {api}")
        else:
            print("No suspicious APIs found.")

    except pefile.PEFormatError:
        print("Not a valid PE file. Skipping.")
    except Exception as e:
        print(f"Error: {e}")

for folder in folders:
    for file in os.listdir(folder):
        file_path = os.path.join(folder, file)

        if file_path.lower().endswith((".exe", ".dll")):
            analyze_imports(file_path)
        else:
            print(f"\nSkipping non-PE file: {file_path}")