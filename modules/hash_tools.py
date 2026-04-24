import hashlib
import os
import requests
import time
from colorama import Fore, Style
from config.settings import get_key


def hash_file(filepath):
    """Compute MD5, SHA1, SHA256 of a file."""
    if not os.path.isfile(filepath):
        print(f"{Fore.RED}[!] File not found: {filepath}{Style.RESET_ALL}")
        return None

    hashes = {"MD5": hashlib.md5(), "SHA1": hashlib.sha1(), "SHA256": hashlib.sha256()}
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                for h in hashes.values():
                    h.update(chunk)

        print(f"\n{Fore.CYAN}[ File Hashes: {os.path.basename(filepath)} ]{Style.RESET_ALL}")
        results = {}
        for name, h in hashes.items():
            digest = h.hexdigest()
            results[name] = digest
            print(f"  {Fore.YELLOW}{name:<8}{Style.RESET_ALL}: {digest}")
        return results
    except PermissionError:
        print(f"{Fore.RED}[!] Permission denied reading file.{Style.RESET_ALL}")
        return None


def hash_string(text, encoding="utf-8"):
    """Hash a string with MD5, SHA1, SHA256."""
    data = text.encode(encoding)
    print(f"\n{Fore.CYAN}[ String Hashes ]{Style.RESET_ALL}")
    for name, func in [("MD5", hashlib.md5), ("SHA1", hashlib.sha1), ("SHA256", hashlib.sha256)]:
        print(f"  {Fore.YELLOW}{name:<8}{Style.RESET_ALL}: {func(data).hexdigest()}")


def check_hash_virustotal(file_hash):
    """Check a hash on VirusTotal."""
    api_key = get_key("virustotal_api_key")
    if not api_key:
        print(f"{Fore.YELLOW}[!] VirusTotal API key not set.{Style.RESET_ALL}")
        return

    headers = {"x-apikey": api_key}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            color = Fore.RED if malicious > 0 else Fore.GREEN
            print(f"\n{Fore.CYAN}[ VirusTotal Hash Report ]{Style.RESET_ALL}")
            print(f"  Name        : {data.get('meaningful_name', 'N/A')}")
            print(f"  File Type   : {data.get('type_description', 'N/A')}")
            print(f"  Size        : {data.get('size', 'N/A')} bytes")
            print(f"  {Fore.RED}Malicious   : {malicious}/{total}{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}Suspicious  : {stats.get('suspicious', 0)}/{total}{Style.RESET_ALL}")
            print(f"  First Seen  : {data.get('first_submission_date', 'N/A')}")
        elif r.status_code == 404:
            print(f"{Fore.YELLOW}[!] Hash not found in VirusTotal.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] VT error: {r.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Request failed: {e}{Style.RESET_ALL}")


def check_hash_virustotal_data(file_hash):
    api_key = get_key("virustotal_api_key")
    if not api_key:
        return {"error": "VirusTotal API key not configured."}
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, timeout=10)
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "found": True,
                "name": attrs.get("meaningful_name", "N/A"),
                "type": attrs.get("type_description", "N/A"),
                "size": attrs.get("size"),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total": sum(stats.values()),
                "first_seen": str(attrs.get("first_submission_date", "N/A")),
            }
        elif r.status_code == 404:
            return {"found": False, "message": "Hash not found in VirusTotal."}
        return {"error": f"VT error: {r.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def hash_string_data(text):
    data = text.encode("utf-8")
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def hash_menu():
    print(f"\n{Fore.CYAN}=== File Hash & Reputation ==={Style.RESET_ALL}")
    print("  [1] Hash a file")
    print("  [2] Hash a string")
    print("  [3] Check hash on VirusTotal")
    print("  [4] Hash file + check on VirusTotal")
    print("  [0] Back")
    choice = input(f"\n{Fore.GREEN}Select > {Style.RESET_ALL}").strip()

    if choice == "0":
        return
    elif choice == "1":
        path = input("Enter file path: ").strip().strip('"')
        hash_file(path)
    elif choice == "2":
        text = input("Enter string to hash: ").strip()
        hash_string(text)
    elif choice == "3":
        h = input("Enter hash (MD5/SHA1/SHA256): ").strip()
        check_hash_virustotal(h)
    elif choice == "4":
        path = input("Enter file path: ").strip().strip('"')
        result = hash_file(path)
        if result:
            check_hash_virustotal(result["SHA256"])
    else:
        print(f"{Fore.RED}[!] Invalid option.{Style.RESET_ALL}")
