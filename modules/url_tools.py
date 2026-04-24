import re
import base64
import urllib.parse
import requests
from colorama import Fore, Style


def sanitize_url(url):
    """Replace . with [.] and http with hxxp for safe sharing."""
    safe = url.replace("http", "hxxp").replace(".", "[.]")
    return safe


def desanitize_url(url):
    """Restore a defanged URL."""
    restored = url.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".")
    return restored


def decode_proofpoint(url):
    """Decode ProofPoint URL Defense encoded URLs."""
    # v2 format
    pp_v2 = re.search(r"https://urldefense\.proofpoint\.com/v2/url\?u=(.+?)&d=", url)
    # v3 format
    pp_v3 = re.search(r"https://urldefense\.com/v3/__(.+?)__;", url)

    if pp_v2:
        encoded = pp_v2.group(1).replace("-", "%").replace("_", "/")
        decoded = urllib.parse.unquote(encoded)
        return decoded
    elif pp_v3:
        decoded = pp_v3.group(1)
        return decoded
    return None


def decode_safelinks(url):
    """Decode Microsoft Office 365 SafeLinks URLs."""
    if "safelinks.protection.outlook.com" in url:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        original = params.get("url", [None])[0]
        if original:
            return urllib.parse.unquote(original)
    return None


def decode_base64_url(encoded):
    """Attempt to decode a base64-encoded URL."""
    try:
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += "=" * padding
        decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
        if decoded.startswith("http"):
            return decoded
    except Exception:
        pass
    return None


def expand_short_url(url):
    """Follow redirects to find the final destination URL."""
    try:
        r = requests.head(url, allow_redirects=True, timeout=10)
        if r.url != url:
            return r.url
        return url
    except requests.RequestException as e:
        return f"Error: {e}"


def extract_urls(text):
    """Extract all URLs from a block of text."""
    pattern = r'https?://[^\s\'"<>]+'
    return re.findall(pattern, text)


def url_menu():
    print(f"\n{Fore.CYAN}=== URL Tools ==={Style.RESET_ALL}")
    print("  [1] Sanitize URL (defang)")
    print("  [2] Desanitize URL (refang)")
    print("  [3] Decode ProofPoint URL")
    print("  [4] Decode Office 365 SafeLinks")
    print("  [5] Decode Base64 URL")
    print("  [6] Expand Shortened URL")
    print("  [7] Extract URLs from text")
    print("  [0] Back")
    choice = input(f"\n{Fore.GREEN}Select > {Style.RESET_ALL}").strip()

    if choice == "0":
        return
    elif choice == "1":
        url = input("Enter URL to sanitize: ").strip()
        print(f"\n{Fore.GREEN}[+] Sanitized: {sanitize_url(url)}{Style.RESET_ALL}")
    elif choice == "2":
        url = input("Enter defanged URL to restore: ").strip()
        print(f"\n{Fore.GREEN}[+] Restored: {desanitize_url(url)}{Style.RESET_ALL}")
    elif choice == "3":
        url = input("Enter ProofPoint URL: ").strip()
        result = decode_proofpoint(url)
        if result:
            print(f"\n{Fore.GREEN}[+] Decoded: {result}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Not a recognized ProofPoint URL format.{Style.RESET_ALL}")
    elif choice == "4":
        url = input("Enter SafeLinks URL: ").strip()
        result = decode_safelinks(url)
        if result:
            print(f"\n{Fore.GREEN}[+] Decoded: {result}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Not a recognized SafeLinks URL.{Style.RESET_ALL}")
    elif choice == "5":
        encoded = input("Enter Base64 string: ").strip()
        result = decode_base64_url(encoded)
        if result:
            print(f"\n{Fore.GREEN}[+] Decoded: {result}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Could not decode as URL.{Style.RESET_ALL}")
    elif choice == "6":
        url = input("Enter shortened URL: ").strip()
        print(f"{Fore.CYAN}[*] Following redirects...{Style.RESET_ALL}")
        result = expand_short_url(url)
        print(f"\n{Fore.GREEN}[+] Final destination: {result}{Style.RESET_ALL}")
    elif choice == "7":
        print("Paste text (enter a blank line when done):")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        text = "\n".join(lines)
        urls = extract_urls(text)
        if urls:
            print(f"\n{Fore.GREEN}[+] Found {len(urls)} URL(s):{Style.RESET_ALL}")
            for u in urls:
                print(f"  {u}")
        else:
            print(f"{Fore.YELLOW}[!] No URLs found.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] Invalid option.{Style.RESET_ALL}")
