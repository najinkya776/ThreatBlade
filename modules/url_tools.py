import re
import base64
import socket
import urllib.parse
import requests
from colorama import Fore, Style

KNOWN_SHORTENERS = {
    "bit.ly", "bitly.com", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
    "buff.ly", "dlvr.it", "ift.tt", "fb.me", "j.mp", "rebrand.ly",
    "cutt.ly", "tiny.cc", "is.gd", "v.gd", "short.io", "linktr.ee",
    "shorte.st", "adf.ly",
}


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


def _extract_domain(url):
    try:
        netloc = urllib.parse.urlparse(url).netloc.split(":")[0]
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return None


def _enrich_domain(domain):
    result = {}
    try:
        result["ip"] = socket.gethostbyname(domain)
    except Exception:
        result["ip"] = None
    try:
        from modules.dns_tools import whois_lookup_data
        result["whois"] = whois_lookup_data(domain)
    except Exception:
        result["whois"] = None
    try:
        from modules.reputation import check_virustotal_data
        result["virustotal"] = check_virustotal_data(domain, "domain")
    except Exception:
        pass
    return result


def expand_short_url(url, enrich=False):
    """Follow redirects and return the full chain with status codes, headers, and analysis."""
    try:
        with requests.get(url, allow_redirects=True, timeout=10, stream=True) as r:
            hops = [
                {
                    "url": resp.url,
                    "status_code": resp.status_code,
                    "location": resp.headers.get("Location"),
                }
                for resp in r.history
            ]
            final = r.url

        all_urls = [h["url"] for h in hops] + [final]
        flags = {
            "too_many_redirects": len(hops) > 5,
            "https_downgrade": any(
                all_urls[i].startswith("https://") and all_urls[i + 1].startswith("http://")
                for i in range(len(all_urls) - 1)
            ),
            "known_shorteners": sorted({
                _extract_domain(u) for u in all_urls if _extract_domain(u) in KNOWN_SHORTENERS
            }),
        }

        result = {"hops": hops, "final": final, "count": len(hops), "flags": flags}

        if enrich:
            unique_domains = sorted({_extract_domain(u) for u in all_urls if _extract_domain(u)})
            result["enrichment"] = {d: _enrich_domain(d) for d in unique_domains}

        return result
    except requests.RequestException as e:
        return {"error": str(e)}


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
        enrich = input("Include domain enrichment? (WHOIS + IP + VT) [y/N]: ").strip().lower() == "y"
        print(f"{Fore.CYAN}[*] Following redirects...{Style.RESET_ALL}")
        result = expand_short_url(url, enrich=enrich)
        if "error" in result:
            print(f"\n{Fore.RED}[!] {result['error']}{Style.RESET_ALL}")
        elif result["count"] == 0:
            print(f"\n{Fore.GREEN}[+] No redirects — resolves directly: {result['final']}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[+] Redirect chain ({result['count']} hop(s)):{Style.RESET_ALL}")
            for i, hop in enumerate(result["hops"], 1):
                print(f"  {Fore.YELLOW}[Hop {i}]{Style.RESET_ALL} {hop['url']}  [{hop['status_code']}]")
                if hop.get("location"):
                    print(f"          {Fore.CYAN}Location: {hop['location']}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}[Final]  {result['final']}{Style.RESET_ALL}")
        flags = result.get("flags", {})
        if flags.get("too_many_redirects"):
            print(f"\n  {Fore.RED}[!] WARNING: Too many redirects (>5){Style.RESET_ALL}")
        if flags.get("https_downgrade"):
            print(f"  {Fore.RED}[!] WARNING: HTTPS → HTTP downgrade detected{Style.RESET_ALL}")
        if flags.get("known_shorteners"):
            print(f"  {Fore.YELLOW}[!] Known shorteners detected: {', '.join(flags['known_shorteners'])}{Style.RESET_ALL}")
        if enrich and "enrichment" in result:
            print(f"\n{Fore.CYAN}[*] Domain Enrichment:{Style.RESET_ALL}")
            for domain, info in result["enrichment"].items():
                print(f"\n  {Fore.YELLOW}{domain}{Style.RESET_ALL}")
                print(f"    IP      : {info.get('ip') or 'N/A'}")
                w = info.get("whois") or {}
                if w and "error" not in w:
                    if w.get("registrar"): print(f"    Registrar: {w['registrar']}")
                    if w.get("creation_date"): print(f"    Created : {w['creation_date']}")
                    if w.get("country"): print(f"    Country : {w['country']}")
                vt = info.get("virustotal") or {}
                if vt and "error" not in vt:
                    print(f"    VT      : {vt.get('malicious', 0)} malicious / {vt.get('total', 0)} total")
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
