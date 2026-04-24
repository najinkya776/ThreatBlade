import requests
import hashlib
from colorama import Fore, Style
from config.settings import get_key


def check_hibp_email(email_address):
    """Check if an email has been in a data breach via HIBP v3 API."""
    api_key = get_key("hibp_api_key")
    if not api_key:
        print(f"{Fore.YELLOW}[!] HIBP API key not set. Get one at https://haveibeenpwned.com/API/Key{Style.RESET_ALL}")
        return

    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "threatBlade-SOC-Tool",
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email_address)}"

    try:
        r = requests.get(url, headers=headers, params={"truncateResponse": False}, timeout=10)
        if r.status_code == 200:
            breaches = r.json()
            print(f"\n{Fore.RED}[!] {email_address} found in {len(breaches)} breach(es):{Style.RESET_ALL}")
            for b in breaches:
                print(f"\n  {Fore.YELLOW}[{b.get('Name')}]{Style.RESET_ALL}")
                print(f"    Domain       : {b.get('Domain', 'N/A')}")
                print(f"    Breach Date  : {b.get('BreachDate', 'N/A')}")
                print(f"    PwnCount     : {b.get('PwnCount', 'N/A'):,}")
                data_classes = b.get("DataClasses", [])
                print(f"    Data Types   : {', '.join(data_classes)}")
                print(f"    Verified     : {b.get('IsVerified', False)}")
                print(f"    Sensitive    : {b.get('IsSensitive', False)}")
        elif r.status_code == 404:
            print(f"\n{Fore.GREEN}[+] {email_address} not found in any known breaches.{Style.RESET_ALL}")
        elif r.status_code == 401:
            print(f"{Fore.RED}[!] Invalid HIBP API key.{Style.RESET_ALL}")
        elif r.status_code == 429:
            print(f"{Fore.YELLOW}[!] Rate limited by HIBP. Wait a moment and try again.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] HIBP error: {r.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Request failed: {e}{Style.RESET_ALL}")


def check_hibp_password(password):
    """Check if a password has been exposed using k-anonymity (Pwned Passwords)."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
        if r.status_code == 200:
            hashes = r.text.splitlines()
            for h in hashes:
                h_suffix, count = h.split(":")
                if h_suffix == suffix:
                    print(f"\n{Fore.RED}[!] Password found in {int(count):,} breach(es). Do NOT use it.{Style.RESET_ALL}")
                    return
            print(f"\n{Fore.GREEN}[+] Password not found in known breach databases.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Pwned Passwords API error: {r.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Request failed: {e}{Style.RESET_ALL}")


def check_hibp_domain(domain):
    """List all breaches associated with a domain."""
    api_key = get_key("hibp_api_key")
    if not api_key:
        print(f"{Fore.YELLOW}[!] HIBP API key not set.{Style.RESET_ALL}")
        return

    headers = {"hibp-api-key": api_key, "User-Agent": "threatBlade-SOC-Tool"}
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breaches",
            headers=headers,
            params={"domain": domain},
            timeout=10,
        )
        if r.status_code == 200:
            breaches = r.json()
            if breaches:
                print(f"\n{Fore.RED}[!] Domain {domain} found in {len(breaches)} breach(es):{Style.RESET_ALL}")
                for b in breaches:
                    print(f"  - {b.get('Name')} ({b.get('BreachDate')}) — {b.get('PwnCount', 0):,} accounts")
            else:
                print(f"\n{Fore.GREEN}[+] No breaches found for domain {domain}.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] HIBP error: {r.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Request failed: {e}{Style.RESET_ALL}")


def check_hibp_email_data(email_address):
    api_key = get_key("hibp_api_key")
    if not api_key:
        return {"error": "HIBP API key not configured."}
    headers = {"hibp-api-key": api_key, "User-Agent": "threatBlade-SOC-Tool"}
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email_address)}",
            headers=headers, params={"truncateResponse": False}, timeout=10
        )
        if r.status_code == 200:
            return {"found": True, "breaches": r.json()}
        elif r.status_code == 404:
            return {"found": False, "breaches": []}
        elif r.status_code == 401:
            return {"error": "Invalid HIBP API key."}
        elif r.status_code == 429:
            return {"error": "Rate limited by HIBP. Try again shortly."}
        return {"error": f"HIBP error: {r.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def check_hibp_domain_data(domain):
    api_key = get_key("hibp_api_key")
    if not api_key:
        return {"error": "HIBP API key not configured."}
    headers = {"hibp-api-key": api_key, "User-Agent": "threatBlade-SOC-Tool"}
    try:
        r = requests.get("https://haveibeenpwned.com/api/v3/breaches",
                         headers=headers, params={"domain": domain}, timeout=10)
        if r.status_code == 200:
            return {"breaches": r.json()}
        return {"error": f"HIBP error: {r.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def check_password_data(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
        if r.status_code == 200:
            for line in r.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return {"found": True, "count": int(count)}
            return {"found": False, "count": 0}
        return {"error": f"Pwned Passwords API error: {r.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def breach_menu():
    print(f"\n{Fore.CYAN}=== Breach / Credential Check ==={Style.RESET_ALL}")
    print("  [1] Check email address (HIBP)")
    print("  [2] Check password exposure (k-anonymity, safe)")
    print("  [3] Check domain for breaches")
    print("  [0] Back")
    choice = input(f"\n{Fore.GREEN}Select > {Style.RESET_ALL}").strip()

    if choice == "0":
        return
    elif choice == "1":
        em = input("Enter email address: ").strip()
        check_hibp_email(em)
    elif choice == "2":
        import getpass
        pw = getpass.getpass("Enter password (hidden): ")
        check_hibp_password(pw)
    elif choice == "3":
        domain = input("Enter domain (e.g. example.com): ").strip()
        check_hibp_domain(domain)
    else:
        print(f"{Fore.RED}[!] Invalid option.{Style.RESET_ALL}")
