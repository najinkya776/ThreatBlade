import requests
import socket
from colorama import Fore, Style
from config.settings import get_key


TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
KNOWN_BLACKLISTS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
    "dnsbl-1.uceprotect.net",
    "psbl.surriel.com",
    "all.s5h.net",
    "ix.dnsbl.manitu.net",
    "truncate.gbudb.net",
    "db.wpbl.info",
]


def geoip_lookup(ip):
    """Get geolocation and ASN info for an IP using ip-api.com (free, no key needed)."""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66842623", timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                print(f"\n{Fore.CYAN}[ GeoIP: {ip} ]{Style.RESET_ALL}")
                fields = {
                    "Country": f"{data.get('country')} ({data.get('countryCode')})",
                    "Region": data.get("regionName"),
                    "City": data.get("city"),
                    "Zip": data.get("zip"),
                    "Timezone": data.get("timezone"),
                    "ISP": data.get("isp"),
                    "Organization": data.get("org"),
                    "ASN": data.get("as"),
                    "Hosting": data.get("hosting"),
                    "Proxy": data.get("proxy"),
                    "VPN": data.get("vpn"),
                    "Tor": data.get("tor"),
                    "Lat/Lon": f"{data.get('lat')}, {data.get('lon')}",
                }
                for label, val in fields.items():
                    if val is not None:
                        flag = f" {Fore.RED}[!]{Style.RESET_ALL}" if label in ("Proxy", "VPN", "Tor", "Hosting") and val else ""
                        print(f"  {Fore.YELLOW}{label:<14}{Style.RESET_ALL}: {val}{flag}")
            else:
                print(f"{Fore.RED}[!] GeoIP failed: {data.get('message')}{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Request failed: {e}{Style.RESET_ALL}")


def check_tor_exit(ip):
    """Check if an IP is a known Tor exit node."""
    print(f"\n{Fore.CYAN}[ Tor Exit Check: {ip} ]{Style.RESET_ALL}")
    try:
        r = requests.get(TOR_EXIT_LIST_URL, timeout=15)
        exit_nodes = set(r.text.strip().splitlines())
        if ip in exit_nodes:
            print(f"  {Fore.RED}[!] {ip} IS a known Tor exit node.{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}[+] {ip} is NOT a known Tor exit node.{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Could not fetch Tor exit list: {e}{Style.RESET_ALL}")


def check_dnsbl(ip):
    """Check IP against common DNS blacklists."""
    print(f"\n{Fore.CYAN}[ DNSBL Blacklist Check: {ip} ]{Style.RESET_ALL}")
    reversed_ip = ".".join(reversed(ip.split(".")))
    listed_on = []

    for bl in KNOWN_BLACKLISTS:
        query = f"{reversed_ip}.{bl}"
        try:
            socket.gethostbyname(query)
            listed_on.append(bl)
            print(f"  {Fore.RED}[LISTED]  {bl}{Style.RESET_ALL}")
        except socket.gaierror:
            print(f"  {Fore.GREEN}[CLEAN]   {bl}{Style.RESET_ALL}")

    print(f"\n  Result: {Fore.RED}{len(listed_on)} list(s){Style.RESET_ALL}" if listed_on
          else f"\n  {Fore.GREEN}Result: Not listed on any checked blacklists.{Style.RESET_ALL}")


def geoip_lookup_data(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66842623", timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return data
            return {"error": data.get("message", "GeoIP failed.")}
        return {"error": f"ip-api error: {r.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def check_tor_exit_data(ip):
    try:
        r = requests.get(TOR_EXIT_LIST_URL, timeout=15)
        exit_nodes = set(r.text.strip().splitlines())
        return {"is_tor": ip in exit_nodes}
    except requests.RequestException as e:
        return {"error": str(e)}


def check_dnsbl_data(ip):
    reversed_ip = ".".join(reversed(ip.split(".")))
    results = {}
    for bl in KNOWN_BLACKLISTS:
        query = f"{reversed_ip}.{bl}"
        try:
            socket.gethostbyname(query)
            results[bl] = True
        except socket.gaierror:
            results[bl] = False
    return results


def ip_menu():
    print(f"\n{Fore.CYAN}=== IP Tools ==={Style.RESET_ALL}")
    print("  [1] GeoIP Lookup")
    print("  [2] Tor Exit Node Check")
    print("  [3] DNSBL Blacklist Check")
    print("  [4] Full IP Report (all above)")
    print("  [0] Back")
    choice = input(f"\n{Fore.GREEN}Select > {Style.RESET_ALL}").strip()

    if choice == "0":
        return
    elif choice == "1":
        ip = input("Enter IP address: ").strip()
        geoip_lookup(ip)
    elif choice == "2":
        ip = input("Enter IP address: ").strip()
        check_tor_exit(ip)
    elif choice == "3":
        ip = input("Enter IP address: ").strip()
        check_dnsbl(ip)
    elif choice == "4":
        ip = input("Enter IP address: ").strip()
        geoip_lookup(ip)
        check_tor_exit(ip)
        check_dnsbl(ip)
    else:
        print(f"{Fore.RED}[!] Invalid option.{Style.RESET_ALL}")
