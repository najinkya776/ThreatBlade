import socket
import requests
from colorama import Fore, Style

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


def dns_lookup(domain):
    print(f"\n{Fore.CYAN}[ DNS Lookup: {domain} ]{Style.RESET_ALL}")

    if not DNS_AVAILABLE:
        print(f"{Fore.YELLOW}[!] dnspython not installed. Falling back to basic socket lookup.{Style.RESET_ALL}")
        try:
            ip = socket.gethostbyname(domain)
            print(f"  A Record: {ip}")
        except socket.gaierror as e:
            print(f"{Fore.RED}[!] Lookup failed: {e}{Style.RESET_ALL}")
        return

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            print(f"\n  {Fore.YELLOW}{rtype} Records:{Style.RESET_ALL}")
            for r in answers:
                print(f"    {r.to_text()}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.resolver.Timeout:
            print(f"  {Fore.RED}{rtype}: Timeout{Style.RESET_ALL}")
        except Exception:
            pass


def whois_lookup(target):
    print(f"\n{Fore.CYAN}[ WHOIS Lookup: {target} ]{Style.RESET_ALL}")

    if not WHOIS_AVAILABLE:
        print(f"{Fore.YELLOW}[!] python-whois not installed. Run: pip install python-whois{Style.RESET_ALL}")
        return

    try:
        w = whois.whois(target)
        fields = {
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Updated Date": w.updated_date,
            "Name Servers": w.name_servers,
            "Registrant Country": w.country,
            "Registrant Org": w.org,
            "Emails": w.emails,
        }
        for label, val in fields.items():
            if val:
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val[:3])
                print(f"  {Fore.YELLOW}{label:<20}{Style.RESET_ALL}: {val}")
    except Exception as e:
        print(f"{Fore.RED}[!] WHOIS failed: {e}{Style.RESET_ALL}")


def reverse_dns(ip):
    print(f"\n{Fore.CYAN}[ Reverse DNS: {ip} ]{Style.RESET_ALL}")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print(f"  Hostname: {Fore.GREEN}{hostname}{Style.RESET_ALL}")
    except socket.herror:
        print(f"  {Fore.YELLOW}No reverse DNS record found.{Style.RESET_ALL}")


def dns_lookup_data(domain):
    result = {}
    if not DNS_AVAILABLE:
        try:
            result["A"] = [socket.gethostbyname(domain)]
        except Exception as e:
            result["error"] = str(e)
        return result
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            result[rtype] = [r.to_text() for r in answers]
        except Exception:
            pass
    return result


def whois_lookup_data(target):
    if not WHOIS_AVAILABLE:
        return {"error": "python-whois not installed."}
    try:
        w = whois.whois(target)
        def fmt(v):
            if isinstance(v, list):
                return [str(x) for x in v[:5]]
            return str(v) if v else None
        return {
            "registrar": fmt(w.registrar),
            "creation_date": fmt(w.creation_date),
            "expiration_date": fmt(w.expiration_date),
            "updated_date": fmt(w.updated_date),
            "name_servers": fmt(w.name_servers),
            "country": fmt(w.country),
            "org": fmt(w.org),
            "emails": fmt(w.emails),
        }
    except Exception as e:
        return {"error": str(e)}


def reverse_dns_data(ip):
    try:
        return {"hostname": socket.gethostbyaddr(ip)[0]}
    except socket.herror:
        return {"hostname": None, "message": "No reverse DNS record found."}


def dns_menu():
    print(f"\n{Fore.CYAN}=== DNS & WHOIS Tools ==={Style.RESET_ALL}")
    print("  [1] DNS Lookup (A/MX/TXT/NS/CNAME/SOA)")
    print("  [2] WHOIS Lookup")
    print("  [3] Reverse DNS (PTR)")
    print("  [0] Back")
    choice = input(f"\n{Fore.GREEN}Select > {Style.RESET_ALL}").strip()

    if choice == "0":
        return
    elif choice == "1":
        domain = input("Enter domain: ").strip()
        dns_lookup(domain)
    elif choice == "2":
        target = input("Enter domain or IP: ").strip()
        whois_lookup(target)
    elif choice == "3":
        ip = input("Enter IP address: ").strip()
        reverse_dns(ip)
    else:
        print(f"{Fore.RED}[!] Invalid option.{Style.RESET_ALL}")
