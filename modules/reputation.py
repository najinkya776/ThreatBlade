import requests
import json
from colorama import Fore, Style
from config.settings import get_key


def check_virustotal(ioc, ioc_type):
    api_key = get_key("virustotal_api_key")
    if not api_key:
        print(f"{Fore.YELLOW}[!] VirusTotal API key not set. Configure in Settings.{Style.RESET_ALL}")
        return

    endpoints = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "url": "https://www.virustotal.com/api/v3/urls",
        "hash": f"https://www.virustotal.com/api/v3/files/{ioc}",
    }

    headers = {"x-apikey": api_key}

    try:
        if ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        else:
            r = requests.get(endpoints[ioc_type], headers=headers, timeout=10)

        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            color = Fore.GREEN if malicious == 0 else Fore.RED
            print(f"\n{Fore.CYAN}[ VirusTotal Results for {ioc} ]{Style.RESET_ALL}")
            print(f"  {Fore.RED}Malicious  : {malicious}/{total}")
            print(f"  {Fore.YELLOW}Suspicious : {suspicious}/{total}")
            print(f"  {Fore.GREEN}Harmless   : {harmless}/{total}")
            print(f"  {Fore.WHITE}Undetected : {undetected}/{total}{Style.RESET_ALL}")

            reputation = data.get("data", {}).get("attributes", {}).get("reputation", "N/A")
            print(f"  Reputation Score: {color}{reputation}{Style.RESET_ALL}")
        elif r.status_code == 404:
            print(f"{Fore.YELLOW}[!] Not found in VirusTotal database.{Style.RESET_ALL}")
        elif r.status_code == 401:
            print(f"{Fore.RED}[!] Invalid VirusTotal API key.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] VT API error: {r.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Request failed: {e}{Style.RESET_ALL}")


def check_abuseipdb(ip):
    api_key = get_key("abuseipdb_api_key")
    if not api_key:
        print(f"{Fore.YELLOW}[!] AbuseIPDB API key not set. Configure in Settings.{Style.RESET_ALL}")
        return

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            color = Fore.RED if score >= 50 else (Fore.YELLOW if score > 0 else Fore.GREEN)
            print(f"\n{Fore.CYAN}[ AbuseIPDB Results for {ip} ]{Style.RESET_ALL}")
            print(f"  Abuse Confidence Score : {color}{score}%{Style.RESET_ALL}")
            print(f"  Country                : {data.get('countryCode', 'N/A')}")
            print(f"  ISP                    : {data.get('isp', 'N/A')}")
            print(f"  Domain                 : {data.get('domain', 'N/A')}")
            print(f"  Total Reports          : {data.get('totalReports', 0)}")
            print(f"  Last Reported          : {data.get('lastReportedAt', 'Never')}")
            print(f"  Usage Type             : {data.get('usageType', 'N/A')}")
            print(f"  Is Tor                 : {data.get('isTor', False)}")
        else:
            print(f"{Fore.RED}[!] AbuseIPDB error: {r.status_code} - {r.text}{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Request failed: {e}{Style.RESET_ALL}")


def check_virustotal_data(ioc, ioc_type):
    api_key = get_key("virustotal_api_key")
    if not api_key:
        return {"error": "VirusTotal API key not configured."}
    headers = {"x-apikey": api_key}
    try:
        if ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        elif ioc_type in ("ip", "domain", "hash"):
            ep = {"ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
                  "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
                  "hash": f"https://www.virustotal.com/api/v3/files/{ioc}"}
            r = requests.get(ep[ioc_type], headers=headers, timeout=10)
        else:
            return {"error": "Unknown IOC type."}

        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source": "VirusTotal",
                "ioc": ioc,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "reputation": attrs.get("reputation", "N/A"),
                "tags": attrs.get("tags", []),
            }
        elif r.status_code == 404:
            return {"error": "Not found in VirusTotal database."}
        elif r.status_code == 401:
            return {"error": "Invalid VirusTotal API key."}
        else:
            return {"error": f"VT API error: {r.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def check_abuseipdb_data(ip):
    api_key = get_key("abuseipdb_api_key")
    if not api_key:
        return {"error": "AbuseIPDB API key not configured."}
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            return {"source": "AbuseIPDB", **r.json().get("data", {})}
        return {"error": f"AbuseIPDB error: {r.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def reputation_menu():
    print(f"\n{Fore.CYAN}=== Reputation Check ==={Style.RESET_ALL}")
    print("  [1] Check IP")
    print("  [2] Check Domain")
    print("  [3] Check URL")
    print("  [4] Check File Hash")
    print("  [0] Back")
    choice = input(f"\n{Fore.GREEN}Select > {Style.RESET_ALL}").strip()

    if choice == "0":
        return
    elif choice == "1":
        ip = input("Enter IP address: ").strip()
        check_abuseipdb(ip)
        check_virustotal(ip, "ip")
    elif choice == "2":
        domain = input("Enter domain: ").strip()
        check_virustotal(domain, "domain")
    elif choice == "3":
        url = input("Enter URL: ").strip()
        check_virustotal(url, "url")
    elif choice == "4":
        file_hash = input("Enter hash (MD5/SHA1/SHA256): ").strip()
        check_virustotal(file_hash, "hash")
    else:
        print(f"{Fore.RED}[!] Invalid option.{Style.RESET_ALL}")
