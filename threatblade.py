#!/usr/bin/env python3

import sys
import os
from colorama import init, Fore, Style

init(autoreset=True)

BANNER = f"""
{Fore.RED}
  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗    ██████╗ ██╗      █████╗ ██████╗ ███████╗
  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝    ██╔══██╗██║     ██╔══██╗██╔══██╗██╔════╝
     ██║   ███████║██████╔╝█████╗  ███████║   ██║       ██████╔╝██║     ███████║██║  ██║█████╗
     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║       ██╔══██╗██║     ██╔══██║██║  ██║██╔══╝
     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║       ██████╔╝███████╗██║  ██║██████╔╝███████╗
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝
{Style.RESET_ALL}
{Fore.YELLOW}                    [ SOC Analyst Automation Toolkit ]
{Fore.CYAN}                           Version 1.0.0
{Style.RESET_ALL}
"""

MENU = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║                   MAIN MENU                          ║
╠══════════════════════════════════════════════════════╣
║  {Fore.WHITE}[1]{Fore.CYAN}  Reputation Check (IP / Domain / URL)            ║
║  {Fore.WHITE}[2]{Fore.CYAN}  URL Tools (Decode / Sanitize / Expand)           ║
║  {Fore.WHITE}[3]{Fore.CYAN}  DNS & WHOIS Lookup                               ║
║  {Fore.WHITE}[4]{Fore.CYAN}  File Hash & Hash Reputation                      ║
║  {Fore.WHITE}[5]{Fore.CYAN}  Phishing Email Analyzer                          ║
║  {Fore.WHITE}[6]{Fore.CYAN}  Breach / Credential Check (HIBP)                 ║
║  {Fore.WHITE}[7]{Fore.CYAN}  IP Tools (Geo / Tor / Blacklist)                 ║
║  {Fore.WHITE}[8]{Fore.CYAN}  Generate Phishing Response Template              ║
║  {Fore.WHITE}[9]{Fore.CYAN}  Settings (API Keys)                              ║
║  {Fore.WHITE}[0]{Fore.CYAN}  Exit                                             ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


def main():
    print(BANNER)
    while True:
        print(MENU)
        choice = input(f"{Fore.GREEN}threatBlade > {Style.RESET_ALL}").strip()

        if choice == "1":
            from modules.reputation import reputation_menu
            reputation_menu()
        elif choice == "2":
            from modules.url_tools import url_menu
            url_menu()
        elif choice == "3":
            from modules.dns_tools import dns_menu
            dns_menu()
        elif choice == "4":
            from modules.hash_tools import hash_menu
            hash_menu()
        elif choice == "5":
            from modules.email_analyzer import email_menu
            email_menu()
        elif choice == "6":
            from modules.breach_check import breach_menu
            breach_menu()
        elif choice == "7":
            from modules.ip_tools import ip_menu
            ip_menu()
        elif choice == "8":
            from modules.templates import template_menu
            template_menu()
        elif choice == "9":
            from config.settings import settings_menu
            settings_menu()
        elif choice == "0":
            print(f"\n{Fore.RED}[!] Exiting threatBlade. Stay sharp.{Style.RESET_ALL}\n")
            sys.exit(0)
        else:
            print(f"{Fore.RED}[!] Invalid option.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
