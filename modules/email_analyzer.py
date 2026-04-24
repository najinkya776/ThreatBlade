import email
import re
import os
from email import policy
from email.parser import BytesParser, Parser
from colorama import Fore, Style


def extract_ips(text):
    pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    return list(set(re.findall(pattern, text)))


def extract_emails_from_text(text):
    pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(pattern, text)))


def extract_urls_from_text(text):
    pattern = r'https?://[^\s\'"<>]+'
    return list(set(re.findall(pattern, text)))


def analyze_eml_file(filepath):
    if not os.path.isfile(filepath):
        print(f"{Fore.RED}[!] File not found: {filepath}{Style.RESET_ALL}")
        return

    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    print(f"\n{Fore.CYAN}{'='*55}")
    print(f"  EMAIL ANALYSIS REPORT")
    print(f"{'='*55}{Style.RESET_ALL}")

    # Headers
    print(f"\n{Fore.YELLOW}[ Headers ]{Style.RESET_ALL}")
    header_fields = ["From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-ID",
                     "Return-Path", "X-Originating-IP", "X-Mailer", "MIME-Version"]
    for field in header_fields:
        val = msg.get(field)
        if val:
            print(f"  {Fore.CYAN}{field:<20}{Style.RESET_ALL}: {val}")

    # Authentication headers
    print(f"\n{Fore.YELLOW}[ Authentication ]{Style.RESET_ALL}")
    auth_fields = ["Received-SPF", "DKIM-Signature", "Authentication-Results", "ARC-Authentication-Results"]
    for field in auth_fields:
        val = msg.get(field)
        if val:
            status = "PASS" if "pass" in val.lower() else "FAIL" if "fail" in val.lower() else "UNKNOWN"
            color = Fore.GREEN if status == "PASS" else Fore.RED if status == "FAIL" else Fore.YELLOW
            print(f"  {Fore.CYAN}{field:<28}{Style.RESET_ALL}: {color}{status}{Style.RESET_ALL}")

    # Body extraction
    body = ""
    html_body = ""
    attachments = []

    for part in msg.walk():
        ct = part.get_content_type()
        cd = part.get_content_disposition()
        if cd == "attachment":
            attachments.append({
                "name": part.get_filename(),
                "type": ct,
                "size": len(part.get_payload(decode=True) or b""),
            })
        elif ct == "text/plain" and cd != "attachment":
            try:
                body += part.get_content() or ""
            except Exception:
                body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
        elif ct == "text/html" and cd != "attachment":
            try:
                html_body += part.get_content() or ""
            except Exception:
                html_body += part.get_payload(decode=True).decode("utf-8", errors="ignore")

    full_text = body + html_body

    # Extracted IOCs
    urls = extract_urls_from_text(full_text)
    ips = extract_ips(full_text)
    found_emails = extract_emails_from_text(full_text)

    print(f"\n{Fore.YELLOW}[ Extracted URLs ({len(urls)}) ]{Style.RESET_ALL}")
    for u in urls[:20]:
        print(f"  {u}")
    if len(urls) > 20:
        print(f"  ... and {len(urls)-20} more")

    print(f"\n{Fore.YELLOW}[ Extracted IPs ({len(ips)}) ]{Style.RESET_ALL}")
    for ip in ips:
        print(f"  {ip}")

    print(f"\n{Fore.YELLOW}[ Extracted Email Addresses ({len(found_emails)}) ]{Style.RESET_ALL}")
    for em in found_emails:
        print(f"  {em}")

    print(f"\n{Fore.YELLOW}[ Attachments ({len(attachments)}) ]{Style.RESET_ALL}")
    if attachments:
        for a in attachments:
            print(f"  {Fore.RED}{a['name']}{Style.RESET_ALL} | {a['type']} | {a['size']} bytes")
    else:
        print(f"  None")

    # Phishing indicators
    print(f"\n{Fore.YELLOW}[ Phishing Indicators ]{Style.RESET_ALL}")
    subject = msg.get("Subject", "").lower()
    phish_keywords = ["urgent", "verify", "suspended", "account", "click here", "password",
                      "confirm", "invoice", "payment", "alert", "unusual activity", "sign in"]
    found_keywords = [k for k in phish_keywords if k in subject or k in full_text.lower()]
    if found_keywords:
        print(f"  {Fore.RED}Suspicious keywords: {', '.join(found_keywords)}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}No common phishing keywords detected.{Style.RESET_ALL}")

    sender = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    if reply_to and reply_to != sender:
        print(f"  {Fore.RED}[!] Reply-To differs from From address — common phishing tactic{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'='*55}{Style.RESET_ALL}\n")


def analyze_raw_headers(raw_headers):
    """Parse and display raw email headers pasted by user."""
    msg = Parser(policy=policy.default).parsestr(raw_headers)
    print(f"\n{Fore.CYAN}[ Parsed Headers ]{Style.RESET_ALL}")
    for key, val in msg.items():
        print(f"  {Fore.YELLOW}{key:<28}{Style.RESET_ALL}: {val}")


def email_menu():
    print(f"\n{Fore.CYAN}=== Phishing Email Analyzer ==={Style.RESET_ALL}")
    print("  [1] Analyze .eml file")
    print("  [2] Parse raw email headers")
    print("  [0] Back")
    choice = input(f"\n{Fore.GREEN}Select > {Style.RESET_ALL}").strip()

    if choice == "0":
        return
    elif choice == "1":
        path = input("Enter path to .eml file: ").strip().strip('"')
        analyze_eml_file(path)
    elif choice == "2":
        print("Paste raw headers (enter a blank line when done):")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        analyze_raw_headers("\n".join(lines))
    else:
        print(f"{Fore.RED}[!] Invalid option.{Style.RESET_ALL}")
