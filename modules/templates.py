from colorama import Fore, Style
from datetime import datetime


PHISHING_TEMPLATE = """Subject: [SECURITY ALERT] Phishing Email Reported - Action Required

Dear {recipient},

This is to inform you that a phishing email was detected and reported on {date}.

--- INCIDENT SUMMARY ---
Reported By     : {reporter}
Date/Time       : {date}
Sender Address  : {sender}
Subject Line    : {subject}
Action Taken    : {action}

--- INDICATORS OF COMPROMISE ---
Malicious URLs  : {urls}
Sender IP       : {sender_ip}
Attachment(s)   : {attachments}

--- RECOMMENDED ACTIONS ---
1. Do NOT click any links in the email.
2. Do NOT open any attachments.
3. Delete the email from your inbox and trash immediately.
4. If you clicked a link or opened an attachment, contact the Security team immediately.
5. Change your password if you entered credentials anywhere.

If you have any questions or believe you may have been compromised, contact the SOC immediately at {soc_contact}.

Regards,
{analyst_name}
Security Operations Center
{date}
"""

MALWARE_TEMPLATE = """Subject: [SECURITY ALERT] Malware Detection - {hostname}

Dear {recipient},

A malware detection event was identified on {date} and requires your attention.

--- INCIDENT SUMMARY ---
Host            : {hostname}
User            : {username}
Date/Time       : {date}
Malware Name    : {malware_name}
File Path       : {file_path}
SHA256 Hash     : {sha256}
Detection Source: {detection_source}
Severity        : {severity}

--- ACTIONS TAKEN ---
{action_taken}

--- RECOMMENDED ACTIONS FOR USER ---
1. Do NOT use the affected device until cleared by the Security team.
2. Contact IT/Security at {soc_contact} immediately.
3. Report any unusual behavior observed before/after the detection.

Regards,
{analyst_name}
Security Operations Center
{date}
"""

ACCOUNT_COMPROMISE_TEMPLATE = """Subject: [URGENT] Potential Account Compromise - {email}

Dear {recipient},

We have detected activity suggesting that the account {email} may have been compromised.

--- INCIDENT SUMMARY ---
Account         : {email}
Date/Time       : {date}
Suspicious IP   : {suspicious_ip}
Location        : {location}
Activity        : {suspicious_activity}

--- IMMEDIATE ACTIONS REQUIRED ---
1. Change your password IMMEDIATELY at {password_reset_url}.
2. Enable Multi-Factor Authentication (MFA) if not already active.
3. Review recent account activity for unauthorized changes.
4. Revoke any active sessions via account security settings.
5. Check for any email forwarding rules you did not create.

If you did NOT perform this activity, contact the Security team immediately at {soc_contact}.

Regards,
{analyst_name}
Security Operations Center
{date}
"""


def fill_template(template, fields):
    for key, val in fields.items():
        template = template.replace("{" + key + "}", val or "N/A")
    return template


def template_menu():
    print(f"\n{Fore.CYAN}=== Generate Security Response Template ==={Style.RESET_ALL}")
    print("  [1] Phishing Email Alert")
    print("  [2] Malware Detection Alert")
    print("  [3] Account Compromise Alert")
    print("  [0] Back")
    choice = input(f"\n{Fore.GREEN}Select > {Style.RESET_ALL}").strip()

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    if choice == "0":
        return

    elif choice == "1":
        print(f"\n{Fore.CYAN}Fill in phishing template fields (press Enter to skip):{Style.RESET_ALL}")
        fields = {
            "recipient": input("  Recipient name: ").strip(),
            "date": now,
            "reporter": input("  Reported by: ").strip(),
            "sender": input("  Sender address: ").strip(),
            "subject": input("  Email subject: ").strip(),
            "action": input("  Action taken (e.g. Quarantined): ").strip() or "Quarantined",
            "urls": input("  Malicious URLs (comma separated): ").strip() or "None identified",
            "sender_ip": input("  Sender IP: ").strip() or "Not available",
            "attachments": input("  Attachments: ").strip() or "None",
            "soc_contact": input("  SOC contact (email/ext): ").strip(),
            "analyst_name": input("  Analyst name: ").strip(),
        }
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(fill_template(PHISHING_TEMPLATE, fields))
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")

    elif choice == "2":
        print(f"\n{Fore.CYAN}Fill in malware template fields:{Style.RESET_ALL}")
        fields = {
            "recipient": input("  Recipient name: ").strip(),
            "date": now,
            "hostname": input("  Hostname: ").strip(),
            "username": input("  Affected user: ").strip(),
            "malware_name": input("  Malware name: ").strip(),
            "file_path": input("  File path: ").strip(),
            "sha256": input("  SHA256 hash: ").strip(),
            "detection_source": input("  Detection source (e.g. Defender): ").strip(),
            "severity": input("  Severity (Low/Med/High/Critical): ").strip(),
            "action_taken": input("  Actions taken: ").strip() or "File quarantined by AV.",
            "soc_contact": input("  SOC contact: ").strip(),
            "analyst_name": input("  Analyst name: ").strip(),
        }
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(fill_template(MALWARE_TEMPLATE, fields))
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")

    elif choice == "3":
        print(f"\n{Fore.CYAN}Fill in account compromise template fields:{Style.RESET_ALL}")
        fields = {
            "recipient": input("  Recipient name: ").strip(),
            "email": input("  Compromised email/account: ").strip(),
            "date": now,
            "suspicious_ip": input("  Suspicious IP: ").strip(),
            "location": input("  Login location: ").strip(),
            "suspicious_activity": input("  Suspicious activity description: ").strip(),
            "password_reset_url": input("  Password reset URL: ").strip(),
            "soc_contact": input("  SOC contact: ").strip(),
            "analyst_name": input("  Analyst name: ").strip(),
        }
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(fill_template(ACCOUNT_COMPROMISE_TEMPLATE, fields))
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")

    else:
        print(f"{Fore.RED}[!] Invalid option.{Style.RESET_ALL}")
