import json
import os
from colorama import Fore, Style

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "keys.json")

DEFAULTS = {
    "virustotal_api_key": "",
    "abuseipdb_api_key": "",
    "hibp_api_key": "",
    "urlscan_api_key": "",
    "shodan_api_key": "",
}


def load_config():
    if not os.path.exists(CONFIG_PATH):
        save_config(DEFAULTS)
        return DEFAULTS.copy()
    with open(CONFIG_PATH, "r") as f:
        data = json.load(f)
    for k, v in DEFAULTS.items():
        data.setdefault(k, v)
    return data


def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4)


def get_key(name):
    return load_config().get(name, "")


def settings_menu():
    config = load_config()
    keys = list(DEFAULTS.keys())
    print(f"\n{Fore.CYAN}=== API Key Settings ==={Style.RESET_ALL}")
    for i, k in enumerate(keys, 1):
        val = config.get(k, "")
        masked = ("*" * (len(val) - 4) + val[-4:]) if len(val) > 4 else ("Set" if val else "Not set")
        print(f"  [{i}] {k}: {Fore.YELLOW}{masked}{Style.RESET_ALL}")
    print(f"  [0] Back")
    choice = input(f"\n{Fore.GREEN}Select key to update > {Style.RESET_ALL}").strip()
    if choice == "0":
        return
    try:
        idx = int(choice) - 1
        key_name = keys[idx]
        new_val = input(f"Enter new value for {Fore.CYAN}{key_name}{Style.RESET_ALL}: ").strip()
        config[key_name] = new_val
        save_config(config)
        print(f"{Fore.GREEN}[+] Saved.{Style.RESET_ALL}")
    except (ValueError, IndexError):
        print(f"{Fore.RED}[!] Invalid selection.{Style.RESET_ALL}")
