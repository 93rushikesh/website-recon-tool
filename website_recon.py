import requests
import socket
import whois
import json
import threading
import re
import time
import os
from datetime import datetime
from colorama import Fore, Style, init
from wafw00f.main import WAFW00F
from urllib.parse import urlparse
from bs4 import BeautifulSoup

init(autoreset=True)
output_lock = threading.Lock()
scan_counter = 1

# ✅ Internet check function
def check_internet(host="8.8.8.8", port=53, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error:
        return False

def show_logo():
    logo = r"""
██████╗░░█████╗░██████╗░██████╗░██████╗░░█████╗░██████╗░░██████╗
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝
██║░░██║██║░░██║██║░░██║██████╦╝██████╔╝███████║██████╔╝╚█████╗░
██║░░██║██║░░██║██║░░██║██╔══██╗██╔═══╝░██╔══██║██╔═══╝░░╚═══██╗
██████╔╝╚█████╔╝██████╔╝██████╦╝██║░░░░░██║░░██║██║░░░░░██████╔╝
╚═════╝░░╚════╝░╚═════╝░╚═════╝░╚═╝░░░░░╚═╝░░╚═╝╚═╝░░░░░╚═════╝░

█▀█	█░█	█▀█	█░█	█	█▀	█▄░█	█▀▀	█▀█
█▀▀	█▄█	█▄█	█▄█	█	▄█	█░▀█	██▄	█▀▄
         RUSHIKESH's Web Recon Tool
"""
    print(Fore.CYAN + logo)

def write_output(text):
    with output_lock:
        with open(output_file, "a", encoding='utf-8') as f:
            f.write(text + "\n")

def is_valid_domain(domain):
    pattern = r"^(?!\-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None

def normalize_domain(domain):
    parsed = urlparse(domain)
    if parsed.scheme:
        return parsed.netloc
    return domain.split("/")[0]

def safe_request(domain, path="/", headers=None):
    headers = headers or {'User-Agent': 'Mozilla/5.0'}
    if not domain.startswith("http"):
        urls = [f"https://{domain}{path}", f"http://{domain}{path}"]
    else:
        urls = [domain]
    for url in urls:
        try:
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                return res
        except:
            continue
    return None

def get_next_filename(prefix, ext):
    i = 1
    while os.path.exists(f"{prefix}_output{i}.{ext}"):
        i += 1
    return f"{prefix}_output{i}.{ext}"

def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            data = res.json()
            subdomains = set()
            for entry in data:
                names = entry['name_value'].split("\n")
                for name in names:
                    if domain in name:
                        subdomains.add(name.strip())
            return subdomains
    except Exception as e:
        raise e
    return set()

def get_subdomains_rapiddns(domain):
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')
        rows = soup.find_all('td')
        subdomains = set()
        for row in rows:
            if domain in row.text:
                subdomains.add(row.text.strip())
        return subdomains
    except Exception as e:
        raise e
    return set()

def get_subdomains_all(domain):
    print("\n[+] Subdomain Enumeration (Multi-source):")
    subdomains = set()

    try:
        subdomains.update(get_subdomains_crtsh(domain))
    except Exception as e:
        print(f"  [-] crt.sh error: {e}")

    try:
        subdomains.update(get_subdomains_rapiddns(domain))
    except Exception as e:
        print(f"  [-] RapidDNS error: {e}")

    if subdomains:
        for sub in subdomains:
            print(f"  [+] {sub}")
        filename = get_next_filename("subdomains", "txt")
        with open(filename, 'w') as f:
            for sub in subdomains:
                f.write(sub + '\n')
        print(f"  [*] Saved to {filename}")
    else:
        print("  [-] No subdomains found.")

def main():
    global scan_counter
    show_logo()
    if not check_internet():
        print(Fore.RED + "❗ No Internet Connection. Please connect and retry.")
        return

    while True:
        domain_input = input("🔎 Enter domain (e.g. example.com): ").strip()
        domain = normalize_domain(domain_input)
        if is_valid_domain(domain):
            break
        else:
            print(Fore.YELLOW + "❗ Invalid domain format. Try again.")

    global output_file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"scan_output_{scan_counter}.txt"
    scan_counter += 1

    with open(output_file, "w", encoding='utf-8') as f:
        f.write(f"--- Scan Results for {domain} ---\n")

    while True:
        print("\nChoose Scan Option:")
        print("1. Subdomain Enumeration")
        print("2. Port Scan")
        print("3. IP & GeoIP")
        print("4. HTTP Headers")
        print("5. Tech Detection")
        print("6. WAF Detection")
        print("7. WHOIS Lookup")
        print("8. Full Scan")
        print("9. Exit")

        choice = input("Enter option (1-9): ")

        if choice == "1":
            get_subdomains_all(domain)
        elif choice == "9":
            print(f"\n🔚 Exiting. Results saved in {output_file}")
            break
        else:
            print(Fore.YELLOW + "❗ Feature not implemented yet. Only subdomain scan works now.")

if __name__ == "__main__":
    main()
