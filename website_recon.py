import requests
import socket
import whois
import json
import threading
import re
import time
from datetime import datetime
from colorama import Fore, Style, init
from wafw00f.main import WAFW00F
from urllib.parse import urlparse

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

█▀█ █░█ █▀█ █░█ █ █▀ █▄░█ █▀▀ █▀█
█▀▀ █▄█ █▄█ █▄█ █ ▄█ █░▀█ ██▄ █▀▄
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

# Remaining functions stay unchanged
# Only update output_file generation in `main` for numbered scans

def main():
    global scan_counter
    show_logo()
    if not check_internet():
        print(Fore.RED + "❗ No Internet Connection. Please connect and retry.")
        return

    while True:
        domain_input = input("🔎 Enter domain (e.g. example.com or https://example.com): ").strip()
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
        elif choice == "2":
            port_scan(domain)
        elif choice == "3":
            ip = get_ip(domain)
            if ip:
                geoip_lookup(ip)
        elif choice == "4":
            http_headers(domain)
        elif choice == "5":
            tech_detect(domain)
        elif choice == "6":
            waf_detect(domain)
        elif choice == "7":
            whois_lookup(domain)
        elif choice == "8":
            get_subdomains_all(domain)
            port_scan(domain)
            ip = get_ip(domain)
            if ip:
                geoip_lookup(ip)
            http_headers(domain)
            tech_detect(domain)
            waf_detect(domain)
            whois_lookup(domain)
        elif choice == "9":
            print(f"\n🔚 Exiting. Results saved in {output_file}")
            break
        else:
            print(Fore.YELLOW + "❗ Invalid choice. Try again.")

if __name__ == "__main__":
    main()
