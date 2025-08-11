import requests
import socket
import whois
import json
import threading
import re
import time
import os
import subprocess
import sys
from datetime import datetime
from colorama import Fore, Style, init
from urllib.parse import urlparse
try:
    from bs4 import BeautifulSoup
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "beautifulsoup4"])
    from bs4 import BeautifulSoup

init(autoreset=True)
output_lock = threading.Lock()
scan_counter = 1

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
    except Exception:
        pass
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
    except Exception:
        pass
    return set()

def get_subdomains_all(domain):
    print("\n[+] Subdomain Enumeration:")
    subdomains = set()
    subdomains.update(get_subdomains_crtsh(domain))
    subdomains.update(get_subdomains_rapiddns(domain))

    if subdomains:
        for sub in subdomains:
            print(f"  [+] {sub}")
            write_output(f"[Subdomain] {sub}")
    else:
        print("  [-] No subdomains found.")

def port_scan(domain):
    print("\n[+] Port Scan:")
    try:
        ip = socket.gethostbyname(domain)
        open_ports = []
        for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 8080]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"  [+] Port {port} is open")
                write_output(f"[Port Open] {port}")
                open_ports.append(port)
            sock.close()
    except Exception as e:
        print(f"  [-] Error: {e}")

def get_ip_geoip(domain):
    print("\n[+] IP & GeoIP Info:")
    try:
        ip = socket.gethostbyname(domain)
        print(f"  [+] IP Address: {ip}")
        write_output(f"[IP] {ip}")
        res = requests.get(f"https://ipinfo.io/{ip}/json")
        data = res.json()
        for key, val in data.items():
            print(f"  {key.capitalize()}: {val}")
            write_output(f"[GeoIP] {key}: {val}")
    except Exception as e:
        print(f"  [-] Error: {e}")

def get_http_headers(domain):
    print("\n[+] HTTP Headers:")
    try:
        url = f"http://{domain}"
        res = requests.get(url, timeout=5)
        for key, val in res.headers.items():
            print(f"  {key}: {val}")
            write_output(f"[Header] {key}: {val}")
    except Exception as e:
        print(f"  [-] Error: {e}")

def detect_tech(domain):
    print("\n[+] Technology Detection:")
    try:
        res = requests.get(f"http://{domain}", timeout=10)
        tech = []
        headers = res.headers
        if "x-powered-by" in headers:
            tech.append(headers["x-powered-by"])
        if "server" in headers:
            tech.append(headers["server"])
        if tech:
            for t in tech:
                print(f"  [+] {t}")
                write_output(f"[Tech] {t}")
        else:
            print("  [-] No tech info found.")
    except Exception as e:
        print(f"  [-] Error: {e}")

def waf_detect(domain):
    print("\n[+] WAF Detection:")
    try:
        result = subprocess.run(["wafw00f", domain], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
            write_output(f"[WAF Detection Output]\n{result.stdout}")
        else:
            print("  [-] wafw00f failed to run.")
    except FileNotFoundError:
        print("  [-] wafw00f not found. Install it via: pip install wafw00f")
    except Exception as e:
        print(f"  [-] Error: {e}")

def whois_lookup(domain):
    print("\n[+] WHOIS Lookup:")
    try:
        info = whois.whois(domain)
        for key, val in info.items():
            print(f"  {key}: {val}")
            write_output(f"[WHOIS] {key}: {val}")
    except Exception as e:
        print(f"  [-] Error: {e}")

def full_scan(domain):
    get_subdomains_all(domain)
    port_scan(domain)
    get_ip_geoip(domain)
    get_http_headers(domain)
    detect_tech(domain)
    waf_detect(domain)
    whois_lookup(domain)

def main():
    global scan_counter, output_file
    show_logo()

    if not check_internet():
        print(Fore.RED + "❗ No Internet Connection.")
        return

    while True:
        domain_input = input("🔎 Enter domain (e.g. example.com): ").strip()
        domain = normalize_domain(domain_input)
        if is_valid_domain(domain):
            break
        else:
            print(Fore.YELLOW + "❗ Invalid domain. Try again.")

    output_file = f"scan_output_{scan_counter}.txt"
    scan_counter += 1
    with open(output_file, "w", encoding='utf-8') as f:
        f.write(f"--- Scan Results for {domain} ---\n")

    while True:
        print("\nChoose Scan Option:")
        print("1. Subdomain Enumeration")
        print("2. Port Scan")
        print("3. IP & GeoIP Info")
        print("4. HTTP Headers")
        print("5. Technology Detection")
        print("6. WAF Detection")
        print("7. WHOIS Lookup")
        print("8. Full Scan")
        print("9. Exit")

        choice = input("Enter option (1-9): ").strip()

        if choice == "1":
            get_subdomains_all(domain)
        elif choice == "2":
            port_scan(domain)
        elif choice == "3":
            get_ip_geoip(domain)
        elif choice == "4":
            get_http_headers(domain)
        elif choice == "5":
            detect_tech(domain)
        elif choice == "6":
            waf_detect(domain)
        elif choice == "7":
            whois_lookup(domain)
        elif choice == "8":
            full_scan(domain)
        elif choice == "9":
            print(f"\n🔚 Exiting. Output saved in {output_file}")
            break
        else:
            print(Fore.YELLOW + "❗ Invalid choice. Try again.")

if __name__ == "__main__":
    main()
