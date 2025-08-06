import requests
import socket
import whois
import json
import threading
import re
from colorama import Fore, Style, init
from wafw00f.main import WAFW00F

init(autoreset=True)

output_lock = threading.Lock()

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
        with open("scan_output.txt", "a", encoding='utf-8') as f:
            f.write(text + "\n")

def get_subdomains_all(domain):
    print("\n[+] Subdomain Enumeration (Multi-source):")
    subdomains = set()
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        response = requests.get(url, timeout=10)
        matches = re.findall(r'<td>([a-zA-Z0-9._-]+\\.' + re.escape(domain) + r')</td>', response.text)
        for match in matches:
            subdomains.add(match.strip())

        crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        crt_response = requests.get(crt_url, timeout=10)
        if crt_response.status_code == 200 and crt_response.text.strip().startswith("["):
            cert_data = crt_response.json()
            for entry in cert_data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    if domain in sub:
                        subdomains.add(sub.strip())
    except Exception as e:
        print(f"  [-] Error during subdomain fetching: {e}")

    if subdomains:
        for sub in sorted(subdomains):
            print(f"  [FOUND] http://{sub}")
    else:
        print("  [-] No subdomains found.")

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        status = "open" if result == 0 else "closed"
        line = f"  Port {port}: {status}"
        print(line)
        write_output(line)
        sock.close()
    except Exception as e:
        write_output(f"  Port {port}: Error - {e}")

def port_scan(domain):
    print(Fore.MAGENTA + "\n[================= PORT SCAN =================]")
    write_output("\n[+] Port Scanning:")
    ports_to_scan = [21, 22, 23, 53, 80, 443, 8080, 8443]
    try:
        ip = socket.gethostbyname(domain)
        threads = []
        for port in ports_to_scan:
            t = threading.Thread(target=scan_port, args=(ip, port))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
    except Exception as e:
        print(Fore.RED + f"  [-] Error: {e}")
        write_output(f"  [-] Error: {e}")

def get_ip(domain):
    print(Fore.GREEN + "\n[+] IP Address:")
    write_output("\n[+] IP Address:")
    try:
        ip = socket.gethostbyname(domain)
        print(f"  IP: {ip}")
        write_output(f"  IP: {ip}")
        return ip
    except Exception as e:
        print(Fore.RED + f"  [-] Could not resolve IP: {e}")
        write_output(f"  [-] Could not resolve IP: {e}")
        return None

def geoip_lookup(ip):
    print(Fore.GREEN + "\n[+] IP Geolocation:")
    write_output("\n[+] IP Geolocation:")
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = res.json()
        for field in ['country', 'regionName', 'city', 'org']:
            line = f"  {field.title()} : {data.get(field)}"
            print(line)
            write_output(line)
    except Exception as e:
        print(Fore.RED + f"  [-] GeoIP Lookup failed: {e}")
        write_output(f"  [-] GeoIP Lookup failed: {e}")

def http_headers(domain):
    print(Fore.GREEN + "\n[+] HTTP Headers:")
    write_output("\n[+] HTTP Headers:")
    try:
        res = requests.get(f"https://{domain}", headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        for header, value in res.headers.items():
            line = f"  {header}: {value}"
            print(line)
            write_output(line)
    except Exception as e:
        print(Fore.RED + f"  [-] Error fetching headers: {e}")
        write_output(f"  [-] Error fetching headers: {e}")

def tech_detect(domain):
    print(Fore.GREEN + "\n[+] Technology Detection:")
    write_output("\n[+] Technology Detection:")
    try:
        res = requests.get(f"https://{domain}", headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        headers = res.headers
        server = headers.get("Server", "Unknown")
        x_powered = headers.get("X-Powered-By", "Unknown")
        print(f"  [TECH] Server: {server}")
        print(f"  [TECH] X-Powered-By: {x_powered}")
        write_output(f"  [TECH] Server: {server}")
        write_output(f"  [TECH] X-Powered-By: {x_powered}")
    except Exception as e:
        print(Fore.RED + f"  [TECH] Not Detected: {e}")
        write_output(f"  [TECH] Not Detected: {e}")

def waf_detect(domain):
    print(Fore.GREEN + "\n[+] WAF Detection:")
    write_output("\n[+] WAF Detection:")
    try:
        res = requests.get(f"https://{domain}", headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        headers = str(res.headers).lower()
        waf_keywords = ['cloudflare', 'sucuri', 'incapsula', 'akamai']
        detected = [waf for waf in waf_keywords if waf in headers]
        if detected:
            line = f"  [WAF] Basic Detected: {', '.join(detected)}"
            print(line)
            write_output(line)
        else:
            print("  [WAF] Basic: Not Detected")
            write_output("  [WAF] Basic: Not Detected")
    except Exception as e:
        print(Fore.RED + f"  [WAF] Basic Detection Failed: {e}")
        write_output(f"  [WAF] Basic Detection Failed: {e}")

    try:
        waf = WAFW00F(f"https://{domain}")
        result = waf.identwaf()
        if result:
            line = f"  [WAF] Advanced Detected: {result[0]}"
            print(line)
            write_output(line)
        else:
            print("  [WAF] Advanced: Not Detected")
            write_output("  [WAF] Advanced: Not Detected")
    except Exception as e:
        print(Fore.RED + f"  [WAF] Advanced Detection Failed: {e}")
        write_output(f"  [WAF] Advanced Detection Failed: {e}")

def whois_lookup(domain):
    print(Fore.GREEN + "\n[+] WHOIS Lookup:")
    write_output("\n[+] WHOIS Lookup:")
    try:
        data = whois.whois(domain)
        whois_data = json.dumps(data, indent=2, default=str)
        print(whois_data)
        write_output(whois_data)
    except Exception as e:
        print(Fore.RED + f"  [-] WHOIS lookup failed: {e}")
        write_output(f"  [-] WHOIS lookup failed: {e}")

def check_internet():
    try:
        requests.get("http://www.google.com", timeout=3)
        return True
    except:
        return False

def main():
    show_logo()
    if not check_internet():
        print(Fore.RED + "❗ No Internet Connection. Please connect and retry.")
        return

    domain = input("🔎 Enter domain (e.g. example.com): ").strip()

    with open("scan_output.txt", "w", encoding='utf-8') as f:
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
            print("\n🔚 Exiting. Results saved in scan_output.txt")
            break
        else:
            print(Fore.YELLOW + "❗ Invalid choice. Try again.")

if __name__ == "__main__":
    main()
