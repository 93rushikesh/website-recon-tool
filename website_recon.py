import requests
import socket
import whois
import json
import time

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
    print(logo)

def write_output(text):
    with open("scan_output.txt", "a", encoding='utf-8') as f:
        f.write(text + "\n")

def get_subdomains_crtsh(domain):
    print("\n[+] Subdomain Enumeration (crt.sh):")
    write_output("\n[+] Subdomain Enumeration (crt.sh):")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        res = requests.get(url, timeout=10)
        entries = res.json()
        subdomains = set()
        for entry in entries:
            name_value = entry['name_value']
            for sub in name_value.split('\n'):
                if domain in sub:
                    subdomains.add(sub.strip())
        if subdomains:
            for sub in sorted(subdomains):
                result = f"  [FOUND] http://{sub}"
                print(result)
                write_output(result)
        else:
            print("  [-] No subdomains found.")
            write_output("  [-] No subdomains found.")
    except Exception as e:
        print("  [-] Error:", e)
        write_output(f"  [-] Error: {e}")

def port_scan(domain):
    print("\n[+] Port Scanning:")
    write_output("\n[+] Port Scanning:")
    ports_to_scan = [21, 22, 23, 53, 80, 443, 8080, 8443]
    try:
        ip = socket.gethostbyname(domain)
        for port in ports_to_scan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            status = "open" if result == 0 else "closed"
            line = f"  Port {port}: {status}"
            print(line)
            write_output(line)
            sock.close()
    except Exception as e:
        print("  [-] Error:", e)
        write_output(f"  [-] Error: {e}")

def get_ip(domain):
    print("\n[+] IP Address:")
    write_output("\n[+] IP Address:")
    try:
        ip = socket.gethostbyname(domain)
        print(f"  IP: {ip}")
        write_output(f"  IP: {ip}")
        return ip
    except:
        print("  [-] Could not resolve IP.")
        write_output("  [-] Could not resolve IP.")
        return None

def geoip_lookup(ip):
    print("\n[+] IP Geolocation:")
    write_output("\n[+] IP Geolocation:")
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = res.json()
        for field in ['country', 'regionName', 'city', 'org']:
            line = f"  {field.title()} : {data.get(field)}"
            print(line)
            write_output(line)
    except Exception as e:
        print("  [-] GeoIP Lookup failed:", e)
        write_output(f"  [-] GeoIP Lookup failed: {e}")

def http_headers(domain):
    print("\n[+] HTTP Headers:")
    write_output("\n[+] HTTP Headers:")
    try:
        res = requests.get(f"https://{domain}", timeout=5)
        for header, value in res.headers.items():
            line = f"  {header}: {value}"
            print(line)
            write_output(line)
    except Exception as e:
        print("  [-] Error fetching headers:", e)
        write_output(f"  [-] Error fetching headers: {e}")

def tech_detect(domain):
    print("\n[+] Technology Detection:")
    write_output("\n[+] Technology Detection:")
    try:
        res = requests.get(f"https://{domain}", timeout=5)
        headers = res.headers
        server = headers.get("Server", "Unknown")
        x_powered = headers.get("X-Powered-By", "Unknown")
        print(f"  [TECH] Server: {server}")
        print(f"  [TECH] X-Powered-By: {x_powered}")
        write_output(f"  [TECH] Server: {server}")
        write_output(f"  [TECH] X-Powered-By: {x_powered}")
    except:
        print("  [TECH] Not Detected")
        write_output("  [TECH] Not Detected")

def waf_detect(domain):
    print("\n[+] WAF Detection:")
    write_output("\n[+] WAF Detection:")
    try:
        res = requests.get(f"https://{domain}", timeout=5)
        headers = str(res.headers).lower()
        waf_keywords = ['cloudflare', 'sucuri', 'incapsula', 'akamai']
        detected = [waf for waf in waf_keywords if waf in headers]
        if detected:
            line = f"  [WAF] Detected: {', '.join(detected)}"
            print(line)
            write_output(line)
        else:
            print("  [WAF] Not Detected")
            write_output("  [WAF] Not Detected")
    except:
        print("  [WAF] Detection Failed")
        write_output("  [WAF] Detection Failed")

def whois_lookup(domain):
    print("\n[+] WHOIS Lookup:")
    write_output("\n[+] WHOIS Lookup:")
    try:
        data = whois.whois(domain)
        whois_data = json.dumps(data, indent=2, default=str)
        print(whois_data)
        write_output(whois_data)
    except:
        print("  [-] WHOIS lookup failed")
        write_output("  [-] WHOIS lookup failed")

# ---------------- MAIN ----------------

def main():
    show_logo()
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
            get_subdomains_crtsh(domain)
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
            get_subdomains_crtsh(domain)
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
            print("❗ Invalid choice. Try again.")

if __name__ == "__main__":
    main()
