import requests
import socket
import whois
import json
import os
import re


def get_subdomains_crtsh(domain):
    print("\n[+] Subdomain Enumeration (via crt.sh):")
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
                print(f"  [FOUND] http://{sub}")
        else:
            print("  [-] No subdomains found.")
    except Exception as e:
        print("  [-] Error in fetching subdomains:", e)


def port_scan(domain):
    print("\n[+] Port Scanning:")
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 8080, 8443]
    open_ports = []
    try:
        ip = socket.gethostbyname(domain)
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"  [OPEN] Port {port}")
                open_ports.append(port)
            else:
                print(f"  [CLOSED] Port {port}")
            sock.close()
    except Exception as e:
        print("  [-] Error in port scanning:", e)


def get_ip(domain):
    print("\n[+] IP Address:")
    try:
        ip = socket.gethostbyname(domain)
        print(f"  IP: {ip}")
        return ip
    except:
        print("  [-] Could not resolve IP.")
        return None


def geoip_lookup(ip):
    print("\n[+] IP Geolocation:")
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = res.json()
        print(f"  Country : {data.get('country')}")
        print(f"  Region  : {data.get('regionName')}")
        print(f"  City    : {data.get('city')}")
        print(f"  Org     : {data.get('org')}")
    except Exception as e:
        print("  [-] GeoIP Lookup failed:", e)


def http_headers(domain):
    print("\n[+] HTTP Headers:")
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        for header, value in res.headers.items():
            print(f"  {header}: {value}")
    except Exception as e:
        print("  [-] Error fetching headers:", e)


def tech_detect(domain):
    print("\n[+] Technology Detection:")
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        headers = res.headers
        server = headers.get("Server", "Unknown")
        x_powered = headers.get("X-Powered-By", "Unknown")
        print(f"  [TECH] Server: {server}")
        print(f"  [TECH] X-Powered-By: {x_powered}")
    except:
        print("  [TECH] Not Detected")


def waf_detect(domain):
    print("\n[+] Firewall / WAF Detection:")
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        headers = str(res.headers).lower()
        waf_keywords = ['cloudflare', 'sucuri', 'incapsula', 'akamai']
        detected = [waf for waf in waf_keywords if waf in headers]
        if detected:
            print(f"  [WAF] Detected: {', '.join(detected)}")
        else:
            print("  [WAF] Not Detected")
    except:
        print("  [WAF] Detection Failed")


def whois_lookup(domain):
    print("\n[+] WHOIS Lookup:")
    try:
        data = whois.whois(domain)
        print(json.dumps(data, indent=2, default=str))
    except:
        print("  [-] WHOIS lookup failed")


# --------------- MAIN EXECUTION ---------------
if __name__ == "__main__":
    print("\n🔎 Enter Domain (e.g. example.com): ", end="")
    domain = input().strip()

    get_subdomains_crtsh(domain)
    port_scan(domain)
    ip = get_ip(domain)
    if ip:
        geoip_lookup(ip)
    http_headers(domain)
    tech_detect(domain)
    waf_detect(domain)
    whois_lookup(domain)
