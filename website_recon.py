import socket
import requests
import whois
import json
import re
from urllib.parse import urlparse

# Subdomain Enumeration
def get_subdomains(domain):
    return [f"http://{sub}.{domain}" for sub in ["www", "mail", "ftp", "webmail", "cpanel"]]

# Port Scanning
def scan_ports(domain):
    open_ports = []
    for port in [80, 443, 21, 22, 25, 3306]:
        try:
            sock = socket.create_connection((domain, port), timeout=2)
            open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

# HTTP Headers Fetch
def get_http_headers(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        return response.headers, response.text
    except:
        return {}, ""

# IP Address
def get_ip_address(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "N/A"

# IP Geolocation
def get_ip_geolocation(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        return response.json()
    except:
        return {}

# Technology Detection
def detect_technologies(headers):
    tech = []
    server = headers.get('Server', '')
    if "cloudflare" in server.lower():
        tech.append("Cloudflare")
    if "gws" in server.lower():
        tech.append("Google Web Server")
    if headers.get("X-Powered-By"):
        tech.append(headers["X-Powered-By"])
    if "Content-Security-Policy" in headers:
        tech.append("CSP Enabled")
    return tech if tech else ["Not Detected"]

# WHOIS Lookup
def whois_lookup(domain):
    try:
        return whois.whois(domain)
    except:
        return {}

# WAF Detection
def detect_firewall(headers, response_text):
    wafs = []
    server = headers.get('Server', '').lower()
    if "cloudflare" in server or "cf-ray" in headers:
        wafs.append("Cloudflare WAF")
    if "sucuri" in server:
        wafs.append("Sucuri WAF")
    if "imperva" in server or "incapsula" in server:
        wafs.append("Imperva Incapsula WAF")
    if "big-ip" in server:
        wafs.append("F5 BIG-IP WAF")
    if "akamai" in server:
        wafs.append("Akamai WAF")
    if any(h.lower().startswith("x-amzn") for h in headers):
        wafs.append("AWS WAF")
    if re.search(r'access denied|blocked|your request was blocked', response_text, re.IGNORECASE):
        wafs.append("Possible Custom WAF / ModSecurity")
    return wafs if wafs else ["Not Detected"]

# ---------------- Main ------------------

domain = input("🔎 Enter Domain (e.g. example.com): ").strip()

print("\n[+] Subdomain Enumeration:")
for sub in get_subdomains(domain):
    print(f"  [FOUND] {sub}")

print("\n[+] Port Scanning:")
for port in scan_ports(domain):
    print(f"  [OPEN] Port {port}")

print("\n[+] IP Address:")
ip = get_ip_address(domain)
print(f"  IP: {ip}")

print("\n[+] IP Geolocation:")
geo = get_ip_geolocation(ip)
if geo:
    print(f"  Country : {geo.get('country')}")
    print(f"  Region  : {geo.get('region')}")
    print(f"  City    : {geo.get('city')}")
    print(f"  Org     : {geo.get('org')}")
else:
    print("  [!] Failed to get Geolocation info.")

print("\n[+] HTTP Headers:")
headers, response_text = get_http_headers(domain)
for key, value in headers.items():
    print(f"  {key}: {value}")

print("\n[+] Technology Detection:")
techs = detect_technologies(headers)
for t in techs:
    print(f"  [TECH] {t}")

print("\n[+] Firewall / WAF Detection:")
wafs = detect_firewall(headers, response_text)
for w in wafs:
    print(f"  [WAF] {w}")

print("\n[+] WHOIS Lookup:")
whois_info = whois_lookup(domain)
try:
    print(json.dumps(whois_info, indent=2, default=str))
except:
    print(whois_info)
