import requests
import socket
import whois

def subdomain_enum(domain):
    print("\n[+] Subdomain Enumeration:")
    subdomains = ['www', 'mail', 'ftp', 'test']
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            requests.get(url, timeout=2)
            print(f"  [FOUND] {url}")
        except requests.ConnectionError:
            pass

def port_scan(domain):
    print("\n[+] Port Scanning:")
    common_ports = [21, 22, 23, 25, 53, 80, 443, 8080]
    ip = socket.gethostbyname(domain)
    for port in common_ports:
        sock = socket.socket()
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"  [OPEN] Port {port}")
        sock.close()

def fetch_headers(domain):
    print("\n[+] HTTP Headers:")
    try:
        response = requests.get(f"http://{domain}", timeout=3)
        for key, value in response.headers.items():
            print(f"  {key}: {value}")
    except:
        print("  [ERROR] Could not fetch headers.")

def whois_lookup(domain):
    print("\n[+] WHOIS Lookup:")
    try:
        data = whois.whois(domain)
        print(data)
    except:
        print("  [ERROR] WHOIS data not found.")

if __name__ == "__main__":
    target = input("Enter Domain (e.g. example.com): ")
    subdomain_enum(target)
    port_scan(target)
    fetch_headers(target)
    whois_lookup(target)