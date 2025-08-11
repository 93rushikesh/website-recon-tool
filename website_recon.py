#!/usr/bin/env python3
"""
Updated Recon Tool
Features:
 - Subdomain enumeration (crt.sh + rapiddns)
 - HTTPS + HTTP header & tech detection
 - Multi-threaded port scanning
 - GeoIP lookup (ip-api fallback)
 - WHOIS lookup
 - WAF detection (wafw00f if available)
 - Output: TXT and JSON (timestamped)
 - CLI with argparse + non-interactive mode
 - Dependency auto-install for common libs
"""

from __future__ import annotations
import os
import sys
import time
import json
import socket
import subprocess
import threading
import argparse
import re
from datetime import datetime
from urllib.parse import urlparse

# -----------------------------
# Auto-install common dependencies if missing
# -----------------------------
def ensure_package(pkg_name, import_name=None):
    try:
        __import__(import_name or pkg_name)
    except ImportError:
        print(f"[i] Installing missing package: {pkg_name} ...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name])
        try:
            __import__(import_name or pkg_name)
        except ImportError:
            print(f"[!] Failed to import {pkg_name} even after install.")
            raise

for pkg in ("requests", "beautifulsoup4", "colorama", "python-whois"):
    ensure_package(pkg)

# wafw00f optional
try:
    import wafw00f  # type: ignore
    WAFW00F_AVAILABLE = True
except Exception:
    WAFW00F_AVAILABLE = False

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as color_init
import whois
from concurrent.futures import ThreadPoolExecutor, as_completed

color_init(autoreset=True)

# -----------------------------
# Utility helpers
# -----------------------------
OUTPUT_LOCK = threading.Lock()

def safe_print(*args, **kwargs):
    with OUTPUT_LOCK:
        print(*args, **kwargs)

def timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?!\-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None

def normalize_domain(domain: str) -> str:
    parsed = urlparse(domain if "://" in domain else f"//{domain}", scheme="http")
    net = parsed.netloc or parsed.path
    # remove possible credentials
    net = net.split("@")[-1]
    return net.split(":")[0].strip("/")

def ensure_internet(timeout=3) -> bool:
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("8.8.8.8", 53))
        s.close()
        return True
    except Exception:
        return False

# -----------------------------
# Output handling
# -----------------------------
class OutputWriter:
    def __init__(self, base_name: str):
        self.txt_file = f"{base_name}.txt"
        self.json_file = f"{base_name}.json"
        self.data = {"meta": {}, "results": {}}
        # create/overwrite files
        with open(self.txt_file, "w", encoding="utf-8") as f:
            f.write(f"--- Recon Output {datetime.now().isoformat()} ---\n")

    def write_txt(self, section_title: str, text_lines):
        with OUTPUT_LOCK:
            with open(self.txt_file, "a", encoding="utf-8") as f:
                f.write(f"\n--- {section_title} ---\n")
                for l in text_lines:
                    f.write(l + "\n")

    def store_json(self, key, value):
        self.data["results"][key] = value

    def set_meta(self, meta: dict):
        self.data["meta"] = meta

    def flush_json(self):
        with OUTPUT_LOCK:
            with open(self.json_file, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)

# -----------------------------
# Subdomain enumeration
# -----------------------------
def query_crtsh(domain: str, timeout=15):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs = set()
    try:
        res = requests.get(url, timeout=timeout)
        if res.status_code == 200:
            try:
                data = res.json()
                for entry in data:
                    names = entry.get("name_value", "")
                    for n in names.split("\n"):
                        if domain in n:
                            subs.add(n.strip().lower())
            except ValueError:
                pass
    except Exception:
        pass
    return subs

def query_rapiddns(domain: str, timeout=15):
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    subs = set()
    try:
        res = requests.get(url, timeout=timeout, headers={"User-Agent":"Mozilla/5.0"})
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, "html.parser")
            # Rapiddns lists subdomains in table cells
            for td in soup.select("table.table td"):
                text = td.get_text(strip=True)
                if domain in text:
                    subs.add(text.lower())
    except Exception:
        pass
    return subs

def enumerate_subdomains(domain: str, workers=6):
    safe_print(Fore.CYAN + "[*] Enumerating subdomains...")
    sources = [query_crtsh, query_rapiddns]
    results = set()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(src, domain) for src in sources]
        for fut in as_completed(futures):
            try:
                res = fut.result()
                results.update(res)
            except Exception:
                pass
    # normalize & unique
    cleaned = sorted({normalize_domain(s) for s in results if s and domain in s})
    return cleaned

# -----------------------------
# Port scanning (multi-threaded)
# -----------------------------
def single_port_scan(ip: str, port: int, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((ip, port))
        s.close()
        return port if res == 0 else None
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None

def port_scan(domain_or_ip: str, ports: list[int], workers=50, timeout=1.0):
    try:
        ip = socket.gethostbyname(domain_or_ip)
    except Exception as e:
        safe_print(Fore.YELLOW + f"[!] Could not resolve {domain_or_ip}: {e}")
        return {"ip": None, "open_ports": []}
    safe_print(Fore.CYAN + f"[*] Scanning {ip} on {len(ports)} ports (threads={workers}) ...")
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(single_port_scan, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                r = fut.result()
                if r:
                    open_ports.append(r)
                    safe_print(Fore.GREEN + f"  [+] Port {r} is open")
            except Exception:
                pass
    open_ports = sorted(open_ports)
    return {"ip": ip, "open_ports": open_ports}

# -----------------------------
# HTTP Headers & Tech detection (HTTP/HTTPS)
# -----------------------------
def fetch_http_headers(domain: str, timeout=6):
    schemes = ["https://", "http://"]
    for scheme in schemes:
        url = scheme + domain
        try:
            res = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent":"Mozilla/5.0"})
            headers = {k: v for k, v in res.headers.items()}
            server = headers.get("server") or headers.get("x-powered-by")
            return {"url": res.url, "status_code": res.status_code, "headers": headers, "server": server}
        except requests.exceptions.SSLError:
            # try next scheme or skip
            continue
        except Exception:
            continue
    return {"url": None, "status_code": None, "headers": {}, "server": None}

# -----------------------------
# GeoIP info
# -----------------------------
def geoip_lookup(ip: str):
    # Try ip-api.com fallback (no key)
    fallback = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,query,timezone"
    try:
        res = requests.get(fallback, timeout=6)
        if res.status_code == 200:
            data = res.json()
            return data
    except Exception:
        pass
    return {}

# -----------------------------
# WHOIS
# -----------------------------
def whois_lookup(domain: str):
    try:
        info = whois.whois(domain)
        # whois returns a dict-like object; convert values to strings
        data = {}
        for k, v in info.items():
            try:
                data[k] = str(v)
            except Exception:
                data[k] = repr(v)
        return data
    except Exception as e:
        return {"error": str(e)}

# -----------------------------
# WAF detection (wafw00f)
# -----------------------------
def waf_detect(domain: str):
    if not WAFW00F_AVAILABLE:
        return {"available": False, "msg": "wafw00f not installed"}
    try:
        # wafw00f has a programmatic API, but it varies by version. We'll call as subprocess for simplicity.
        res = subprocess.run([sys.executable, "-m", "wafw00f", domain], capture_output=True, text=True, timeout=30)
        return {"available": True, "output": res.stdout.strip() or res.stderr.strip()}
    except Exception as e:
        return {"available": True, "error": str(e)}

# -----------------------------
# Full scan orchestration
# -----------------------------
def full_scan(domain: str, ports: list[int], output: OutputWriter, threads=50):
    meta = {"domain": domain, "scanned_at": datetime.now().isoformat()}
    output.set_meta(meta)
    safe_print(Fore.MAGENTA + f"\n=== Full Scan for {domain} ===")

    # 1) Subdomains
    subs = enumerate_subdomains(domain, workers=6)
    output.write_txt("Subdomains", subs or ["No subdomains found."])
    output.store_json("subdomains", subs)

    # 2) Port scan on main domain
    port_res = port_scan(domain, ports, workers=min(threads, 200))
    output.write_txt("Port Scan (main)", [f"IP: {port_res['ip']}", f"Open Ports: {port_res['open_ports']}"])
    output.store_json("port_scan_main", port_res)

    # 3) GeoIP for main IP
    geo = geoip_lookup(port_res["ip"]) if port_res["ip"] else {}
    output.write_txt("GeoIP (main)", [json.dumps(geo, ensure_ascii=False, indent=2)])
    output.store_json("geoip_main", geo)

    # 4) HTTP headers & tech
    http_info = fetch_http_headers(domain)
    headers_lines = [f"URL: {http_info['url']}", f"Status: {http_info['status_code']}", "Headers:"]
    for k, v in http_info["headers"].items():
        headers_lines.append(f"  {k}: {v}")
    output.write_txt("HTTP Headers & Tech", headers_lines)
    output.store_json("http_info", http_info)

    # 5) WAF detect
    waf = waf_detect(domain)
    output.write_txt("WAF Detection", [json.dumps(waf, ensure_ascii=False, indent=2)])
    output.store_json("waf", waf)

    # 6) WHOIS
    who = whois_lookup(domain)
    # short human readable
    who_lines = []
    for k, v in who.items():
        who_lines.append(f"{k}: {v}")
    output.write_txt("WHOIS", who_lines[:200] or ["No WHOIS data"])
    output.store_json("whois", who)

    # 7) Quick port scan for discovered subdomains (top N) concurrently (optional)
    if subs:
        safe_print(Fore.CYAN + "\n[*] Scanning top subdomains (concurrent) for open ports (first 10)...")
        top = subs[:10]
        sub_results = {}
        with ThreadPoolExecutor(max_workers=10) as ex:
            fut_map = {ex.submit(port_scan, s, ports, workers=30): s for s in top}
            for fut in as_completed(fut_map):
                s = fut_map[fut]
                try:
                    r = fut.result()
                    sub_results[s] = r
                except Exception:
                    sub_results[s] = {"error": "failed"}
        output.write_txt("Subdomain Port Scans", [f"{k}: {v}" for k, v in sub_results.items()])
        output.store_json("subdomain_port_scans", sub_results)

    # flush json at end
    output.flush_json()
    safe_print(Fore.GREEN + f"\n[+] Scan complete. Results saved to {output.txt_file} and {output.json_file}")

# -----------------------------
# Argparse & main
# -----------------------------
def parse_ports(port_arg: str | None):
    # Accept formats: "80,443,8080" or "1-1024" or "21-25,80,443"
    if not port_arg:
        return [21,22,23,25,53,80,110,143,443,445,8080]  # default
    ports = set()
    parts = port_arg.split(",")
    for p in parts:
        if "-" in p:
            a,b = p.split("-",1)
            try:
                a=int(a); b=int(b)
                ports.update(range(min(a,b), max(a,b)+1))
            except Exception:
                continue
        else:
            try:
                ports.add(int(p))
            except Exception:
                continue
    return sorted(p for p in ports if 1 <= p <= 65535)

def main():
    parser = argparse.ArgumentParser(description="Updated Recon Tool - multi-feature")
    parser.add_argument("--domain", "-d", help="Target domain (e.g. example.com)")
    parser.add_argument("--output", "-o", help="Base name for output files (default recon_<timestamp>)")
    parser.add_argument("--ports", "-p", help="Ports to scan (e.g. 1-1024 or 80,443,8080)")
    parser.add_argument("--full", "-f", action="store_true", help="Run full scan (default interactive)")
    parser.add_argument("--threads", "-t", type=int, default=50, help="Max threads for port scanning")
    args = parser.parse_args()

    if not ensure_internet():
        safe_print(Fore.RED + "❗ No internet connection detected. Abort.")
        sys.exit(1)

    domain = args.domain
    if not domain:
        domain = input("Enter domain (e.g. example.com): ").strip()
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        safe_print(Fore.YELLOW + f"❗ '{domain}' does not look like a valid domain. Exiting.")
        sys.exit(1)

    base = args.output or f"recon_{domain}_{timestamp()}"
    output = OutputWriter(base)

    ports = parse_ports(args.ports)

    if args.full:
        full_scan(domain, ports, output, threads=args.threads)
        return

    # Interactive menu
    safe_print(Fore.CYAN + f"\n=== Recon Tool (target: {domain}) ===")
    while True:
        safe_print("\nChoose option:")
        safe_print("1) Subdomain Enumeration")
        safe_print("2) Port Scan (main domain)")
        safe_print("3) IP & GeoIP Info")
        safe_print("4) HTTP Headers & Tech")
        safe_print("5) WAF Detection")
        safe_print("6) WHOIS Lookup")
        safe_print("7) Full Scan")
        safe_print("8) Exit")
        choice = input("Option: ").strip()
        if choice == "1":
            subs = enumerate_subdomains(domain)
            safe_print(Fore.GREEN + f"Found {len(subs)} subdomains")
            output.write_txt("Subdomains", subs or ["No subdomains found."])
            output.store_json("subdomains", subs)
            output.flush_json()
        elif choice == "2":
            res = port_scan(domain, ports, workers=min(args.threads, 200))
            output.write_txt("Port Scan", [f"IP: {res['ip']}", f"Open: {res['open_ports']}"])
            output.store_json("port_scan", res)
            output.flush_json()
        elif choice == "3":
            try:
                ip = socket.gethostbyname(domain)
                geo = geoip_lookup(ip)
                output.write_txt("GeoIP", [json.dumps(geo, ensure_ascii=False, indent=2)])
                output.store_json("geoip", geo)
                output.flush_json()
            except Exception as e:
                safe_print(Fore.YELLOW + f"Error: {e}")
        elif choice == "4":
            h = fetch_http_headers(domain)
            lines = [f"URL: {h['url']}", f"Status: {h['status_code']}"]
            for k, v in h["headers"].items():
                lines.append(f"{k}: {v}")
            output.write_txt("HTTP Headers", lines)
            output.store_json("http", h)
            output.flush_json()
        elif choice == "5":
            waf = waf_detect(domain)
            output.write_txt("WAF", [json.dumps(waf, ensure_ascii=False, indent=2)])
            output.store_json("waf", waf)
            output.flush_json()
        elif choice == "6":
            w = whois_lookup(domain)
            output.write_txt("WHOIS", [f"{k}: {v}" for k, v in w.items()])
            output.store_json("whois", w)
            output.flush_json()
        elif choice == "7":
            full_scan(domain, ports, output, threads=args.threads)
        elif choice == "8":
            safe_print(Fore.CYAN + f"Exiting. Results (if any) saved at: {output.txt_file} and {output.json_file}")
            break
        else:
            safe_print(Fore.YELLOW + "Invalid option.")

if __name__ == "__main__":
    main()
