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

if name == "__main__":
    main()
