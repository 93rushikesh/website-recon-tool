import socket
from datetime import datetime
import threading

open_ports = []
closed_ports = []

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[+] Port {port} is OPEN")
            open_ports.append(port)
        else:
            print(f"[-] Port {port} is CLOSED")
            closed_ports.append(port)
        sock.close()
    except Exception as e:
        print(f"[!] Error scanning port {port}: {e}")

def scan_ports(ip, port_range=100):
    print(f"\n[*] Starting scan on {ip}")
    threads = []

    for port in range(1, port_range + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("\n[*] Scan complete.")

def save_results(ip):
    try:
        with open("scan_results.txt", "w") as f:
            f.write(f"Scan results for {ip} - {datetime.now()}\n\n")
            f.write("Open Ports:\n")
            for port in open_ports:
                f.write(f"{port}\n")
            f.write("\nClosed Ports:\n")
            for port in closed_ports:
                f.write(f"{port}\n")
        print("[+] Results saved to scan_results.txt")
    except Exception as e:
        print(f"[!] Failed to save results: {e}")

if __name__ == "__main__":
    target_ip = input("Enter target IP address: ").strip()
    scan_ports(target_ip, port_range=100)  # default: scan first 100 ports
    save_results(target_ip)
