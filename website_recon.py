import socket
import threading
from queue import Queue
from colorama import Fore, Style, init

init(autoreset=True)

print(Fore.CYAN + """
██████╗░░█████╗░██████╗░██████╗░██████╗░░█████╗░██████╗░░██████╗
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝
██║░░██║██║░░██║██║░░██║██████╦╝██████╔╝███████║██████╔╝╚█████╗░
██║░░██║██║░░██║██║░░██║██╔══██╗██╔═══╝░██╔══██║██╔═══╝░░╚═══██╗
██████╔╝╚█████╔╝██████╔╝██████╦╝██║░░░░░██║░░██║██║░░░░░██████╔╝
╚═════╝░░╚════╝░╚═════╝░╚═════╝░╚═╝░░░░░╚═╝░░╚═╝╚═╝░░░░░╚═════╝░
""")

print(Fore.YELLOW + Style.BRIGHT + "\nWELCOME TO PYTHON PORT SCANNER")
print(Fore.YELLOW + "Developed by: RUSHIKESH GADEKAR")

# Common ports to scan
common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 8080, 8443]

# Thread count
thread_count = 100

# Queue to store ports
queue = Queue()

# Lists to store results
open_ports = []
closed_ports = []

# Lock for printing
print_lock = threading.Lock()

def portscan(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((ip, port))
        with print_lock:
            print(Fore.GREEN + f"[+] Port {port} is open")
        open_ports.append(port)
        s.close()
    except:
        with print_lock:
            print(Fore.RED + f"[-] Port {port} is closed")
        closed_ports.append(port)

def threader(ip):
    while True:
        worker = queue.get()
        portscan(ip, worker)
        queue.task_done()

def start_scan(ip):
    for _ in range(thread_count):
        t = threading.Thread(target=threader, args=(ip,))
        t.daemon = True
        t.start()

    for port in common_ports:
        queue.put(port)

    queue.join()

    print(Fore.CYAN + "\nScan Summary:")
    print(Fore.GREEN + f"Open ports: {open_ports}")
    print(Fore.RED + f"Closed ports: {closed_ports}")

if __name__ == "__main__":
    target = input("\nEnter target IP address: ")
    start_scan(target)
