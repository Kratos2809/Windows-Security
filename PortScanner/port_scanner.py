#!/usr/bin/env python3

import socket
import argparse
import threading
from queue import Queue
import sys
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for Windows terminal colors
init()

# Dictionary of common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP"
}

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024, threads=100, timeout=1):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout
        self.queue = Queue()
        self.results = []

    def scan_port(self):
        while True:
            if self.queue.empty():
                break
            
            port = self.queue.get()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    service = COMMON_PORTS.get(port, "Unknown")
                    self.results.append((port, "Open", service))
                    print(f"{Fore.GREEN}[+] Port {port:5d}: Open    Service: {service}{Style.RESET_ALL}")
                sock.close()
            
            except socket.gaierror:
                print(f"{Fore.RED}[!] Hostname could not be resolved{Style.RESET_ALL}")
                sys.exit()
            except socket.error:
                print(f"{Fore.RED}[!] Could not connect to server{Style.RESET_ALL}")
                sys.exit()
            
            self.queue.task_done()

    def run(self):
        # Fill queue with ports
        for port in range(self.start_port, self.end_port + 1):
            self.queue.put(port)

        # Create and start threads
        thread_list = []
        for _ in range(self.threads):
            thread = threading.Thread(target=self.scan_port)
            thread_list.append(thread)
            thread.daemon = True
            thread.start()

        # Wait for all threads to complete
        for thread in thread_list:
            thread.join()

def main():
    parser = argparse.ArgumentParser(description='Custom Python Port Scanner')
    parser.add_argument('-t', '--target', required=True, help='Target to scan (IP or domain name)')
    parser.add_argument('-p', '--port', help='Specific port to scan')
    parser.add_argument('-r', '--range', help='Port range to scan (e.g., 20-100)')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads to use')
    parser.add_argument('--timeout', type=float, default=1, help='Timeout for each connection')
    
    args = parser.parse_args()

    print(f"\n{Fore.CYAN}[*] Port Scanner v1.0{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Starting scan on {args.target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Start time: {datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}\n")

    start_port = 1
    end_port = 1024

    if args.port:
        start_port = end_port = int(args.port)
    elif args.range:
        start_port, end_port = map(int, args.range.split('-'))

    scanner = PortScanner(
        args.target,
        start_port=start_port,
        end_port=end_port,
        threads=args.threads,
        timeout=args.timeout
    )

    try:
        scanner.run()
        print(f"\n{Fore.CYAN}[*] Scan completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] End time: {datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit()

if __name__ == "__main__":
    main()
