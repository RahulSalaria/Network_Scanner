#!/usr/bin/env python3
"""
network_scanner.py
Multithreaded ARP network scanner using scapy, ipaddress, threading, queue, socket.

Usage:
    sudo python3 network_scanner.py 192.168.1.0/24
or run and follow prompt.

Requirements:
    pip install scapy
On Windows: run as Administrator and install Npcap (scapy needs a packet capture driver).
"""

import sys
import argparse
import ipaddress
import socket
import threading
from queue import Queue
from dataclasses import dataclass, asdict
import time

# Import scapy: keep import local to catch permission/platform issues gracefully
try:
    import scapy.all as scapy
except Exception as e:
    scapy = None
    SCAPY_IMPORT_ERROR = e


@dataclass
class HostInfo:
    ip: str
    mac: str
    hostname: str = "Unknown"


def make_parser():
    p = argparse.ArgumentParser(description="ARP network scanner (multithreaded).")
    p.add_argument("cidr", nargs="?", help="Network in CIDR format, e.g. 192.168.1.0/24")
    p.add_argument("-t", "--threads", type=int, default=100, help="Number of worker threads (default 100)")
    p.add_argument("-T", "--timeout", type=float, default=1.0, help="ARP wait timeout seconds (default 1.0)")
    p.add_argument("--no-resolve", action="store_true", help="Skip reverse DNS hostname resolution")
    return p


def resolve_hostname(ip, timeout=1.0):
    """Try to resolve hostname; handle exceptions and set socket timeout."""
    try:
        # settimeout affects socket operations globally on some platforms; ensure we preserve previous if needed
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"
    except Exception:
        return "Unknown"


def scan_ip(ip, timeout, resolve, result_queue):
    """Send ARP to a single IP and, if response, put HostInfo into result_queue."""
    try:
        arp = scapy.ARP(pdst=str(ip))
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        # srp returns a couple: (answered, unanswered)
        answered = scapy.srp(packet, timeout=timeout, verbose=False)[0]
        if answered:
            # There may be multiple replies; take first
            resp = answered[0][1]
            ip_addr = resp.psrc
            mac = resp.hwsrc
            hostname = "Unknown"
            if resolve:
                hostname = resolve_hostname(ip_addr)
            result_queue.put(HostInfo(ip=ip_addr, mac=mac, hostname=hostname))
    except PermissionError:
        # scapy will generally raise a permission or OSError if not run as admin
        result_queue.put(("__ERROR__", f"PermissionError scanning {ip} - run as root/admin"))
    except Exception as e:
        # Non-fatal: record an error entry we can inspect later
        result_queue.put(("__ERROR__", f"{ip} -> {repr(e)}"))


def worker_thread(ip_queue: Queue, result_queue: Queue, timeout: float, resolve: bool):
    while True:
        try:
            ip = ip_queue.get(block=False)
        except Exception:
            break
        scan_ip(ip, timeout, resolve, result_queue)
        ip_queue.task_done()


def pretty_print(results):
    # Sort by IP
    hosts = [r for r in results if not (isinstance(r, tuple) and r[0] == "__ERROR__")]
    errors = [r for r in results if isinstance(r, tuple) and r[0] == "__ERROR__"]
    hosts_sorted = sorted(hosts, key=lambda h: tuple(int(x) for x in h.ip.split('.')))
    if hosts_sorted:
        # Table header
        print(f"\n{'IP':<16} {'MAC':<20} {'HOSTNAME'}")
        print("-" * 60)
        for h in hosts_sorted:
            print(f"{h.ip:<16} {h.mac:<20} {h.hostname}")
    else:
        print("\nNo hosts found (no ARP replies).")

    if errors:
        print("\nErrors / Notes:")
        for e in errors:
            print(f"  - {e[1]}")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = make_parser()
    args = parser.parse_args(argv)

    if not args.cidr:
        args.cidr = input("Enter network (CIDR), e.g. 192.168.1.0/24: ").strip()

    # scapy import check
    if scapy is None:
        print("ERROR: scapy import failed.")
        print("Detailed error:", SCAPY_IMPORT_ERROR)
        print("Install scapy with: pip install scapy")
        print("On Windows, ensure Npcap is installed and you run as Administrator.")
        sys.exit(1)

    # Validate CIDR
    try:
        network = ipaddress.ip_network(args.cidr, strict=False)
    except ValueError as ve:
        print(f"Invalid CIDR: {ve}")
        sys.exit(1)

    # Build IP queue
    ip_queue = Queue()
    for ip in network.hosts():
        ip_queue.put(ip)

    result_queue = Queue()
    num_threads = max(1, min(args.threads, ip_queue.qsize()))

    print(f"Starting scan: {args.cidr} / hosts: {ip_queue.qsize()} / threads: {num_threads}")
    start_time = time.time()

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker_thread, args=(ip_queue, result_queue, args.timeout, not args.no_resolve))
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for all IPs to be processed
    ip_queue.join()

    # Collect results
    results = []
    while not result_queue.empty():
        results.append(result_queue.get())

    end_time = time.time()
    pretty_print(results)
    print(f"\nScan finished in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
