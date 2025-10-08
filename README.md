A simple, multithreaded ARP-based network scanner implemented in Python using Scapy.
Discovers active hosts on a local subnet and reports IP, MAC address, and hostname (via reverse DNS).

Features

Discover active devices on a CIDR subnet (e.g. 192.168.0.0/24)

Reports IP, MAC and hostname (if available)

Multithreaded scanning using threading + queue for speed

Graceful error handling for permission and DNS failures

Clear, commented code for learning

Requirements

Python 3.8+

scapy Python package

Windows users: install Npcap (required for Scapy to send/receive packets): https://nmap.org/npcap/

Installation

Create a virtual environment (recommended) and install dependencies:

python3 -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows (PowerShell)
# venv\Scripts\Activate.ps1

pip install scapy


Optional requirements.txt:

scapy

Files

network_scanner_explained.py — Main scanner script (with line-by-line explanations).

scapy_probe.py — Small helper to test ARP replies (useful for debugging).

README.md — This file.

Usage

Important: Sending raw packets requires privileges.

Linux/macOS: run with sudo

Windows: run PowerShell/CMD as Administrator and ensure Npcap is installed

Example commands

Scan a full /24 (common home subnet):

sudo python3 network_scanner_explained.py 192.168.0.0/24


Scan a small subnet for quick testing:

sudo python3 network_scanner_explained.py 192.168.0.0/29 --no-resolve -t 20


Run interactively (script prompts for CIDR):

sudo python3 network_scanner_explained.py
# then enter: 192.168.0.0/24
