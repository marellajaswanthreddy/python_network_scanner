# Python Network Scanner (Basic)

A beginner-friendly network diagnostics project using **Python**, **Scapy**, and the **socket** library.

## Features

- ARP-based live-host discovery on a private IPv4 subnet
- TCP checks for common ports (FTP, SSH, HTTP/HTTPS, SMB, databases, and others)
- Basic banner grabbing when a service returns a response
- Plain-text report saved as `scan_report.txt`
- Input safeguards: private IPv4 networks only, maximum `/24`-sized scan, and a limited port list

## Requirements

- Python 3.10+
- Scapy
- A network you own or have explicit permission to test

## Installation

### Windows

1. Install Python 3.10 or newer.
2. Open PowerShell in this project folder.
3. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```

4. Scapy's ARP discovery may require Npcap and an elevated terminal on Windows. Install Npcap from its official website if Scapy reports that packet capture is unavailable.

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
sudo .venv/bin/python scanner.py 192.168.1.0/24
```

Use the subnet that matches your own local network. The example is only an example; it may not match your router's subnet.

## Find your local subnet

- **Windows:** run `ipconfig` and inspect the IPv4 Address and Subnet Mask for your active adapter.
- **Linux:** run `ip addr` or `ip route`.
- **macOS:** run `ifconfig` or check Network settings.

For example, an address such as `192.168.1.23` with mask `255.255.255.0` commonly corresponds to `192.168.1.0/24`.

## Usage

Default common-port list:

```bash
python scanner.py 192.168.1.0/24
```

Specify ports and an output filename:

```bash
python scanner.py 192.168.1.0/24 --ports 22,80,443,445,8080 --output my_report.txt
```

Adjust TCP connection timeout:

```bash
python scanner.py 192.168.1.0/24 --timeout 1.0
```

The script writes a text report to `scan_report.txt` by default.

## How it works

1. **Host discovery:** Scapy sends ARP requests to discover devices on the local Layer-2 subnet.
2. **Port scanning:** Python sockets attempt TCP connections to the selected ports.
3. **Banner grabbing:** For open ports, the scanner attempts to read a short service response. On ports 80 and 8080, it sends a basic HTTP `HEAD` request.
4. **Reporting:** Host addresses, MAC addresses, open ports, service labels, and available banner text are written to a plain-text report.

## Limitations

- ARP discovery works only on the local Layer-2 network; it does not discover hosts across routers.
- Firewalls, Wi-Fi client isolation, and host settings may prevent replies.
- Some services do not send banners, and HTTPS/TLS services may not provide readable text before a TLS handshake.
- Port labels are common defaults, not proof of the actual protocol.
- This is an educational diagnostic tool, not a replacement for a professional security scanner.

## Responsible use

Scan only your own devices or networks for which you have explicit authorization. This project is intentionally limited to private IPv4 ranges and small subnets. Avoid scanning public IP ranges or networks you do not administer.
