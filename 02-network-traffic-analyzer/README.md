# Network Traffic Monitoring & Packet Analysis

A Python tool that analyzes live network traffic or Wireshark `.pcap`
captures to automatically flag suspicious activity: port scans, SYN/stealth
scans, unusually chatty hosts, and plaintext credential leakage.

## Why I built this

Wireshark is great for manual inspection, but in a real SOC/blue-team
context you also need to *automate* pattern detection at scale — you
can't eyeball every packet. This project bridges the two: it can read
`.pcap` files exported directly from Wireshark, or capture traffic live,
then applies detection logic for common attacker behavior.

## Detections implemented

| Detection | Logic |
|---|---|
| **Port scan** | Source IP touches ≥15 distinct destination ports |
| **SYN/stealth scan** | Source IP sends ≥20 bare SYN packets with no completed handshake |
| **Top talkers** | Ranks IPs by packet volume — useful for spotting exfiltration or DoS |
| **Plaintext credentials** | Flags payloads containing `USER`, `PASS`, `password=`, `login=` — common in unencrypted FTP/HTTP traffic |
| **Protocol breakdown** | Summarizes TCP/UDP/other traffic mix |

## Setup

```bash
pip install scapy
```

Live capture requires elevated privileges (root on Linux/macOS,
Administrator + Npcap on Windows).

## Usage

**Analyze a Wireshark capture:**
```bash
python3 scripts/traffic_analyzer.py --pcap sample_output/sample_capture.pcap
```

**Live capture:**
```bash
sudo python3 scripts/traffic_analyzer.py --live --interface eth0 --duration 60
```

Both produce a Markdown report (see [`sample_output/traffic_report.md`](sample_output/traffic_report.md)
for an example).

## How I tested it

I generated traffic in a lab environment using `nmap` against a target
VM (both a full TCP connect scan and a SYN scan with `-sS`), captured it
with Wireshark, exported the `.pcap`, and confirmed the tool correctly
flagged the scanning host. I also replayed an unencrypted FTP login
using `curl` to confirm the plaintext-credential detector fires
correctly.

## Skills demonstrated

- Packet-level protocol analysis (TCP flags, IP headers, payloads)
- Recognizing attacker behavior patterns (scanning, enumeration) at
  the network layer
- Practical use of Wireshark for capture + Python (Scapy) for automated
  analysis
- Understanding why plaintext protocols are a security risk

## Roadmap / possible extensions

- Add DNS tunneling detection
- Add ARP spoofing detection
- Export findings to a SIEM-friendly format (e.g. CEF or JSON for Splunk)
