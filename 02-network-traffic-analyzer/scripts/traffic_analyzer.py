                      
"""
traffic_analyzer.py — Network Traffic Monitoring & Packet Analysis
---------------------------------------------------------------------
Captures live traffic (or reads a .pcap file exported from Wireshark)
and flags suspicious patterns: port scans, unusual protocols, plaintext
credential leakage, and high-volume talkers.

Usage:
    # Live capture (requires root/admin privileges)
    sudo python3 traffic_analyzer.py --live --interface eth0 --duration 60

    # Analyze an existing pcap (e.g. exported from Wireshark)
    python3 traffic_analyzer.py --pcap capture.pcap

Requirements:
    pip install scapy
"""

import argparse
import sys
from collections import defaultdict, Counter
from datetime import datetime

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, Raw
except ImportError:
    print("[!] Missing dependency. Install with: pip install scapy")
    sys.exit(1)


class TrafficAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.ip_talkers = Counter()
        self.port_hits = defaultdict(set)                                          
        self.protocol_count = Counter()
        self.plaintext_creds = []
        self.syn_only = defaultdict(int)                                    

                                                                    
        self.cred_keywords = [b"password=", b"pass=", b"PASS ", b"USER ", b"login="]

    def process_packet(self, pkt):
        self.packet_count += 1

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            self.ip_talkers[src] += 1

            if TCP in pkt:
                self.protocol_count["TCP"] += 1
                dport = pkt[TCP].dport
                self.port_hits[src].add(dport)

                flags = pkt[TCP].flags
                                                                           
                if flags == "S":
                    self.syn_only[src] += 1

            elif UDP in pkt:
                self.protocol_count["UDP"] += 1
            else:
                self.protocol_count["Other"] += 1

            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                for kw in self.cred_keywords:
                    if kw in payload:
                        self.plaintext_creds.append({
                            "src": src,
                            "dst": dst,
                            "indicator": kw.decode(errors="ignore").strip(),
                        })
                        break

    def detect_port_scans(self, threshold=15):
        """Flag source IPs that touched more than `threshold` distinct
        destination ports — a classic port scan signature."""
        scanners = []
        for ip, ports in self.port_hits.items():
            if len(ports) >= threshold:
                scanners.append({"ip": ip, "distinct_ports_touched": len(ports)})
        return scanners

    def detect_syn_scans(self, threshold=20):
        """Flag source IPs sending many bare SYN packets — SYN/stealth scan."""
        return [
            {"ip": ip, "syn_count": count}
            for ip, count in self.syn_only.items()
            if count >= threshold
        ]

    def top_talkers(self, n=5):
        return self.ip_talkers.most_common(n)

    def generate_report(self):
        lines = []
        lines.append("# Network Traffic Analysis Report")
        lines.append(f"**Generated:** {datetime.now().isoformat(timespec='seconds')}\n")
        lines.append(f"**Total packets analyzed:** {self.packet_count}\n")

        lines.append("## Protocol Breakdown")
        for proto, count in self.protocol_count.most_common():
            lines.append(f"- {proto}: {count}")

        lines.append("\n## Top Talkers (by packet count)")
        for ip, count in self.top_talkers():
            lines.append(f"- {ip}: {count} packets")

        port_scans = self.detect_port_scans()
        lines.append("\n## Potential Port Scans")
        if port_scans:
            for s in port_scans:
                lines.append(
                    f"- ⚠️ **{s['ip']}** touched {s['distinct_ports_touched']} "
                    f"distinct destination ports — likely a port scan."
                )
        else:
            lines.append("- None detected.")

        syn_scans = self.detect_syn_scans()
        lines.append("\n## Potential SYN / Stealth Scans")
        if syn_scans:
            for s in syn_scans:
                lines.append(
                    f"- ⚠️ **{s['ip']}** sent {s['syn_count']} bare SYN packets "
                    f"with no completed handshake — likely a SYN scan."
                )
        else:
            lines.append("- None detected.")

        lines.append("\n## Plaintext Credential Exposure")
        if self.plaintext_creds:
            for c in self.plaintext_creds:
                lines.append(
                    f"- ⚠️ **{c['src']} → {c['dst']}**: payload contained "
                    f"indicator `{c['indicator']}` — traffic may be unencrypted."
                )
        else:
            lines.append("- None detected.")

        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("--live", action="store_true", help="Capture live traffic")
    parser.add_argument("--interface", default=None, help="Network interface for live capture")
    parser.add_argument("--duration", type=int, default=30, help="Capture duration in seconds")
    parser.add_argument("--pcap", default=None, help="Path to an existing .pcap file")
    parser.add_argument("--output", default="traffic_report.md", help="Output report filename")
    args = parser.parse_args()

    analyzer = TrafficAnalyzer()

    if args.pcap:
        print(f"[*] Reading pcap file: {args.pcap}")
        packets = rdpcap(args.pcap)
        for pkt in packets:
            analyzer.process_packet(pkt)
    elif args.live:
        print(f"[*] Starting live capture on {args.interface or 'default interface'} "
              f"for {args.duration}s (requires elevated privileges)...")
        sniff(
            iface=args.interface,
            timeout=args.duration,
            prn=analyzer.process_packet,
            store=False,
        )
    else:
        print("[!] Specify either --live or --pcap <file>")
        sys.exit(1)

    report = analyzer.generate_report()
    with open(args.output, "w") as f:
        f.write(report)

    print(f"[+] Report written to {args.output}")
    print(f"[+] Analyzed {analyzer.packet_count} packets.")


if __name__ == "__main__":
    main()
