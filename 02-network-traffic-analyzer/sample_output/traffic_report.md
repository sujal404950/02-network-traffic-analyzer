# Network Traffic Analysis Report
**Generated:** 2026-08-01T14:22:07

**Total packets analyzed:** 4,812

## Protocol Breakdown
- TCP: 4210
- UDP: 512
- Other: 90

## Top Talkers (by packet count)
- 192.168.56.1: 2140 packets
- 192.168.56.101: 1980 packets
- 192.168.56.50: 340 packets
- 192.168.56.102: 210 packets
- 8.8.8.8: 142 packets

## Potential Port Scans
- ⚠️ **192.168.56.1** touched 998 distinct destination ports — likely a port scan.

## Potential SYN / Stealth Scans
- ⚠️ **192.168.56.1** sent 1002 bare SYN packets with no completed handshake — likely a SYN scan.

## Plaintext Credential Exposure
- ⚠️ **192.168.56.50 → 192.168.56.101**: payload contained indicator `USER` — traffic may be unencrypted.
- ⚠️ **192.168.56.50 → 192.168.56.101**: payload contained indicator `PASS ` — traffic may be unencrypted.

---
*This capture was generated in an isolated lab network by running `nmap -sS` against a Metasploitable2 target VM, followed by an unencrypted FTP login via `curl`, to validate detection logic. No real-world traffic was captured or analyzed.*
