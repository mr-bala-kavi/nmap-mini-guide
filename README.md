# 🔍 Nmap Complete Guide

A comprehensive guide covering Nmap (Network Mapper) from basic to advanced usage — everything you need for network scanning and security auditing.

## 📖 What's Inside

This guide covers:

- **Introduction** — What is Nmap and why use it
- **Installation** — Setup on Windows, Linux, and macOS
- **Basic Scans** — Simple target and port scanning
- **Port Scanning Techniques** — SYN, TCP, UDP, NULL, FIN, Xmas, and more
- **Host Discovery** — Ping scans, ARP, and traceroute
- **Service & Version Detection** — Identify running services
- **OS Detection** — Fingerprint operating systems
- **Nmap Scripting Engine (NSE)** — Extend Nmap with powerful scripts
- **Timing & Performance** — Optimize scan speed
- **Output Formats** — Save results in various formats
- **Firewall/IDS Evasion** — Bypass security measures
- **Vulnerability Scanning** — Find security weaknesses
- **Practical Examples** — Real-world scenarios and cheat sheet

## 🚀 Quick Start

```bash
# Basic scan
nmap example.com

# Scan all ports
nmap -p- example.com

# Service and version detection
nmap -sV example.com

# Aggressive scan (OS + version + scripts + traceroute)
nmap -A example.com

# Vulnerability scan
nmap --script=vuln example.com
```

## 📁 Files

| File | Description |
|------|-------------|
| [nmap-complete-guide.md](nmap-complete-guide.md) | Full comprehensive guide |

## ⚠️ Legal Disclaimer

> **IMPORTANT:** Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions.

## 📚 Resources

- [Nmap Official Documentation](https://nmap.org/docs.html)
- [Nmap Book (Free Online)](https://nmap.org/book/)
- [NSE Script Library](https://nmap.org/nsedoc/)

## 📄 License

This guide is provided for educational purposes only.

---

*Happy Scanning! 🎯*
