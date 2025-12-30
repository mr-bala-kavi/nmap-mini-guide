# 🔍 Nmap - Complete Guide (Basic to Advanced)

> **Target Domain for Examples:** `kavisnetwork.in`

---

## 📖 Table of Contents

1. [What is Nmap?](#what-is-nmap)
2. [Why Use Nmap?](#why-use-nmap)
3. [Nmap Installation](#nmap-installation)
4. [Basic Scans](#basic-scans)
5. [Port Scanning Techniques](#port-scanning-techniques)
6. [Host Discovery](#host-discovery)
7. [Service & Version Detection](#service--version-detection)
8. [OS Detection](#os-detection)
9. [Nmap Scripting Engine (NSE)](#nmap-scripting-engine-nse)
10. [Timing & Performance](#timing--performance)
11. [Output Formats](#output-formats)
12. [Firewall/IDS Evasion Techniques](#firewallids-evasion-techniques)
13. [Advanced Scanning Techniques](#advanced-scanning-techniques)
14. [Vulnerability Scanning](#vulnerability-scanning)
15. [Practical Examples & Cheat Sheet](#practical-examples--cheat-sheet)

---

## What is Nmap?

**Nmap (Network Mapper)** is a free, open-source network scanning and security auditing tool. It was created by Gordon Lyon (Fyodor) and is used by security professionals, network administrators, and penetration testers worldwide.

### Key Features:
- **Host Discovery** - Find active devices on a network
- **Port Scanning** - Identify open ports and services
- **Version Detection** - Determine software versions running on ports
- **OS Detection** - Identify operating systems
- **Scriptable** - Extensible with Nmap Scripting Engine (NSE)
- **Cross-Platform** - Works on Windows, Linux, macOS

---

## Why Use Nmap?

| Use Case | Description |
|----------|-------------|
| **Network Inventory** | Discover all devices connected to a network |
| **Security Auditing** | Identify open ports and potential vulnerabilities |
| **Penetration Testing** | Reconnaissance phase of ethical hacking |
| **Firewall Testing** | Verify firewall rules are properly configured |
| **Compliance Checking** | Ensure systems meet security standards |
| **Troubleshooting** | Debug network connectivity issues |
| **Service Monitoring** | Track which services are running |
| **Vulnerability Assessment** | Find security weaknesses in systems |

---

## Nmap Installation

### Windows
```bash
# Download from https://nmap.org/download.html
# Or using Chocolatey
choco install nmap
```

### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install nmap
```

### Linux (RHEL/CentOS)
```bash
sudo yum install nmap
```

### macOS
```bash
brew install nmap
```

### Verify Installation
```bash
nmap --version
```

---

## Basic Scans

### 1. Simple Target Scan
Scans the most common 1000 ports on the target.

```bash
nmap kavisnetwork.in
```
**Output:** List of open ports, their states, and services.

---

### 2. Scan Specific Ports

```bash
# Single port
nmap -p 80 kavisnetwork.in

# Multiple ports
nmap -p 80,443,22,21 kavisnetwork.in

# Port range
nmap -p 1-1000 kavisnetwork.in

# All 65535 ports
nmap -p- kavisnetwork.in

# Top ports
nmap --top-ports 100 kavisnetwork.in
```

---

### 3. Scan Multiple Targets

```bash
# Multiple IPs
nmap 192.168.1.1 192.168.1.2 192.168.1.3

# IP range
nmap 192.168.1.1-254

# CIDR notation
nmap 192.168.1.0/24

# From file
nmap -iL targets.txt

# Exclude hosts
nmap 192.168.1.0/24 --exclude 192.168.1.1
```

---

## Port Scanning Techniques

### 1. TCP SYN Scan (Stealth Scan) - Default
**Most popular scan type.** Sends SYN packets and analyzes responses.

```bash
nmap -sS kavisnetwork.in
```

| Response | Port State |
|----------|-----------|
| SYN/ACK | Open |
| RST | Closed |
| No response | Filtered |

**Why use it?**
- Fast and stealthy
- Doesn't complete TCP handshake
- Less likely to be logged

---

### 2. TCP Connect Scan
Completes the full TCP three-way handshake.

```bash
nmap -sT kavisnetwork.in
```

**Why use it?**
- Works without root/admin privileges
- More reliable but slower
- Gets logged by target systems

---

### 3. UDP Scan
Scans UDP ports (DNS, DHCP, SNMP, etc.)

```bash
nmap -sU kavisnetwork.in

# Common UDP ports
nmap -sU -p 53,67,68,69,123,161,162 kavisnetwork.in
```

**Why use it?**
- Many services use UDP (DNS, SNMP, DHCP)
- Often overlooked in security assessments
- Slower than TCP scans

---

### 4. TCP NULL Scan
Sends packets with no flags set.

```bash
nmap -sN kavisnetwork.in
```

**Why use it?**
- Can bypass some firewalls
- Stealthy approach

---

### 5. TCP FIN Scan
Sends packets with only FIN flag.

```bash
nmap -sF kavisnetwork.in
```

**Why use it?**
- Can bypass non-stateful firewalls
- Less common, may avoid detection

---

### 6. TCP Xmas Scan
Sends packets with FIN, PSH, and URG flags (like a Christmas tree).

```bash
nmap -sX kavisnetwork.in
```

**Why use it?**
- Firewall evasion
- Works against Unix/Linux systems

---

### 7. TCP ACK Scan
Sends ACK packets to determine firewall rules.

```bash
nmap -sA kavisnetwork.in
```

**Why use it?**
- Maps firewall rulesets
- Determines filtered vs unfiltered ports

---

### 8. TCP Window Scan
Similar to ACK scan but examines TCP window field.

```bash
nmap -sW kavisnetwork.in
```

---

### 9. TCP Maimon Scan
Sends FIN/ACK probe.

```bash
nmap -sM kavisnetwork.in
```

---

### 10. SCTP INIT Scan
For SCTP protocol (used in telecommunications).

```bash
nmap -sY kavisnetwork.in
```

---

### 11. SCTP COOKIE-ECHO Scan

```bash
nmap -sZ kavisnetwork.in
```

---

### 12. IP Protocol Scan
Determines which IP protocols are supported.

```bash
nmap -sO kavisnetwork.in
```

---

### 13. Idle (Zombie) Scan
Uses a zombie host to scan the target anonymously.

```bash
nmap -sI zombie_host kavisnetwork.in
```

**Why use it?**
- Extremely stealthy
- Hides the real scanner's IP

---

## Host Discovery

### 1. Ping Scan (No Port Scan)
Only discovers live hosts.

```bash
nmap -sn kavisnetwork.in
nmap -sn 192.168.1.0/24
```

---

### 2. No Ping (Skip Host Discovery)
Treats all hosts as online.

```bash
nmap -Pn kavisnetwork.in
```

**Why use it?**
- When ICMP is blocked
- Scanning through firewalls

---

### 3. TCP SYN Ping

```bash
nmap -PS22,80,443 kavisnetwork.in
```

---

### 4. TCP ACK Ping

```bash
nmap -PA22,80,443 kavisnetwork.in
```

---

### 5. UDP Ping

```bash
nmap -PU53,161 kavisnetwork.in
```

---

### 6. ICMP Echo Ping

```bash
nmap -PE kavisnetwork.in
```

---

### 7. ICMP Timestamp Ping

```bash
nmap -PP kavisnetwork.in
```

---

### 8. ICMP Address Mask Ping

```bash
nmap -PM kavisnetwork.in
```

---

### 9. ARP Ping (Local Network)

```bash
nmap -PR 192.168.1.0/24
```

---

### 10. Traceroute

```bash
nmap --traceroute kavisnetwork.in
```

---

## Service & Version Detection

### 1. Service Version Detection

```bash
nmap -sV kavisnetwork.in
```

**What you get:**
- Service name
- Version number
- Additional details (OS, hostname)

---

### 2. Aggressive Version Detection

```bash
nmap -sV --version-intensity 5 kavisnetwork.in
```

**Intensity levels:** 0-9 (higher = more probes, more accurate)

---

### 3. Light Version Detection

```bash
nmap -sV --version-light kavisnetwork.in
```

---

### 4. All Version Detection

```bash
nmap -sV --version-all kavisnetwork.in
```

---

### 5. Banner Grabbing with Scripts

```bash
nmap -sV --script=banner kavisnetwork.in
```

---

## OS Detection

### 1. Enable OS Detection

```bash
nmap -O kavisnetwork.in
```

**What you get:**
- Operating system guess
- Kernel version
- Device type

---

### 2. Aggressive OS Detection

```bash
nmap -O --osscan-guess kavisnetwork.in
```

---

### 3. Limit OS Detection

```bash
nmap -O --osscan-limit kavisnetwork.in
```

---

### 4. Combined Detection (Recommended)

```bash
# OS + Version + Scripts + Traceroute
nmap -A kavisnetwork.in
```

---

## Nmap Scripting Engine (NSE)

NSE allows you to write and run scripts for various tasks.

### Script Categories

| Category | Description |
|----------|-------------|
| `auth` | Authentication bypass/bruteforce |
| `broadcast` | LAN discovery |
| `brute` | Credential bruteforcing |
| `default` | Safe, standard scripts |
| `discovery` | Information gathering |
| `dos` | Denial of service (use carefully!) |
| `exploit` | Vulnerability exploitation |
| `external` | External service queries |
| `fuzzer` | Fuzzing tests |
| `intrusive` | Aggressive, risky scripts |
| `malware` | Malware detection |
| `safe` | Non-intrusive scripts |
| `version` | Version detection |
| `vuln` | Vulnerability detection |

---

### 1. Default Scripts

```bash
nmap -sC kavisnetwork.in
# Or
nmap --script=default kavisnetwork.in
```

---

### 2. Specific Script

```bash
nmap --script=http-title kavisnetwork.in
nmap --script=ssh-brute kavisnetwork.in
nmap --script=ssl-cert kavisnetwork.in
```

---

### 3. Multiple Scripts

```bash
nmap --script=http-title,http-headers,http-methods kavisnetwork.in
```

---

### 4. Script Category

```bash
nmap --script=vuln kavisnetwork.in
nmap --script=discovery kavisnetwork.in
nmap --script=safe kavisnetwork.in
```

---

### 5. Wildcard Scripts

```bash
nmap --script="http-*" kavisnetwork.in
nmap --script="ssh-*" kavisnetwork.in
```

---

### 6. Script Arguments

```bash
nmap --script=http-brute --script-args http-brute.path=/admin kavisnetwork.in
```

---

### 7. Update Scripts Database

```bash
nmap --script-updatedb
```

---

### 8. List Available Scripts

```bash
nmap --script-help=all
nmap --script-help="http-*"
```

---

### Popular NSE Scripts

```bash
# HTTP enumeration
nmap --script=http-enum kavisnetwork.in

# SSL/TLS vulnerabilities
nmap --script=ssl-enum-ciphers -p 443 kavisnetwork.in

# HTTP headers
nmap --script=http-headers kavisnetwork.in

# HTTP methods
nmap --script=http-methods kavisnetwork.in

# DNS enumeration
nmap --script=dns-brute kavisnetwork.in

# SMB vulnerabilities
nmap --script=smb-vuln* -p 445 target

# MySQL info
nmap --script=mysql-info -p 3306 target

# FTP anonymous
nmap --script=ftp-anon -p 21 target

# SSH authentication methods
nmap --script=ssh-auth-methods -p 22 kavisnetwork.in
```

---

## Timing & Performance

### Timing Templates

| Template | Flag | Description | Use Case |
|----------|------|-------------|----------|
| Paranoid | `-T0` | Very slow, IDS evasion | Highly protected networks |
| Sneaky | `-T1` | Slow, IDS evasion | Sensitive environments |
| Polite | `-T2` | Lower bandwidth usage | Slow/unstable networks |
| Normal | `-T3` | Default | General purpose |
| Aggressive | `-T4` | Fast, reliable network | Fast scanning |
| Insane | `-T5` | Very fast, may miss ports | Lab environments |

```bash
# Examples
nmap -T0 kavisnetwork.in  # Paranoid
nmap -T4 kavisnetwork.in  # Aggressive (recommended)
nmap -T5 kavisnetwork.in  # Insane
```

---

### Custom Timing Options

```bash
# Minimum packet rate
nmap --min-rate 100 kavisnetwork.in

# Maximum packet rate
nmap --max-rate 1000 kavisnetwork.in

# Host timeout
nmap --host-timeout 30m kavisnetwork.in

# Scan delay
nmap --scan-delay 1s kavisnetwork.in

# Maximum retries
nmap --max-retries 2 kavisnetwork.in

# Parallel hosts
nmap --min-hostgroup 64 kavisnetwork.in
```

---

## Output Formats

### 1. Normal Output

```bash
nmap -oN output.txt kavisnetwork.in
```

---

### 2. XML Output

```bash
nmap -oX output.xml kavisnetwork.in
```

---

### 3. Grepable Output

```bash
nmap -oG output.gnmap kavisnetwork.in
```

---

### 4. Script Kiddie Output

```bash
nmap -oS output.txt kavisnetwork.in
```

---

### 5. All Formats

```bash
nmap -oA output_basename kavisnetwork.in
# Creates: output_basename.nmap, output_basename.xml, output_basename.gnmap
```

---

### 6. Verbose Output

```bash
nmap -v kavisnetwork.in     # Verbose
nmap -vv kavisnetwork.in    # Very verbose
nmap -vvv kavisnetwork.in   # Extra verbose
```

---

### 7. Debug Output

```bash
nmap -d kavisnetwork.in     # Debug
nmap -dd kavisnetwork.in    # More debug
```

---

### 8. Show Only Open Ports

```bash
nmap --open kavisnetwork.in
```

---

### 9. Reason for Port State

```bash
nmap --reason kavisnetwork.in
```

---

### 10. Packet Trace

```bash
nmap --packet-trace kavisnetwork.in
```

---

## Firewall/IDS Evasion Techniques

### 1. Fragment Packets

```bash
nmap -f kavisnetwork.in
nmap -f -f kavisnetwork.in  # Even smaller fragments
```

---

### 2. Specify MTU

```bash
nmap --mtu 16 kavisnetwork.in
```

---

### 3. Decoy Scan

```bash
# Use decoy IPs
nmap -D decoy1,decoy2,ME kavisnetwork.in

# Random decoys
nmap -D RND:10 kavisnetwork.in
```

---

### 4. Spoof Source IP

```bash
nmap -S 192.168.1.100 kavisnetwork.in
```

---

### 5. Spoof Source Port

```bash
nmap --source-port 53 kavisnetwork.in
nmap -g 80 kavisnetwork.in
```

---

### 6. Append Random Data

```bash
nmap --data-length 25 kavisnetwork.in
```

---

### 7. Randomize Target Order

```bash
nmap --randomize-hosts 192.168.1.0/24
```

---

### 8. Spoof MAC Address

```bash
# Random MAC
nmap --spoof-mac 0 kavisnetwork.in

# Specific vendor
nmap --spoof-mac Apple kavisnetwork.in

# Specific MAC
nmap --spoof-mac 00:11:22:33:44:55 kavisnetwork.in
```

---

### 9. Bad Checksum

```bash
nmap --badsum kavisnetwork.in
```

---

### 10. IPv6 Scanning

```bash
nmap -6 kavisnetwork.in
```

---

## Advanced Scanning Techniques

### 1. Comprehensive Scan

```bash
nmap -A -T4 -p- kavisnetwork.in
```

**Includes:**
- OS detection
- Version detection
- Script scanning
- Traceroute

---

### 2. Aggressive Vulnerability Scan

```bash
nmap -sS -sV -O --script=vuln -T4 kavisnetwork.in
```

---

### 3. Web Application Scan

```bash
nmap -p 80,443 --script=http-enum,http-vuln*,http-methods kavisnetwork.in
```

---

### 4. SSL/TLS Analysis

```bash
nmap --script=ssl-cert,ssl-enum-ciphers,ssl-known-key -p 443 kavisnetwork.in
```

---

### 5. DNS Enumeration

```bash
nmap --script=dns-brute,dns-zone-transfer -p 53 kavisnetwork.in
```

---

### 6. Email Server Scan

```bash
nmap -p 25,110,143,465,587,993,995 --script=smtp-*,pop3-*,imap-* kavisnetwork.in
```

---

### 7. Database Server Scan

```bash
nmap -p 1433,1521,3306,5432,27017 --script=mysql-*,ms-sql-*,oracle-*,mongodb-* target
```

---

### 8. Network Share Discovery

```bash
nmap --script=smb-enum-shares,smb-enum-users -p 445 target
```

---

### 9. Heartbleed Detection

```bash
nmap --script=ssl-heartbleed -p 443 kavisnetwork.in
```

---

### 10. Custom Scan with Everything

```bash
nmap -sS -sU -sV -O -A -T4 -p- --script="default,vuln" -oA full_scan kavisnetwork.in
```

---

## Vulnerability Scanning

### 1. General Vulnerability Scan

```bash
nmap --script=vuln kavisnetwork.in
```

---

### 2. Safe Vulnerability Scan

```bash
nmap --script="vuln and safe" kavisnetwork.in
```

---

### 3. Specific Vulnerability Scripts

```bash
# Shellshock
nmap --script=http-shellshock --script-args uri=/cgi-bin/bin kavisnetwork.in

# Heartbleed (SSL)
nmap --script=ssl-heartbleed -p 443 kavisnetwork.in

# POODLE
nmap --script=ssl-poodle -p 443 kavisnetwork.in

# MS17-010 (EternalBlue)
nmap --script=smb-vuln-ms17-010 -p 445 target

# SMB vulnerabilities
nmap --script=smb-vuln* -p 445 target

# HTTP vulnerabilities
nmap --script="http-vuln*" -p 80,443 kavisnetwork.in

# WordPress vulnerabilities
nmap --script=http-wordpress-enum kavisnetwork.in
```

---

### 4. CVE Checking

```bash
nmap --script=vulscan,vulners kavisnetwork.in
```

> **Note:** You may need to install additional scripts for `vulscan` and `vulners`.

---

## Practical Examples & Cheat Sheet

### Quick Reference Table

| Scan Type | Command | Use Case |
|-----------|---------|----------|
| Basic scan | `nmap kavisnetwork.in` | Quick overview |
| All ports | `nmap -p- kavisnetwork.in` | Full port coverage |
| Service detection | `nmap -sV kavisnetwork.in` | Identify services |
| OS detection | `nmap -O kavisnetwork.in` | Identify OS |
| Aggressive | `nmap -A kavisnetwork.in` | Full information |
| Fast scan | `nmap -T4 -F kavisnetwork.in` | Quick results |
| Stealth scan | `nmap -sS kavisnetwork.in` | Avoid detection |
| UDP scan | `nmap -sU kavisnetwork.in` | UDP services |
| Vulnerability | `nmap --script=vuln kavisnetwork.in` | Find vulnerabilities |
| No ping | `nmap -Pn kavisnetwork.in` | Skip host discovery |

---

### Real-World Scenarios

#### Scenario 1: Initial Reconnaissance
```bash
# First, discover live hosts
nmap -sn kavisnetwork.in

# Quick scan of common ports
nmap -T4 -F kavisnetwork.in

# Detailed scan of interesting targets
nmap -sV -sC -O -T4 kavisnetwork.in
```

---

#### Scenario 2: Web Server Assessment
```bash
nmap -p 80,443,8080,8443 -sV --script=http-enum,http-headers,http-methods,http-vuln* kavisnetwork.in -oA web_scan
```

---

#### Scenario 3: Full Network Audit
```bash
nmap -sS -sU -sV -O -A -T4 --top-ports 1000 --script="default,vuln" -oA network_audit kavisnetwork.in
```

---

#### Scenario 4: Stealthy Reconnaissance
```bash
nmap -sS -T2 -f --data-length 50 -D RND:5 --randomize-hosts kavisnetwork.in
```

---

#### Scenario 5: SSL/TLS Security Check
```bash
nmap -p 443 --script=ssl-enum-ciphers,ssl-cert,ssl-known-key,ssl-heartbleed kavisnetwork.in
```

---

### Complete Command Reference

```bash
# ============================================
# BASIC SCANS
# ============================================

# Default scan
nmap kavisnetwork.in

# Scan specific ports
nmap -p 22,80,443 kavisnetwork.in

# Scan all ports
nmap -p- kavisnetwork.in

# Fast scan (top 100 ports)
nmap -F kavisnetwork.in

# ============================================
# DISCOVERY
# ============================================

# Ping scan only
nmap -sn kavisnetwork.in

# No ping (skip discovery)
nmap -Pn kavisnetwork.in

# ============================================
# SCAN TYPES
# ============================================

# SYN scan (stealth)
nmap -sS kavisnetwork.in

# TCP connect scan
nmap -sT kavisnetwork.in

# UDP scan
nmap -sU kavisnetwork.in

# ============================================
# DETECTION
# ============================================

# Version detection
nmap -sV kavisnetwork.in

# OS detection
nmap -O kavisnetwork.in

# Aggressive scan (OS + versions + scripts + traceroute)
nmap -A kavisnetwork.in

# ============================================
# SCRIPTS
# ============================================

# Default scripts
nmap -sC kavisnetwork.in

# Vulnerability scripts
nmap --script=vuln kavisnetwork.in

# Specific scripts
nmap --script=http-title,http-headers kavisnetwork.in

# ============================================
# TIMING
# ============================================

# Fast timing
nmap -T4 kavisnetwork.in

# Slow/stealth timing
nmap -T1 kavisnetwork.in

# ============================================
# OUTPUT
# ============================================

# Save all formats
nmap -oA results kavisnetwork.in

# Verbose output
nmap -v kavisnetwork.in

# Show only open ports
nmap --open kavisnetwork.in

# ============================================
# EVASION
# ============================================

# Fragment packets
nmap -f kavisnetwork.in

# Use decoys
nmap -D RND:5 kavisnetwork.in

# Random MAC
nmap --spoof-mac 0 kavisnetwork.in

# ============================================
# COMBINED COMMANDS
# ============================================

# Comprehensive scan
nmap -sS -sV -sC -O -T4 -p- -oA full_scan kavisnetwork.in

# Web focused
nmap -p 80,443 -sV --script="http-*" kavisnetwork.in

# Vulnerability assessment
nmap -sV --script=vuln -T4 kavisnetwork.in
```

---

## Summary: What Can You Get from Nmap?

| Information Type | How to Get It |
|-----------------|---------------|
| **Open Ports** | Basic scan: `nmap target` |
| **Service Names** | Version scan: `nmap -sV target` |
| **Service Versions** | Aggressive version: `nmap -sV --version-all target` |
| **Operating System** | OS detection: `nmap -O target` |
| **Network Path** | Traceroute: `nmap --traceroute target` |
| **Firewall Rules** | ACK scan: `nmap -sA target` |
| **Vulnerabilities** | Scripts: `nmap --script=vuln target` |
| **SSL/TLS Info** | Scripts: `nmap --script=ssl-* -p 443 target` |
| **Web Directories** | Scripts: `nmap --script=http-enum target` |
| **DNS Information** | Scripts: `nmap --script=dns-brute target` |
| **User Accounts** | Scripts: `nmap --script=smb-enum-users target` |
| **Network Shares** | Scripts: `nmap --script=smb-enum-shares target` |

---

## ⚠️ Legal Disclaimer

> **IMPORTANT:** Only scan systems that you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions and can result in criminal charges. Always:
> 
> - Get written authorization before scanning
> - Follow responsible disclosure practices
> - Respect privacy and legal boundaries
> - Document all testing activities

---

## 📚 Additional Resources

- **Official Nmap Documentation:** https://nmap.org/docs.html
- **Nmap Book (Free Online):** https://nmap.org/book/
- **NSE Script Library:** https://nmap.org/nsedoc/
- **Nmap Cheat Sheet:** https://www.stationx.net/nmap-cheat-sheet/

---

**Author:** Security Guide  
**Target Domain:** kavisnetwork.in  
**Last Updated:** December 2024

---

*Happy Scanning! 🎯*
