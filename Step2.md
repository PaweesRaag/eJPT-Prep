# Advanced DNS Active Recon — dnsenum, fierce, Zone Transfers (AXFR), Detection & Exploitation

**Discovering information about a target without actively interacting with or modifying the system.**

##  Table of Contents
1. [Introduction](#introduction)
2. [DNS Recon Fundamentals](#dns-recon-fundamentals)
3. [Active Recon With dnsenum](#1-active-recon-with-dnsenum)
4. [Active Recon With fierce](#2-active-recon-with-fierce)
5. [DNS Zone Transfers — AXFR Deep Dive](#3-dns-zone-transfers--axfr-deep-dive)
6. [Detecting Zone Transfer Vulnerabilities](#4-detecting-zone-transfer-vulnerabilities)
7. [Exploiting AXFR](#5-exploiting-axfr)
8. [Defensive Notes](#6-defensive-notes)

---

## Introduction
DNS is often overlooked yet remains one of the richest treasure troves during reconnaissance. Misconfigured name servers can leak entire internal/production infrastructure through zone transfers, making DNS a critical security layer to audit and attack.

This document covers advanced active DNS recon, including:
* Enumeration
* Subdomain discovery
* AXFR zone-transfer exploitation
* Evasion techniques
* Practical attacker workflows

---

## DNS Recon Fundamentals
DNS supports multiple query types. During recon, the important ones are:

| Type | Purpose |
| :--- | :--- |
| **A** | IPv4 address |
| **AAAA** | IPv6 address |
| **MX** | Mail server |
| **NS** | Name servers |
| **TXT** | Misc text (SPF, DKIM) |
| **AXFR** | Full zone transfer (**dangerous if allowed**) |

---

## 1. Active Recon With dnsenum
`dnsenum` performs aggressive DNS enumeration using:
* WHOIS lookups
* Zone transfers
* Subdomain brute-forcing
* Reverse lookups
* NS enumeration

### Key Flags

| Flag | Explanation |
| :--- | :--- |
| `--enum` | Enable all enumeration steps |
| `--threads <n>` | Speed up brute-forcing (use 10+ carefully) |
| `--dnsserver <server>` | Force a specific DNS server |
| `--norecursion` | Disable recursive queries |
| `-f <file>` | Custom wordlist for subdomain brute-force |
| `--axfr` | Force AXFR attempts |

### Practical Example

**Complete aggressive enumeration**
```bash
dnsenum --enum --threads 15 --norecursion example.com
```
**AXFR-focused scan**
```
dnsenum --enum --axfr example.com
```
**Using a custom wordlist for subdomain brute force**
```
dnsenum -f /usr/share/wordlists/dns.txt example.com
```
---
## 2. Active Recon With fierce

`fierce` is extremely powerful for mapping DNS environments that use:
* Wildcard DNS
* Geo-distributed NS records
* Load-balanced infrastructure

It recursively hunts for subdomains & NS relationships.

### Why Fierce Is Dangerous for Blue Teams
* Walks the entire DNS structure
* Detects misconfigured NS servers
* Identifies shadow IT
* Uses smart logic (not just brute force)

### Usage

**Basic scan**
```bash
fierce --domain example.com
```
**Scan using a specific DNS server**

```bash
fierce --domain example.com --dns-server ns1.example.com
```
**Force range scanning to find hidden blocks**
```
fierce --range 10.0.0.0-10.0.0.255 --domain example.com
```
---
## 3. DNS Zone Transfers — AXFR Deep Dive
### What AXFR Is ??
<br>
AXFR (Authoritative Zone Transfer) is a DNS mechanism used to replicate DNS records between primary & secondary nameservers.

> **If misconfigured:**
> It leaks the **ENTIRE DNS ZONE**, including:
> * Internal hostnames
> * Development servers
> * Staging servers
> * VPN endpoints
> * Admin panels
> * SIEM/log servers
> **This is catastrophic.**



### When AXFR Works
AXFR succeeds if:
1.  The target NS allows transfers from anywhere (misconfigured)
2.  The NS allows transfers from your IP (rare)
3.  The NS doesn’t validate TSIG / ACL rules

### When AXFR Fails
Most modern DNS servers reject unknown AXFR requests:
* *Transfer failed.*
* *Connection timed out.*
* *Refused.*

But even a "Refused" error teaches you:
* The host exists
* You’re talking to an authoritative NS
* It’s actively protected

---

## 4. Detecting Zone Transfer Vulnerabilities

### Manual Methods

**1. Using dig**
```bash
dig AXFR example.com @ns1.example.com
```
**2. Using host**
```
host -t AXFR example.com ns1.example.com
```
**3. Using nslookup**
```
server ns1.example.com
ls -d example.com
```
### Automated Methods
**dnsenum**
```
dnsenum --enum --axfr example.com
```
**fierce**
```
fierce --domain example.com --dns-servers ns1.example.com
```
**Nmap NSE script**
```
nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com ns1.example.com
```
*If AXFR is possible, Nmap will dump the entire zone.*
---
## 5. Exploiting AXFR

Once AXFR succeeds, you receive:
* ALL subdomains
* ALL internal hosts
* ALL DNS entries (SRV, MX, TXT, etc.)

**Example output:**
```text
mail.example.com   A   10.0.2.15
vpn.example.com    A   10.1.0.4
dev-db.example.com A   192.168.5.12
intranet.example.com CNAME internal-web01
```
This is pure gold.

**Host Enumeration**
Once you have internal hosts, resolve them:
```
for i in $(cat dump.txt | awk '{print $1}'); do dig +short $i; done
```
### Pivoting After AXFR
Common attack paths:
* Check for vulnerable webapps on internal subdomains
* Bruteforce VPN endpoints
* Target staging/dev servers
* Identify admin portals
* Check exposed RDP/SSH services
* Build an internal network map

**AXFR essentially bypasses:**
1.  Subdomain brute force
2.  Passive DNS
3.  Certificate transparency enumeration

It hands you everything.

---

## 6. Defensive Notes

**Prevent AXFR:**
* Disable AXFR unless required

**Restrict zone transfers:**
* ACL (IP-based)
* TSIG keys

**Monitor for abnormal AXFR traffic (tcp/53)**
* Log every zone transfer

**Validate your NS:**
```bash
dig example.com NS
```
**Then test each name server manually for AXFR.**
