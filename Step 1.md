# Passive Enumeration — Complete Documentation

*Discovering information about a target without actively interacting with or modifying the system.*

## 1. What Is Passive Enumeration?

Passive enumeration refers to gathering information about a target system without directly sending packets or interacting aggressively with the target infrastructure.

You rely on publicly available data, search engines, 3rd-party services, OSINT tools, and cached content.

This phase helps understand:

* Attack surface

* Technologies used

* DNS structure

* Email pattern

* Subdomains

* Network/Cloud footprint

* Human and organizational details

Passive enumeration is safe, stealthy, and often the first step in any penetration test.

## 2. Tools Covered

We will document:
`host`, `Wappalyzer` / `BuiltWith`, `WhatWeb`, `HTTrack`, `WHOIS`, `Netcraft`, `dnsrecon`, `dnsdumpster`, `wafw00f`, `Sublist3r`, `Google Dorks` (GHDB), `theHarvester`.

Each tool documentation includes its purpose, usage, examples, and findings.

## 3. host

**Category:** DNS lookup
**Type:** Passive + semi-active depending on queries

### ✔ Purpose

Retrieve DNS records such as A, AAAA, CNAME, MX, NS, SOA.

### ✔ Usage
 ```c
host example.com
host -t A example.com
host -t MX example.com
host -t NS example.com
host -a example.com # all records
```
### ✔ Example
### ✔ What you learn

* IP address

* Mail infrastructure

* Nameservers

* Subdomains (sometimes)

* DNS misconfigurations

## 4. Wappalyzer / BuiltWith

**Category:** Web technology fingerprinting
**Type:** Passive (browser extension)

### ✔ Purpose

Identify technologies used by a website:

* Server (Apache, nginx, IIS)

* CMS (WordPress, Joomla)

* Frameworks (React, Laravel)

* Analytics

* CDN

* Programming languages

* WAF

### ✔ Tools

* Wappalyzer (browser extension)

* BuiltWith (builtwith.com)

### ✔ What you learn

* Exact tech stack

* Webserver version

* Attack surface vectors

* CMS plugins/themes

* Cloud providers

* Email tech

## 5. WhatWeb

**Category:** Web Fingerprinting
**Type:** Semi-passive

### ✔ Purpose

Identify technologies via HTTP requests.

### ✔ Usage

```c
whatweb http://target.com
whatweb -v http://target.com # verbose
whatweb --aggression 3 http://target.com
```
### ✔ What you learn

* Webserver version

* Frameworks

* CMS

* Cookies

* Redirects

* WAF fingerprints

**Example:**
```
whatweb http://target.ine.local
```
## 6. HTTrack (Website Mirroring)

**Category:** OSINT / Offline Analysis
**Type:** Passive

### ✔ Purpose

Download the entire website to inspect hidden files, comments, offline pages.

### ✔ Usage
```
httrack "http://target.com" -O target_mirror -v
```
### ✔ What you learn

* Hidden/old pages

* Local backups

* Developer comments

* JS files

* Unlinked directories

* Hardcoded secrets

## 7. WHOIS

**Category:** Domain Ownership
**Type:** Passive

### ✔ Purpose

Retrieve domain registration details:

* Registrar

* DNS servers

* Organization

* Email

* Creation/expiry data

### ✔ Usage
```
whois example.com
```
### ✔ What you learn

* Hosting provider

* Contact emails

* Subdomains (sometimes)

* Network blocks

* Ownership

## 8. Netcraft

**Category:** Hosting/Infrastructure Footprint
**Type:** Passive

### ✔ Tool

Use:
<https://sitereport.netcraft.com/>

### ✔ Purpose

* Hosting provider

* IP history

* OS fingerprint

* SSL certificate chain

* DNS history

### ✔ What you learn

* Previous server hosts

* Tech changes over time

* CDN usage

* OS & webserver data

* Historical footprint

## 9. dnsrecon

**Category:** DNS Enumeration
**Type:** Semi-passive (makes DNS queries)

### ✔ Purpose

Gather DNS information including:

* A, AAAA

* MX

* NS

* SOA

* CNAME

* Zone transfers

* Subdomain brute force

### ✔ Usage
```
dnsrecon -d example.com dnsrecon -d example.com -t axfr
```
### ✔ What you learn

* Full DNS footprint

* Zone transfer leaks

* Mail servers

* Subdomains

## 10. dnsdumpster

**Category:** Passive DNS + OSINT
**Type:** Passive (online tool)

### ✔ Tool

<https://dnsdumpster.com/>

### ✔ Purpose

* DNS maps

* Subdomain discovery

* MX, TXT, NS

* Visual topology map

### ✔ What you learn

* Infrastructure layout

* Subdomains

* Cloud assets

* Email servers

## 11. wafw00f

**Category:** WAF Fingerprinting
**Type:** Semi-passive

### ✔ Purpose

Detect if a site is using a Web Application Firewall (WAF).

### ✔ Usage
```
wafw00f http://target.com
wafw00f https://target.com
```
### ✔ What you learn

* Whether WAF exists

* Which WAF (Cloudflare, ModSecurity, Akamai, Sucuri, etc.)

## 12. Sublist3r

**Category:** Subdomain Enumeration
**Type:** Passive + semi-passive

### ✔ Purpose

Enumerate subdomains using:

* Search engines

* Certificate transparency

* OSINT sources

* Passive DNS

### ✔ Usage
```
sublist3r -d example.com
```
### ✔ What you learn

* Subdomains

* Attack surface

* Possible admin panels

* Staging/dev environments

## 13. Google Dorks (GHDB)

**Category:** OSINT / Search Engine Recon
**Type:** Passive

### ✔ Purpose

Use advanced Google queries to find sensitive files.

### ✔ Examples:
```
site:example.com intitle:"index of" inurl:admin filetype:pdf site:example.com site:example.com ext:sql | ext:env | ext:bak
```
<br>

| Operator                          | Meaning                                          | Example                       | What It Does                                                |
| --------------------------------- | ------------------------------------------------ | ----------------------------- | ----------------------------------------------------------- |
| **site:**                         | Limits results to a specific website or domain   | `site:tesla.com`              | Shows only pages from Tesla’s domain                        |
| **inurl:**                        | Search for words inside the URL                  | `inurl:admin`                 | Finds pages with "admin" in the link (e.g., `/admin/login`) |
| **intitle:**                      | Search for words that appear in the page title   | `intitle:"login page"`        | Finds pages with "login page" in the browser tab title      |
| **intext:**                       | Search for words inside the visible page content | `intext:"confidential"`       | Finds pages containing that word in the website body text   |
| **filetype:** or **ext:**         | Search for specific file types                   | `filetype:pdf "confidential"` | Finds PDF files that contain the word "confidential"        |
| **cache:**                        | View Google’s cached version of a site           | `cache:example.com`           | Useful if the site is down or removed                       |
| **link:**                         | Finds pages linking TO a specific URL            | `link:example.com/login`      | Shows sites linking to a target (useful for OSINT)          |
| **related:**                      | Shows similar websites                           | `related:github.com`          | Finds websites similar to GitHub                            |
| **allintitle:**                   | All listed keywords must be in the title         | `allintitle: admin login`     | More strict version of `intitle:`                           |
| **allinurl:**                     | All listed keywords must be in the URL           | `allinurl: admin login`       | Finds URLs containing both keywords                         |
| **OR** (capital letters required) | Search one keyword OR another                    | `"password" OR "passwd"`      | Finds either of the terms, broad search                     |
| **AND**                           | Requires both terms (usually implied)            | `admin AND login`             | Only pages containing both                                  |
| **- (minus)**                     | Exclude words from results                       | `login -wordpress`            | Removes unwanted results                                    |
| **" " (quotes)**                  | Exact phrase search                              | `"admin login page"`          | Finds only that exact sentence/phrase                       |
| `*` (wildcard)                    | Unknown or any word(s)                           | `"password * expired"`        | Matches patterns with variable text                         |

### ✔ What you learn

* Exposed directories

* Leaked credentials

* Open admin panels

* Exposed backups

* Public logs

**Reference:**
<https://www.exploit-db.com/google-hacking-database>

## 14. theHarvester

**Category:** OSINT
**Type:** Passive

### ✔ Purpose

Gather emails, hosts, subdomains from:

* Bing

* DuckDuckGo

* Baidu

* CRT.sh

* VirusTotal

* Github

### ✔ Usage
```
theHarvester -d example.com -b all
```
### ✔ What you learn

* Employee emails

* Subdomains

* IPs

* Public-facing infrastructure

## 15. Summary Table

| Tool | Category | Type | Findings |
 | ----- | ----- | ----- | ----- |
| **host** | DNS | Semi-passive | Records (A, MX, NS), IPs |
| **Wappalyzer** | Web Tech | Passive | CMS, server, frameworks |
| **BuiltWith** | Web Tech | Passive | Tech stack, plugins |
| **WhatWeb** | Fingerprint | Semi-passive | Server version, CMS |
| **HTTrack** | Mirroring | Passive | Hidden pages, old files |
| **WHOIS** | Domain | Passive | Ownership, registrar |
| **Netcraft** | Infra History | Passive | Hosting history, OS |
| **dnsrecon** | DNS | Semi-passive | Subdomains, AXFR |
| **dnsdumpster** | Passive DNS | Passive | Maps, subdomains |
| **wafw00f** | WAF Detection | Semi-passive | WAF type |
| **Sublist3r** | Subdomains | Passive | Subdomain list |
| **Google Dorks** | Search OSINT | Passive | Sensitive leaks |
| **theHarvester** | OSINT | Passive | Emails, IPs, subdomains |
