# 🧩 Lab Guide: Recon & Flag Capture – Skill Check Lab (INE CTF)

**Goal:** Perform reconnaissance and capture 5 flags hidden around the webroot and mirrored files.

> **⚠️ Legal / Safety Note:** Only run these steps against lab targets you own or have explicit permission to test (like `target.ine.local`, `zonetransfer.me`, etc.). Do not run intrusive scans against systems you don't own.

---

## 📋 Prerequisites
Ensure you have the following installed in your Kali VM:
* **Tools:** `Nmap`, `FTP client`, `MySQL client`, `gobuster`.
* **Browser:** Firefox or Chrome (for viewing directory listings).
* **Access:** Terminal with root/sudo permissions.

---
## Objectives & Flags

| Flag #     | Hint                                                                    |
| ---------- | ----------------------------------------------------------------------- |
| **Flag 1** | The server proudly announces its identity.                              |
| **Flag 2** | Check what the gatekeeper wants hidden—read between the lines.          |
| **Flag 3** | Anonymous access might reveal forgotten treasures.                      |
| **Flag 4** | A well-named database reveals secrets if you look at its configuration. |

### Flag 1 — Server Announces Its Identity
Why?

Many web servers include their server banner in HTTP responses.
This banner often includes the web server type + version, and in this CTF, it contains the first flag.

We get a /secret-info inside /robots.txt
> Hmm, what could be inside???

Yep....Flag1 it is

### Flag 2 — Gatekeeper Instructions (robots.txt)
Why?

robots.txt tells search engines which areas of a site to avoid.
Sometimes admins hide sensitive paths in it.
In this lab, the flag is hidden in that exact file.
> We were just over here when we found Flag1 what more could've been there????
> Let's try gobuster, afterall why not??
```
gobuster dir -u target.ine.local/secret-info -w /usr/share/wordlists/dirb/common.txt
```
hmm we got something interesting let's try this then
```
curl http://target.ine.local/secret-info/flag.txt
```

### Flag 3 — Anonymous FTP Treasure Hunt

Why?
Misconfigured FTP servers often allow `anonymous` login, exposing secrets.

Steps

**1. Check if FTP is open with Nmap:**
```bash
nmap -sV target.ine.local
```
Look for:
```bash
21/tcp open ftp
```
**2. Attempt anonymous login:**
```
ftp target.ine.local
```
* Name: `anonymous`

* Password: <press enter>

seems to work fine, now let's do this
```bash
ls
get flag.txt
get credentials.txt
```
### Flag 4 — MySQL Configuration Secrets

Why?
<br>The description hints:
> “A well-named database can be quite revealing. Peek at the configurations...”

This means:
1.  MySQL is running.
2.  The database name itself or table content includes the flag.
3.  Credentials might be defaults or leaked.

Steps

**Step 1 — Scan for MySQL**
```bash
nmap -sV target.ine.local
```
we get 
```bash
3306/tcp open mysql
```
from the credentials list we get the username and password
```bash
mysql -h target.ine.local -u <username> -p
```
enter the password
```bash
SHOW DATABASES;
```
and we get the flag4 too
