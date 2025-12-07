# Service Enumeration
## Enumeration Cheat Sheet
>A Complete Guide for FTP, SMB, Web, MySQL, SSH & SMTP Enumeration

* FTP Enumeration
* SMB Enumeration
* Webserver Enumeration
* MySQL Enumeration
* SSH Enumeration
* SMTP Enumeration

Includes:

* Manual enumeration
* Automatic enumeration
* Metasploit modules
* Nmap NSE scripts
* Enum4linux, smbclient, hydra, smtp-user-enum, gobuster, curl, nikto
* Extra commands you gave (sendemail, telnet SMTP commands, etc.)
* Organized tables with Tool → Command → Purpose

## FTP Enumeration
**Manual Enumeration**
| Tool     | Command                              | Purpose               |
| -------- | ------------------------------------ | --------------------- |
| `nc`     | `nc target 21`                       | Check banner manually |
| `ftp`    | `ftp target` → `anonymous / <blank>` | Test anonymous login  |
| `telnet` | `telnet target 21`                   | Banner grab           |

**Nmap Enumeration (Auto)**
| Command                                         | Purpose                   |
| ----------------------------------------------- | ------------------------- |
| `nmap -sV -p21 target`                          | FTP version detection     |
| `nmap --script ftp-anon -p21 target`            | Check for anonymous login |
| `nmap --script ftp-syst -p21 target`            | System info               |
| `nmap --script ftp-vsftpd-backdoor -p21 target` | Check vsftpd backdoor     |
| `nmap --script ftp-brute -p21 target`           | Brute force               |

**Hydra Brute-Force**
| Command                                                  | Purpose         |
| -------------------------------------------------------- | --------------- |
| `hydra -L users.txt -P passwords.txt ftp://target -s 21` | FTP brute-force |

**Metasploit Enumeration**
| Command                                 | Purpose              |
| --------------------------------------- | -------------------- |
| `use auxiliary/scanner/ftp/ftp_version` | Version detection    |
| `use auxiliary/scanner/ftp/ftp_login`   | Brute force login    |
| `use auxiliary/scanner/ftp/anonymous`   | Test anonymous login |

---

## SMB Enumeration
**Manual Enumeration**
| Tool                               | Command                    | Purpose |
| ---------------------------------- | -------------------------- | ------- |
| `smbclient -L //target -N`         | List shares (no password)  |         |
| `smbclient //target/share -N`      | Access share anonymously   |         |
| `smbclient //target/share -U user` | Authenticated access       |         |
| `rpcclient -U "" target`           | RID cycling, enum users    |         |
| `enum4linux -a target`             | Full automated enumeration |         |

**Nmap Enumeration**
| Command                                           | Purpose              |
| ------------------------------------------------- | -------------------- |
| `nmap -p139,445 --script smb-os-discovery target` | OS info              |
| `nmap --script smb-enum-users target`             | Enumerate users      |
| `nmap --script smb-enum-shares target`            | List shares          |
| `nmap --script smb-enum-groups target`            | Groups               |
| `nmap --script smb-brute target`                  | Password brute force |
| `nmap --script smb-vuln* target`                  | Vulnerability check  |

**Metasploit Modules**
| Module                                 | Purpose           |
| -------------------------------------- | ----------------- |
| `auxiliary/scanner/smb/smb_version`    | Version detection |
| `auxiliary/scanner/smb/smb_enumshares` | Enumerate shares  |
| `auxiliary/scanner/smb/smb_enumusers`  | Enumerate users   |
| `auxiliary/scanner/smb/smb_login`      | SMB brute-force   |

---
## Web Server Enumeration (HTTP/HTTPS)
**Manual Enumeration**
| Tool                     | Command                              | Purpose |
| ------------------------ | ------------------------------------ | ------- |
| `curl -I target`         | Fetch headers                        |         |
| `curl target/robots.txt` | Check hidden paths                   |         |
| `wget -r target`         | Mirror site                          |         |
| `whatweb target`         | Web fingerprint                      |         |
| `wappalyzer`             | Technology detection (browser addon) |         |

**Gobuster / Dirbuster**
| Command                                       | Purpose               |
| --------------------------------------------- | --------------------- |
| `gobuster dir -u http://target -w common.txt` | Directory brute-force |
| `gobuster vhost -u target -w hosts.txt`       | VHOST enumeration     |

**Nmap Web Scripts**
| Command                                    | Purpose            |
| ------------------------------------------ | ------------------ |
| `nmap -p80,443 --script http-title target` | Page title         |
| `nmap --script http-enum target`           | Common directories |
| `nmap --script http-headers target`        | Header enumeration |

**Vulnerability Scanning**
| Tool                              | Command          |
| --------------------------------- | ---------------- |
| `nikto -h target`                 | Web vuln scanner |
| `nmap --script http-vuln* target` | Web vulns        |

---
## MySQL Enumeration
**Manual**
| Tool                                  | Command              | Purpose |
| ------------------------------------- | -------------------- | ------- |
| `mysql -u root -p -h target`          | Test direct login    |         |
| `mysql -u root --password= -h target` | Check blank password |         |

**Nmap Scripts**
| Command                            | Purpose             |
| ---------------------------------- | ------------------- |
| `nmap -sV -p3306 target`           | Version detection   |
| `nmap --script mysql-info target`  | Server info         |
| `nmap --script mysql-enum target`  | User/db enumeration |
| `nmap --script mysql-brute target` | Brute-force         |

**Metasploit Modules**
| Module                                  | Purpose           |
| --------------------------------------- | ----------------- |
| `auxiliary/scanner/mysql/mysql_login`   | Brute-force       |
| `auxiliary/scanner/mysql/mysql_version` | Version detection |
| `auxiliary/admin/mysql/mysql_sql`       | Run SQL queries   |

---
## SSH Enumeration
**Manual**
| Command              | Purpose       |
| -------------------- | ------------- |
| `ssh user@target`    | Test login    |
| `ssh -v user@target` | Verbose debug |
| `nc target 22`       | Banner check  |

**Nmap Enumeration**
| Command                                                               | Purpose              |
| --------------------------------------------------------------------- | -------------------- |
| `nmap -sV -p22 target`                                                | Version detection    |
| `nmap --script ssh-hostkey target`                                    | Hostkey fingerprint  |
| `nmap --script ssh-auth-methods --script-args="ssh.user=root" target` | Allowed auth methods |

**Brute Force**
| Tool                                               | Command          |
| -------------------------------------------------- | ---------------- |
| `hydra -L users.txt -P passwords.txt ssh://target` | SSH brute-force  |
| `medusa -h target -u root -P passwords.txt -M ssh` | Alternative tool |

**Metasploit Modules**
| Module                                | Purpose           |
| ------------------------------------- | ----------------- |
| `auxiliary/scanner/ssh/ssh_version`   | Version detection |
| `auxiliary/scanner/ssh/ssh_login`     | Brute force       |
| `auxiliary/scanner/ssh/ssh_enumusers` | User enumeration  |

---
## SMTP Enumeration
**Manual Enumeration**

**1. Banner Grab**
```
telnet target 25
HELO attacker.xyz
```
**2. Send Fake Email (Manual)**
```
telnet demo.ine.local 25
HELO attacker.xyz
mail from: admin@attacker.xyz
rcpt to: root@openmailbox.xyz
data
Subject: Hi Root
Hello,
This is a fake mail sent using telnet.
.
quit
```
**3. Send Email via CLI**
```
sendemail -f admin@attacker.xyz -t root@openmailbox.xyz -s demo.ine.local -u Fakemail -m "Hi root, a fake from admin" -o tls=no
```

**Automated Enumeration**
| Command                                     | Purpose                |
| ------------------------------------------- | ---------------------- |
| `smtp-user-enum -U usernames.txt -t target` | VRFY/RCPT TO user enum |

**Nmap SMTP Scripts**
| Command                                   | Purpose                 |
| ----------------------------------------- | ----------------------- |
| `nmap -p25 --script smtp-commands target` | Supported SMTP commands |
| `nmap --script smtp-open-relay target`    | Check open relay        |
| `nmap --script smtp-brute target`         | Brute force             |
| `nmap --script smtp-enum-users target`    | User enum               |

**Metasploit Modules**
| Module                                | Purpose           |
| ------------------------------------- | ----------------- |
| `auxiliary/scanner/smtp/smtp_version` | Version detection |
| `auxiliary/scanner/smtp/smtp_enum`    | User enumeration  |
| `auxiliary/scanner/smtp/smtp_relay`   | Check open relay  |
| `auxiliary/scanner/smtp/smtp_login`   | Brute force       |

---
---

## How SMB Works (Server Message Block)

>SMB = File sharing + Printer sharing + Remote access protocol<br>
>SMB is used mainly on Windows networks but Samba brings SMB to Linux.

**What SMB Actually Does**
SMB allows a client to:
* Access shared folders (`\\SERVER\share`)
* Read/write files remotely
* List directories
* Enumerate users & groups
* Use printers
* Perform remote administration

**SMB Ports**
| Protocol                | Port | Description                                  |
| ----------------------- | ---- | -------------------------------------------- |
| **SMB over NetBIOS**    | 139  | Older, uses NetBIOS session service          |
| **SMB Direct (modern)** | 445  | Direct SMB communication (most common today) |

>Most modern systems use SMBv3 over port 445.

**How SMB Works (Step-by-Step)**
1. Negotiation Phase

   Client → Server:
   “What SMB version do you support?”

    Server → Client:
   “I support SMB2 and SMB3.”

   They agree on a version (SMB2, SMB3).

2. Session Setup (Authentication)

   Client sends:

  * Username
  * Password / NTLM hash
  * Optional domain

   Server checks credentials with:
  * Local SAM database
  * Active Directory (if domain joined)
  * If anonymous login is allowed, the server grants a session without credentials.

3. Tree Connect Phase

   Client connects to a share:
   ```
   \\server\public
   \\server\C$
   \\server\IPC$
   ```
   IPC$ = used for communication, user enumeration, etc.

4. File Operations Phase
   Client performs file operations:
 
   * List directory
   * Upload/download files
   * Execute remote commands (if RPC enabled)
   * Enumerate shares, users, groups
   * This is the phase penetration testers abuse.
  
**Authentication Mechanisms in SMB**
1. NTLMv1/v2

Hash-based authentication. Pentesters steal or brute-force these hashes.

2️. Guest / Null Sessions

Login without a password:
```
smbclient -L //target -N
```
Allows:

Enumerating users
* Enumerating shares
* Enumerating groups
* Very common finding in CTFs.

**Why SMB is Dangerous**
* Misconfigured anonymous shares leak data
* Weak passwords allow brute-force
* SMB signing often disabled → MITM attacks
* Vulnerabilities (EternalBlue, SMBGhost)
* Password reuse for lateral movement

SMB is one of the most critical attack surfaces in a network.

---
## How SMTP Works (Simple Mail Transfer Protocol)
>SMTP is the protocol responsible for sending emails.<br>
It does NOT retrieve emails (that's POP3/IMAP).<br>
SMTP only sends emails between mail servers or by clients.

**SMTP Ports**
| Port    | Protocol   | Purpose                                 |
| ------- | ---------- | --------------------------------------- |
| **25**  | SMTP       | Mail server → mail server (MX delivery) |
| **465** | SMTPS      | Legacy encrypted SMTP                   |
| **587** | Submission | Client → server authentication          |

>Penetration testing usually targets port 25.

**How SMTP Works (Step-by-Step)**

1. SMTP Greeting
  Client connects:
  ```
  220 mailserver.com ESMTP Postfix
  ```
  This is called the banner.

2️. HELO/EHLO Command
  Client identifies itself:
```
HELO attacker.com
EHLO attacker.com
```
>EHLO is modern—it lists supported features (auth, TLS, extensions).

3️. MAIL FROM Command
  Sender address:
```
MAIL FROM: admin@company.com
```
>SMTP allows spoofing because no verification is required unless SPF/DMARC is enforced.

4️. RCPT TO Command
  Recipient address:
```
RCPT TO: root@company.com
```

If the user exists → server responds 250 OK<br>
If not → 550 User Unknown

>This forms the basis for username enumeration.

5️. DATA Command
  Email body is sent:
```
DATA
Subject: test
hello world
.
```
>A single dot on a new line ends the email.

**SMTP in Penetration Testing**
1. Username Enumeration

The attacker abuses `RCPT` or `VRFY` commands:

Example:
```
smtp-user-enum -U names.txt -t target
```
Manual:
```
RCPT TO: alice
550 User unknown
```
>This reveals valid usernames!

2. Open Relay Testing

An open relay allows ANYONE to send mail through the server.
```
nmap --script smtp-open-relay target
```

Or manually:
```
MAIL FROM: attacker@gmail.com
RCPT TO: victim@yahoo.com
```

If accepted → misconfigured.

3. Banner Grabbing

SMTP banners leak:

* Server name
* Version
* OS sometimes
```
nc target 25
nmap -sV -p25 target
```
**Why SMTP Is Dangerous**

* SMTP user enumeration → helps brute-force SSH/SMB/FTP
* Email spoofing → phishing / social engineering
* Open relays → spam abuse
* Misconfigured auth → credential leakage

>SMTP is a very common attack vector for attackers.
---
**SMB vs SMTP (Key Difference Summary)**
| Feature          | SMB                                     | SMTP                                     |
| ---------------- | --------------------------------------- | ---------------------------------------- |
| Purpose          | File sharing                            | Email sending                            |
| Port(s)          | 139, 445                                | 25, 465, 587                             |
| Risk             | Data exposure, RCE, lateral movement    | User enumeration, spoofing               |
| Pentesting Tools | smbclient, enum4linux, metasploit, nmap | smtp-user-enum, telnet, metasploit, nmap |
| Authentication   | NTLM, Guest                             | Optional, often none on port 25          |
