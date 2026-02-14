# Penetration Testing Lab - Cold Start Summary

## Context

The conversation documents a full penetration testing workflow within a controlled lab environment (likely INE/eJPT-style). The user systematically attacked multiple Windows servers (WINSERVER-01 and WINSERVER-03) and pivoted into an internal Linux network. Activities included SMB enumeration, credential brute forcing with Hydra, privilege escalation, hash dumping and cracking, RDP access, internal pivoting via Meterpreter autoroute, and service identification. The final phase involved identifying a vulnerable internal web application and extracting flags from compromised systems.

---

## User Goals and Reasoning

From the beginning, the user demonstrated a goal-oriented, verification-driven mindset. They repeatedly avoided guessing and explicitly requested proper enumeration methods ("no guess work"). Their objectives evolved logically:

### 1. Initial Access & Enumeration

* Began with SMB brute force:

```bash
hydra -l admin -P rockyou.txt smb://192.168.100.50
→ login: admin  password: superman
```

* Confirmed group membership using:

```bash
net localgroup administrators
→ admin
  Administrator
```

* Explicitly validated administrator membership rather than assuming based on naming.

---

### 2. Privilege Escalation & Credential Extraction

* Gained Meterpreter via:

```bash
use exploit/windows/smb/psexec
set SMBUser admin
set SMBPass superman
```

* Dumped hashes:

```
lawrence:1009:...:18aa104784f77431563b1a1b67f6096c:::
```

* Cracked with:

```bash
hashcat -m 1000 lawrence_hash.txt rockyou.txt
```

* Demonstrated understanding of NTLM hash mode (1000).

---

### 3. Lateral Movement & RDP

* Verified RDP brute force success:

```bash
hydra -l admin -P rockyou.txt rdp://192.168.100.50
→ login: admin password: superman
```

* Distinguished between "exploitation" and credential reuse.

---

### 4. Internal Pivot & Web App Identification

* Identified dual NICs:

```
192.168.100.55
192.168.0.50
```

* Pivoted using autoroute.
* Scanned internal subnet:

```
192.168.0.51:10000 - TCP OPEN
```

* Correctly inferred: Port 10000 → Webmin

Throughout the session, the user refined commands, corrected Hydra flags (`-l` vs `-u`, `-P` vs `-p`), and insisted on proper proof-based enumeration.

---

## Key Progress and Decisions

✅ Successfully brute-forced SMB and RDP credentials  
✅ Identified `admin` as a member of local administrators group on WINSERVER-03  
✅ Dumped and cracked NTLM hash for `lawrence`  
✅ Retrieved flags from compromised systems  
✅ Pivoted into internal 192.168.0.0/24 network  
✅ Identified vulnerable internal web app as Webmin (port 10000)  
✅ Demonstrated full attack chain: **Recon → Credential Access → Privilege Escalation → Lateral Movement → Internal Discovery**

---

## Open Threads and Next Actions

🔄 Exploit Webmin on 192.168.0.51 (likely vulnerable version)  
🔄 Determine exact Webmin version via HTTP banner  
🔄 Identify applicable CVE (common: CVE-2019-15107)  
🔄 Gain shell access to internal Linux host  
🔄 Perform privilege escalation on Linux host  
🔄 Extract final internal flags
