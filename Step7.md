# SMB Relay Attack Guide

## 🧠 What is an SMB Relay Attack? (one line)

An SMB Relay Attack is when an attacker tricks a victim into authenticating, then forwards (relays) that authentication to another machine to gain access without knowing the password.

**Think:**  
"I didn't crack your password — I reused it while you were sending it."

---

## 🧩 Simple real-life analogy

Imagine this:

* You swipe your office badge at a door
* An attacker stands in between
* He forwards your badge signal to another door
* That door opens — for him, not you

**You never gave him the badge. You just used it at the wrong place.**

That's SMB relay.

---

## 🌐 Visual idea (mental picture)

```
Victim PC  ──NTLM auth──▶  Attacker
                             │
                             │  relays auth
                             ▼
                        Target Server
                       (accepts login)
```

---

## 🔐 What authentication does SMB relay abuse?

SMB relay attacks abuse **NTLM authentication**.

**Important facts:**

* NTLM uses challenge–response
* Password is not sent, but:
* The response can be relayed in real time

⚠️ **NTLM ≠ encrypted session**  
⚠️ **NTLM ≠ tied to one server**

**That's the weakness.**

---

## 🧠 Step-by-step: How SMB Relay works (conceptual)

### Step 1️⃣ Victim tries to authenticate

* Victim PC tries to access:
  * A file share
  * A printer
  * A fake server
* Uses NTLM automatically

**Windows does this silently.**

### Step 2️⃣ Attacker captures the NTLM handshake

* Attacker pretends to be:
  * A file server
  * A printer
  * A network service

**Victim sends NTLM auth to attacker.**

### Step 3️⃣ Attacker relays authentication

* Attacker forwards that NTLM handshake
* Sends it to a real server

### Step 4️⃣ Target server accepts it

If the target:

* Uses NTLM
* Does NOT require SMB signing

👉 **The server accepts the authentication**

### Step 5️⃣ Attacker gains access

* Attacker now:
  * Accesses shares
  * Executes commands
  * Drops malware
  * Moves laterally

💥 **No password cracked**  
💥 **No brute force**  
💥 **Just relayed trust**

---

## 🚨 Why SMB Relay is dangerous

Because:

* Works even with strong passwords
* Works even with hashes
* Happens inside the network
* Users don't notice anything

**This is a lateral movement attack, not initial compromise.**

---

## 🧠 When SMB Relay is possible (conditions)

All of these must be true:

| Condition | Required |
|-----------|----------|
| NTLM enabled | ✅ |
| SMB signing disabled | ✅ |
| Victim authenticates to attacker | ✅ |
| Attacker can reach target | ✅ |

**If any one is missing, relay fails.**

---

## 🛑 What SMB Relay is NOT

❌ Not password cracking  
❌ Not brute force  
❌ Not hash dumping  
❌ Not external internet attack

**It's internal network abuse.**

---

## 🔐 How defenders stop SMB Relay (important)

| Defense | Effect |
|---------|--------|
| Enable SMB signing | ❌ Relay blocked |
| Disable NTLM | ❌ Relay blocked |
| Use Kerberos | ❌ Relay blocked |
| Firewall segmentation | ❌ Relay limited |
| Disable LLMNR/NBT-NS | ❌ Fewer auth leaks |

**SMB signing ON = game over for relay**

---

## 🧠 Exam-level takeaway (MEMORIZE)

**SMB relay works because NTLM authentication is not bound to a specific server and can be forwarded in real time.**

**If you remember only one sentence — remember that.**
