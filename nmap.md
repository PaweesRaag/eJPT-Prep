# Nmap 

## Step 1: Host Discovery

| Nmap Flag              | Expanded Form            | Packet Sent                                                  | Bits Set                | Expected Response                                    | Purpose                                  |
| ---------------------- | ------------------------ | ------------------------------------------------------------ | ----------------------- | ---------------------------------------------------- | ---------------------------------------- |
| **-PE**                | ICMP Echo Request        | ICMP Type 8                                                  | N/A (ICMP—no TCP flags) | ICMP Echo Reply (Type 0)                             | Normal ping; blocked often               |
| **-PP**                | ICMP Timestamp Ping      | ICMP Type 13                                                 | N/A                     | Type 14 Timestamp Reply                              | Stealthier than -PE                      |
| **-PM**                | ICMP Netmask Ping        | ICMP Type 17                                                 | N/A                     | Type 18 Netmask Reply                                | Rare; old routers respond                |
| **-PS**                | TCP SYN Ping             | TCP SYN packet                                               | **SYN = 1**             | SYN/ACK (open) or RST (closed) = *host is up*        | Best bypass for ICMP blocks              |
| **-PS22,80,443**       | SYN Ping to chosen ports | TCP SYN                                                      | **SYN = 1**             | SYN/ACK or RST                                       | Blend into normal traffic                |
| **-PA**                | TCP ACK Ping             | TCP ACK packet                                               | **ACK = 1**             | RST = host alive                                     | Firewall mapping                         |
| **-PA80,443**          | ACK to specific ports    | TCP ACK                                                      | **ACK = 1**             | RST                                                  | Used to probe filtered hosts             |
| **-PU**                | UDP Ping                 | Empty UDP packet                                             | N/A                     | ICMP Port Unreachable (Type 3 Code 3) OR NO RESPONSE | Good for DNS/SNMP discovery              |
| **-PU53,161**          | UDP Ping to common ports | UDP empty payload                                            | N/A                     | ICMP errors                                          | DNS/SNMP often respond                   |
| **--arp-scan**         | ARP Ping                 | ARP request                                                  | N/A (L2 frame)          | ARP reply                                            | Fastest on LAN                           |
| **-sn**                | Ping scan / No port scan | Sends host-discovery probes (ICMP + ARP + SYN/ACK depending) | Depends                 | Host Up/Down                                         | Quick live-host scan                     |
| **-Pn**                | Treat host as online     | **No packets for discovery**                                 | N/A                     | Always proceed                                       | Forces scanning even if ICMP/TCP dropped |
| **--disable-arp-ping** | Disable ARP discovery    | Remove ARP frames                                            | N/A                     | —                                                    | Rare use; reduces accuracy on LAN        |
| **--traceroute**       | Path discovery           | Incremental TTL packets                                      | N/A                     | Time Exceeded                                        | Host path mapping                        |

### Detailed Explanation of Each Discovery Method

**1️⃣ -PE (ICMP Echo Request)**

Packet:
```
ICMP Type 8 (Echo Request)
```

Bits: ❌ No TCP flags

Response:
```
ICMP Echo Reply (Type 0)
```

> ✔ Works on LANs

> ❌ Blocked by firewalls on internet

> ✔ Most basic discovery

**2️⃣ -PP (ICMP Timestamp Request)**

Packet:
```
Type 13 (Timestamp)
```

Response:
```
Type 14 (Timestamp Reply)
```

>✔ Less filtered

>✔ Bypasses some ICMP filters

>❌ Not widely supported

**3️⃣ -PM (ICMP Netmask Request)**

Packet:
```
Type 17 (Netmask Request)
```

Response:
```
Type 18 (Netmask Reply)
```

>Rare now but useful for legacy networks.

**4️⃣ -PS (TCP SYN Ping)**

Packet:
```
TCP: SYN=1 ACK=0
```

Bits:

 * SYN bit set

 * Standard initial handshake packet

Response:

 * SYN/ACK → Open

 * RST → Closed

**Both mean: HOST IS UP**

**Best for bypassing ICMP-blocked hosts.**

**5️⃣ -PA (TCP ACK Ping)**

Packet:
```
TCP: ACK=1
```

Bits:

  * ACK bit set

Response:

  * RST → Host is up
   Used for:

  * Firewall detection

  * Stealth mapping

**6️⃣ -PU (UDP Ping)**

Packet:
```
UDP empty payload
```

Response:

 * ICMP Type 3 Code 3 (Port Unreachable) → Host up

 * Silence → Host unknown

Used for:

 * DNS (-PU53)

 * SNMP (-PU161)

**7️⃣ --arp-scan**

Packet:
```
Layer 2 – ARP request
```

Response:
```
ARP reply
```

✔ 100% reliable on LAN
✔ Much faster than ICMP/SYN

**8️⃣ -sn (Host Discovery only)**

Sends:

 * ICMP

 * ARP (LAN)

 * TCP SYN/ACK probes

 * Does not perform port scan.

9️⃣ -Pn (Skip Host Discovery)

Sends:
```
Nothing for discovery
```

Immediately begins port scan.

Used when:

 * Firewall drops ICMP

 * Firewall drops SYN/ACK

 * Host appears “down” but is actually alive

### BEST COMBINED HOST DISCOVERY COMMANDS
**Stealth bypass**
```
nmap -sn -PS22,80,443 10.10.10.0/24
```
**Firewall bypass**
```
nmap -sn -PA80,443 10.10.10.0/24
```
**UDP service discovery**
```
nmap -sn -PU53,161 <target>
```
**LAN scan**
```
sudo nmap -sn --arp-scan 192.168.1.0/24
```
**If everything is blocked**
```
nmap -Pn -sS <target>
```
---
## Step 2: Port Scanning

| Scan Type              | Flag                 | Packet Sent                           | TCP/UDP Bits        | Host Response                         | Port State Interpretation | Notes                                      |
| ---------------------- | -------------------- | ------------------------------------- | ------------------- | ------------------------------------- | ------------------------- | ------------------------------------------ |
| **TCP SYN Scan**       | `-sS`                | SYN packet                            | SYN=1               | SYN/ACK → RST from Nmap               | **open**                  | Fast, stealthy, most commonly used         |
|                        |                      |                                       |                     | RST                                   | **closed**                |                                            |
|                        |                      |                                       |                     | no response / ICMP filter             | **filtered**              |                                            |
| **TCP Connect Scan**   | `-sT`                | Full TCP handshake                    | SYN=1, SYN/ACK, ACK | 3-way handshake succeeds              | **open**                  | No raw sockets needed; noisy               |
| **TCP ACK Scan**       | `-sA`                | ACK packet                            | ACK=1               | RST                                   | **unfiltered**            | Firewall mapping                           |
|                        |                      |                                       |                     | no response                           | **filtered**              |                                            |
| **TCP FIN Scan**       | `-sF`                | FIN packet                            | FIN=1               | no response                           | **open|filtered**         | RFC-based stealth; bypasses some firewalls |
|                        |                      |                                       |                     | RST                                   | **closed**                |                                            |
| **TCP XMAS Scan**      | `-sX`                | FIN+PSH+URG                           | FIN=1 PSH=1 URG=1   | no response                           | **open|filtered**         | Lights up IDS signatures                   |
|                        |                      |                                       |                     | RST                                   | **closed**                |                                            |
| **TCP NULL Scan**      | `-sN`                | 0-flag packet                         | (no flags set)      | no response                           | **open|filtered**         | Silent probe                               |
|                        |                      |                                       |                     | RST                                   | **closed**                |                                            |
| **TCP MAIMON Scan**    | `-sM`                | FIN/ACK                               | FIN=1 ACK=1         | no response                           | **open|filtered**         | Exploits BSD stack bug                     |
| **UDP Scan**           | `-sU`                | UDP empty or protocol-specific packet | UDP                 | ICMP Port Unreachable (Type 3 Code 3) | **closed**                | UDP is slow, noisy                         |
|                        |                      |                                       |                     | no response                           | **open|filtered**         |                                            |
|                        |                      |                                       |                     | UDP reply                             | **open**                  |                                            |
| **TCP Window Scan**    | `-sW`                | ACK packet                            | ACK=1               | RST (with window size > 0)            | **open** on some stacks   | Obscure; rarely used                       |
|                        |                      |                                       |                     | RST + window = 0                      | **closed**                |                                            |
| **TCP Custom Flags**   | `--scanflags <bits>` | Custom TCP packet                     | Defined by user     | Varies                                | Varies                    | IDS/Firewall evasion                       |
| **Idle Scan (Zombie)** | `-sI`                | SYN packets via zombie                | SYN=1               | Zombie IPID changes                   | **open**                  | Fully stealth (your IP never shows)        |

### Detailed Explanation of All Port Scan Types

**1️⃣ -sS (TCP SYN Scan)**

Packet:
```
SYN
```
Response:
* SYN/ACK → Nmap sends RST → **Open**
* RST → **Closed**
* No reply / ICMP → **Filtered**

>  Best general scan
>  Fast + Stealthy + Accurate

**2️⃣ -sT (TCP Connect Scan)**

Packet:
```
SYN → SYN/ACK → ACK → Close
```
Bits: Performs full 3-way handshake.

>  Works without root/admin privileges
>  Very noisy (appears in logs)

**3️⃣ -sA (TCP ACK Scan)**

Packet:
```
ACK
```
Bits: Used ONLY to map firewall rules.

Response:
* RST → **Unfiltered** (packet reached target)
* No response → **Filtered**

> ❌ Does NOT show open/closed ports.

**4️⃣ -sF (TCP FIN Scan)**

Packet:
```
FIN
```
Bits: Based on RFC 793 behavior.

Response:
* No response → **Open | Filtered**
* RST → **Closed**

> ✔ Stealth (bypasses some firewalls)
> ❌ Not reliable on Windows stacks

**5️⃣ -sN (TCP NULL Scan)**

Packet:
```
(No flags set)
```
Bits: RFC violation → some systems ignore.

Response:
* No response → **Open | Filtered**
* RST → **Closed**

**6️⃣ -sX (TCP Xmas Scan)**

Packet:
```
FIN + PSH + URG
```
Bits: Lights up IDS logs (“Christmas Tree attack”).

Response:
* Behavior same as FIN/NULL.

**7️⃣ -sM (TCP MAIMON Scan)**

Packet:
```
FIN + ACK
```
Bits: Old BSD systems respond differently.

Response:
* Used to identify open ports on legacy systems.

> Rare today.

**8️⃣ -sU (UDP Scan)**

Packet:
```
UDP <empty> or protocol-specific probes
```
Response:
* ICMP Port Unreachable (3/3) → **Closed**
* No response → **Open | Filtered**
* UDP reply → **Open**

>  Needed for DNS, SNMP, SIP, NTP
>  Slow due to ICMP rate limiting

**9️⃣ -sW (TCP Window Scan)**

Packet:
```
ACK
```
Bits: Look at TCP window size in RST reply.

Response:
* Window > 0 → **Open**
* Window = 0 → **Closed**

> Very stack-specific.

**🔟 -sI <zombie> (Idle Scan)**

Packet:
```
Uses IPID side-channel to hide identity
```
Bits: Your machine never touches the target.

> ⭐ Most stealth method
> ⭐ Great for red teaming
> ❌ Hard to find a suitable zombie
---
## Nmap Port Scan Comparison Table (Open vs Closed vs Filtered)

| Scan Type           | Open        | Closed    | Filtered        |
| ------------------- | ----------- | --------- | --------------- |
| **SYN (`-sS`)**     | SYN/ACK     | RST       | no reply / ICMP |
| **CONNECT (`-sT`)** | handshake   | RST       | no reply        |
| **UDP (`-sU`)**     | UDP reply   | ICMP 3/3  | silence         |
| **FIN (`-sF`)**     | silence     | RST       | ICMP errors     |
| **NULL (`-sN`)**    | silence     | RST       | ICMP errors     |
| **XMAS (`-sX`)**    | silence     | RST       | ICMP errors     |
| **ACK (`-sA`)**     | N/A         | RST       | silence         |
| **Idle (`-sI`)**    | IPID change | unchanged | unchanged       |

## Red Team Notes
| Goal             | Recommended Scan                  |
| ---------------- | --------------------------------- |
| Stealth          | `-sS`, `-sN`, `-sF`, `-sX`, `-sI` |
| Firewall evasion | `-sA`, `-sS -f`, `--scanflags`    |
| Accuracy         | `-sS -sV -p-`                     |
| UDP discovery    | `-sU --top-ports 50`              |
| Full enumeration | `-sS -sU -A -p-`                  |
---
## NMAP FIREWALL EVASION & STEALTH MASTER TABLE

### LEGEND
| Feature           | Description                                     |
| ----------------- | ----------------------------------------------- |
| **Forged IP**     | Makes traffic appear from different IPs         |
| **Forged Port**   | Makes traffic appear from known/allowed ports   |
| **Fragmentation** | Splits packets to evade IDS                     |
| **Data stuffing** | Adds random bytes to change signature           |
| **MAC spoofing**  | Changes OSI Layer 2 identity                    |
| **Timing**        | Controls how fast or stealthily probes are sent |

### COMPLETE EVASION TABLE
| Nmap Option                            | What It Does                                 | Packet Details                      | Bits/Headers Modified     | Purpose / Effect                             |
| -------------------------------------- | -------------------------------------------- | ----------------------------------- | ------------------------- | -------------------------------------------- |
| **-D RND:<n>**                         | Decoy IP addresses                           | Sends probes from many spoofed IPs  | Source IP randomized      | Hides your real IP among decoys              |
| **-D <ip1>,<ip2>,ME**                  | Manual decoy list                            | Multiple forged source IPs          | Source IP cycles          | Makes attribution nearly impossible          |
| **-S <fake-ip>**                       | Spoof source IP                              | Raw packet crafted                  | Source IP = fake          | True IP spoofing (breaks TCP handshake)      |
| **-g <src-port>** or **--source-port** | Fake source port                             | Forge TCP/UDP src port              | Source port = 53, 80, 443 | Evade filtering by pretending to be DNS/HTTP |
| **-f**                                 | Fragment packets                             | Splits into 8-byte chunks           | Small IP fragments        | Evades simple packet filters/IDS             |
| **--mtu <size>**                       | Set custom MTU for fragmentation             | Packets = MTU-sized                 | Overrides DF bit          | Evade fragmentation detection                |
| **--data-length <n>**                  | Add random data to packets                   | Appends n bytes                     | Payload inflated          | Breaks IDS signatures / obfuscation          |
| **--badsum**                           | Sends incorrect checksums                    | TCP/UDP checksum corrupted          | Bad checksum              | Firewalls sometimes still log/open replies   |
| **--randomize-hosts**                  | Random target ordering                       | Reorders scan targets               | N/A                       | Avoids sequential scan detection             |
| **--spoof-mac <vendor>**               | MAC address spoofing                         | L2 frame modified                   | MAC = fake                | Evade layer-2 detection, VLAN ACLs           |
| **--ttl <n>**                          | Modify Time-To-Live                          | TTL field rewritten                 | TTL=X                     | Manipulate routing / fingerprinting          |
| **--ip-options <opts>**                | Custom IP options                            | Adds LSRR/SSRR                      | IP header extended        | Rare; bypass strict routing                  |
| **--send-eth**                         | Force Ethernet layer sending                 | Raw ethernet                        | L2 direct                 | Useful for LAN stealth / bypass kernel       |
| **--bypass-firewall**                  | Legacy, rarely used                          | Mixed evasion                       | N/A                       | Not reliable, avoid                          |
| **--defeat-rst-ratelimit**             | Adjust timing to avoid Linux RST rate limits | Timing change                       | RST pacing                | Avoids misleading port-closed results        |
| **-T0 / -T1**                          | Slow, sneaky timing                          | VERY slow packets                   | Timing profile            | Evades rate-based firewalls                  |
| **--dns-servers <ip>**                 | Use alternative DNS                          | DNS resolution via specified server | DNS header                | Bypass DNS filtering/rebind attacks          |
| **-sI <zombie>**                       | Idle scan (fully spoofed)                    | Uses IPID side-channel              | True spoof                | 100% stealth — target never sees your IP     |

### ADVANCED PACKET DETAILS TABLE
| Feature                            | Affected Layer | Field Modified  | Range / Example    | Impact                                   |
| ---------------------------------- | -------------- | --------------- | ------------------ | ---------------------------------------- |
| **Fake IP (-S)**                   | L3 (IP)        | Source IP       | 1.2.3.4            | True spoofing; no reply unless idle scan |
| **Decoys (-D)**                    | L3             | Source IP       | multiple           | Your true IP buried among others         |
| **Fake Source Port (-g)**          | L4             | Source Port     | 53/80/443 common   | Evade port-based ACLs                    |
| **Fragmentation (-f)**             | L3             | Fragment offset | 8-byte blocks      | Evade deep-packet inspection             |
| **MTU (--mtu)**                    | L3             | Packet length   | e.g., 16, 24, 32   | Precision fragmentation                  |
| **Data stuffing (--data-length)**  | L4             | Payload size    | append 200 bytes   | Change signature fingerprint             |
| **Checksum corruption (--badsum)** | L4             | Checksum        | Incorrect          | Used to probe firewall behavior          |
| **MAC spoofing (--spoof-mac)**     | L2             | Source MAC      | e.g., Apple, Cisco | Evade L2 logs/filters                    |
| **Idle Scan (-sI)**                | L3             | Zombie IPID     | side-channel       | Fully stealth, ultimate evasion          |
| **TTL (--ttl)**                    | L3             | TTL field       | 2–255              | Router path manipulation                 |

### Common Red-Team Evasion Combos

**1. Full stealth scan with decoys + fragmentation**
```bash
nmap -sS -p- -f -D RND:10 target
```
**2. Spoofed-port scan (pretend to be DNS)**
```
nmap -sS --source-port 53 -p80,443 target
```
**3. Spoofed IP + data stuffing**
```
nmap -sS -S 8.8.8.8 --data-length 200 target
```
**4. Idle scan (100% anonymous)**
```
nmap -sI <zombie-ip> -p80 target
```
**5. Full obfuscation + slow**
```
nmap -sS -T1 -f --data-length 150 --spoof-mac Cisco target
```
**6. Evasion for WAF/IPS heavy environments**
```
nmap -sS -p- --mtu 24 -D 192.168.1.10,ME,192.168.1.1 target
```
---
## NSE
### Where NSE scripts are located
### Default path (Linux / Kali / Parrot / Ubuntu):
```
/usr/share/nmap/scripts/
```
**To view all scripts:**
```
ls -1 /usr/share/nmap/scripts/
```
### How to search for specific scripts
**Search scripts by name:**
```
ls -1 /usr/share/nmap/scripts/ | grep -i <script>
```
### How to run NSE scripts
**Run a single script**
```
nmap --script=<script-name> <target>
```
**Run multiple scripts**
```
nmap --script=http-title,http-headers <target>
```
**Run scripts by category**
```
nmap --script=vuln <target>
```
**Categories include:**
 * vuln
 * auth
 * default
 * discovery
 * safe
 * exploit
 * brute
 * malware
 * dos
 * intrusive

**Run all default scripts (recommended)**
```
nmap -sC <target>
```
**Equivalent to:**
```
nmap --script=default <target>
```
**Run scripts with arguments**
```
nmap --script=http-sql-injection --script-args=http-sql-injection.path=/login <target>
```
**Combine with service detection**
```
nmap -sV --script=vuln <target>
```
**Combine with full scan**
```
nmap -sC -sV -p- <target>
```
### How NSE scripts are structured
 * description
 * categories
 * portrule
 * hostrule
 * action()

You can open any script to study it:
```
nano /usr/share/nmap/scripts/smb-os-discovery.nse
```
**To Find more about the scripts**
```c
nmap --script-help=snmp-brute.nse              
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 07:32 EST

snmp-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/snmp-brute.html
  Attempts to find an SNMP community string by brute force guessing.

  This script opens a sending socket and a sniffing pcap socket in parallel
  threads. The sending socket sends the SNMP probes with the community strings,
  while the pcap socket sniffs the network for an answer to the probes. If
  valid community strings are found, they are added to the creds database and
  reported in the output.

  The script takes the <code>snmp-brute.communitiesdb</code> argument that
  allows the user to define the file that contains the community strings to
  be used. If not defined, the default wordlist used to bruteforce the SNMP
  community strings is <code>nselib/data/snmpcommunities.lst</code>. In case
  this wordlist does not exist, the script falls back to
  <code>nselib/data/passwords.lst</code>

  No output is reported if no valid account is found.
```
