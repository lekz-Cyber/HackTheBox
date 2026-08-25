# HTB Sherlock: PhantomRing

**Category:** DFIR / Malware Analysis (Sherlock)
**Tools:** VirusTotal, Hybrid Analysis, Ghidra

> **Scenario:** Your organization's SOC team intercepted a suspicious binary during a routine threat hunting operation on a Linux server. The file was found in `/var/tmp` with an unusual name and was attempting to establish outbound connections. Initial analysis suggested this could be a post-exploitation agent. The task: perform static analysis on the binary to identify its capabilities, extract indicators of compromise, and understand the threat actor's infrastructure.

The artifact is a single Linux ELF binary named `agent`.

---

## Task 1 — SHA256 Hash of the Binary
**Q:** What is the SHA256 hash of the malicious binary?

First thing I did was run the binary through VirusTotal — the SHA256 hash is right there on the overview page (MetaDefender shows the same value too).

**A:** `2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5`

## Task 2 — Hardcoded C2 IP Address
**Q:** What is the IP address hardcoded in the binary for C2 communication?

Loaded the sample into Hybrid Analysis and checked the network-related section — there's a hardcoded IP address sitting in there. It shows up in Ghidra's Defined Strings too.

**A:** `192.168.56.1`

## Task 3 — C2 Port
**Q:** What port does the agent connect to on the C2 server?

Back in Ghidra, I searched Defined Strings for `192.168.56.1` and followed the XREFs into the Listing view:

```
s_192.168.56.1_0010551b                      XREF[4]: main:0010421f (*), main:00104226 (*),
                                                       main:0010437e (*), main:00104385 (*)
0010551b  31 39 32 2e 31 36 38 2e 35  ds  "192.168.56.1"

s_socket_00105528                            XREF[2]: main:00104256 (*), main:0010425d (*)
00105528  73 6f 63 6b 65 74 00        ds  "socket"

s_io_uring_wait_cqe:_%s_0010552f             XREF[2]: main:00104305 (*), main:0010430c (*)
0010552f  69 6f 5f 75 72 69 6e 67 5f  ds  "io_uring_wait_cqe: %s\n"

s_connect()_failed:_trying_to_reco_00105548  XREF[2]: main:001043b2 (*), main:001043b9 (*)
00105548  63 6f 6e 6e 65 63 74 28 29  ds  "connect() failed: trying to reconnect\n"

s_[+]_Connected_to_%s:%d_0010556f            XREF[2]: main:00104388 (*), main:0010438f (*)
0010556f  5b 2b 5d 20 43 6f 6e 6e 65  ds  "[+] Connected to %s:%d\n"
```

Following the XREF for the "Connected to" string lands on this in the decompiler:

```c
printf("[+] Connected to %s:%d\n","192.168.56.1",0x115d);
```

`0x115d` converts to decimal `4445`.

**A:** `4445`

## Task 4 — Reconnect Delay
**Q:** How many seconds does the agent wait before attempting to reconnect after a failed connection?

Right below the `connect() failed: trying to reconnect` message in `main`, there's a `sleep(0x78);` call. `0x78` is `120` in decimal — two minutes.

**A:** `120` seconds

## Task 5 — Number of Supported Commands
**Q:** How many different commands does the agent support (excluding invalid commands)?

Searching Defined Strings for the `cmd_` prefix pulls up every command the agent implements.

**A:** `11`

## Task 6 — Kernel Interface Abused for EDR Evasion
**Q:** What Linux kernel interface does this malware abuse to evade EDR syscall monitoring?

Hybrid Analysis flags a long list of syscall-related API references in the sample:

```
Found reference to API "_ITM_deregisterTMCloneTable" (Indicator: "clone")
Found reference to API "_ITM_registerTMCloneTable" (Indicator: "clone")
Found reference to API "io_uring_queue_exit" (Indicator: "exit")
Found reference to API "getpid" (Indicator: "getpid")
Found reference to API "socket" (Indicator: "socket")
Found reference to API "closedir" (Indicator: "close")
Found reference to API "close" (Indicator: "close")
Found reference to API "opendir" (Indicator: "open")
Found reference to API "fwrite" (Indicator: "write")
Found reference to API "readdir" (Indicator: "read")
Found reference to API "readlink" (Indicator: "link")
Found reference to API "readlink" (Indicator: "read")
Found reference to API "readlink" (Indicator: "readlink")
Found reference to API "Error reading /var/run/utmp" (Indicator: "read")
Found reference to API "Error reading /proc/net/tcp" (Indicator: "read")
Found reference to API "Local Address Remote Address State UID" (Indicator: "stat")
Found reference to API "Failed to open %s: %s" (Indicator: "open")
Found reference to API "Failed to open /proc" (Indicator: "open")
Found reference to API "Failed to open /dev/pts: %s" (Indicator: "open")
Found reference to API "Failed to open /proc: %s" (Indicator: "open")
Found reference to API "Killed process %d using %s" (Indicator: "kill")
Found reference to API "Failed to kill process %d: %s" (Indicator: "kill")
Found reference to API "Failed to open /usr/bin" (Indicator: "open")
Found reference to API "Unlink failed: %s" (Indicator: "link")
Found reference to API "Unlink failed: %s" (Indicator: "unlink")
Found reference to API "Agent disconnecting and exiting" (Indicator: "connect")
Found reference to API "Agent disconnecting and exiting" (Indicator: "exit")
Found reference to API "[-] Failed to open /proc: %s" (Indicator: "open")
Found reference to API "[+] Killed PID using BPF: %d" (Indicator: "kill")
```

The one that stood out was near the bottom — killing a process using BPF.

Back in Ghidra, searching Defined Strings for `bpf` turns up a `cmd_killbpf` command and a `killbpf` string. Following `killbpf` leads through `process_cmd` and into the `cmd_killbpf` function itself, which disables kernel tracing and kills BPF PIDs — and does all of its file operations through `io_uring`. `io_uring` also shows up constantly across the rest of Defined Strings, called from a lot of different functions. Between that and `cmd_killbpf`'s behaviour, `io_uring` is the kernel interface being abused to dodge EDR syscall hooks.

**A:** `io_uring`

## Task 7 — Logged-In User Enumeration
**Q:** What file does the agent read to enumerate logged-in users?

Searching `user` in Defined Strings turns up a `Logged users:` string tied to `cmd_users`:

```
s_Logged_users:_00105033        XREF[1]: cmd_users:00101f54 (*)
00105033  4c 6f 67 67 65 64 20 75 73  ds  "Logged users:\n"
```

In `cmd_users`, the first thing that shows up is:

```c
uVar3 = read_file_uring(param_1,"/var/run/utmp",(long)local_4018,0x2000);
```

**A:** `/var/run/utmp`

## Task 8 — SUID Binary Scan Directory
**Q:** What directory does the agent scan when searching for SUID binaries for privilege escalation?

Searching `SUID` in Defined Strings turns up `Potential SUID binaries:`, tied to `cmd_privesc`:

```
s_Potential_SUID_binaries:_001052a1        XREF[1]: cmd_privesc:0010338a (*)
001052a1  50 6f 74 65 6e 74 69 61 6c  ds  "Potential SUID binaries:\n"
```

In `cmd_privesc`:

```c
local_4330 = opendir("/usr/bin");
```

**A:** `/usr/bin`

## Task 9 — eBPF Detection String
**Q:** What string does the agent search for in /proc/[pid]/maps to identify security tools using eBPF?

Searching `proc` in Defined Strings turns up `/proc/%s/maps`, tied to `cmd_killbpf`:

```
s_/proc/%s/maps_00105418        XREF[1]: cmd_killbpf:00103c77 (*)
00105418  2f 70 72 6f 63 2f 25 73 2f  ds  "/proc/%s/maps"
```

Scrolling to the maps section of `cmd_killbpf`:

```c
pcVar5 = strstr(local_4018,"anon_inode:bpf-map");
```

**A:** `anon_inode:bpf-map`

## Task 10 — First Tracing File Disabled
**Q:** What is the full path of the first tracing file the agent attempts to disable?

Still in `cmd_killbpf` — right at the top of the function:

```c
local_6138[0] = "/sys/kernel/debug/tracing/tracing_on";
```

**A:** `/sys/kernel/debug/tracing/tracing_on`

## Task 11 — Self-Location Lookup
**Q:** What procfs path does the agent read to find its own executable location before self-destruction?

Following `main` into `process_cmd` shows all the commands it dispatches, including `cmd_selfdestruct(param_1,param_2);`. Inside `cmd_selfdestruct`:

```c
local_2a8 = readlink("/proc/self/exe",local_218,0x1ff);
```

**A:** `/proc/self/exe`

## Task 12 — Self-Destruct Trigger
**Q:** What command string is compared by the agent to trigger deletion of its own binary?

Back in `process_cmd`, the trigger for `cmd_selfdestruct` is:

```c
iVar1 = strcmp(param_3,"sdestruct");
if (iVar1 == 0) {
  cmd_selfdestruct(param_1,param_2);
}
```

**A:** `sdestruct`
