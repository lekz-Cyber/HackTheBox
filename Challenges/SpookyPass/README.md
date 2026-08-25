# HTB: SpookyPass

**Category:** Reverse Engineering
**Tools:** HxD / DIE, WSL (Ubuntu), Ghidra

A quick one — the password sits in plaintext in the binary's strings, no obfuscation involved, just straight enumeration.

---

## Initial Recon

First, I checked the file in HxD / DIE (Detect It Easy) and confirmed it's an ELF executable for Linux, so I ran `chmod +x pass` in Ubuntu to make it executable.

Running `./pass` prints:

```
Welcome to the SPOOKIEST party of the year.
Before we let you in, you'll need to give us the password:
```

So it's waiting on a password.

## Finding the Password in Ghidra

I imported the binary into Ghidra and searched Defined Strings for `password`, which turned up the prompt string and this right next to it:

```
s_Before_we_let_you_in,_you'll_nee_00102040    XREF[2]: main:001011de (*), main:001011e5 (*)
00102040  42 65 66 6f 72 65 20 77 65  ds  "Before we let you in, you'll need to give us ..."
0010207c  00                          ??  00h
0010207d  00                          ??  00h
0010207e  00                          ??  00h
0010207f  00                          ??  00h

s_s3cr3t_REDACTED_gh0ul_00102080    XREF[2]: main:00101243 (*), main:0010124a (*)
00102080  73 33 63 72 33 74 5f 70 34  ds  "s3cr3t_REDACTED_gh0ul5"
```

That's the password, sitting there in plaintext: `s3cr3t_REDACTED_gh0ul5`.

## Getting the Flag

Entering it into the running binary confirms it and drops the flag:

```
Welcome to the SPOOKIEST party of the year.
Before we let you in, you'll need to give us the password: s3cr3t_REDACTED_gh0ul5
Welcome inside!
HTB{REDACTED}
```

## Flag

```
HTB{REDACTED}
```
