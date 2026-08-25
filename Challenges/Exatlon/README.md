# HTB: Exatlon

**Category:** Reverse Engineering
**Tools:** HxD, WSL (Ubuntu), Ghidra, UPX

A reverse engineering challenge built around a UPX-packed ELF binary. The password check takes the input, shifts each character's value left by 4 bits (multiplying it by 16), and compares the resulting string against a hardcoded value.

---

## Initial Recon

First, I used a hex editor (HxD) to check the file type — turned out to be an ELF executable, so I'd need WSL Ubuntu to run it. I moved the file over to my Ubuntu directory.

```bash
chmod +x exatlon_v1
./exatlon_v1
```

Running it prints a banner and asks for a password:

```
leeky1@leeky:~/Reverse-Engineering$ ./exatlon_v1

███████╗██╗  ██╗ █████╗ ████████╗██╗      ██████╗ ███╗   ██╗       ██╗   ██╗ ██╗
██╔════╝╚██╗██╔╝██╔══██╗╚══██╔══╝██║     ██╔═══██╗████╗  ██║       ██║   ██║███║
█████╗   ╚███╔╝ ███████║   ██║   ██║     ██║   ██║██╔██╗ ██║       ██║   ██║╚██║
██╔══╝   ██╔██╗ ██╔══██║   ██║   ██║     ██║   ██║██║╚██╗██║       ╚██╗ ██╔╝ ██║
███████╗██╔╝ ██╗██║  ██║   ██║   ███████╗╚██████╔╝██║ ╚████║███████╗╚████╔╝  ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═══╝   ╚═╝

[+] Enter Exatlon Password  : 
```

## Static Analysis in Ghidra

### Hitting a Packed Binary

I loaded the binary into Ghidra, ran auto-analysis, and checked the Defined Strings window. The decompiler came back with nothing useful, though. Going back to HxD and cross-checking against Ghidra's defined strings showed why — the binary is packed with UPX.

So I unpacked it:

```bash
upx -d exatlon_v1
```

### Finding the Password Check

With the unpacked binary, I re-imported it into Ghidra and searched Defined Strings for `password` again. This time it turned up something useful:

```
s_[+]_Enter_Exatlon_Password_:_0054b4d0        XREF[1]: main:00404cf0 (*)
0054b4d0  5b 2b 5d 20 45 6e 74 65 72  ds  "[+] Enter Exatlon Password  : "
0054b4ef  00                          ??  00h

s_1152_1344_1056_1968_1728_816_164_0054b4f0    XREF[1]: main:00404d2d (*)
0054b4f0  31 31 35 32 20 31 33 34 34  ds  "1152 1344 1056 1968 1728 816 1648 784 1584 81..."

s_[+]_Looks_Good_^_^_0054b59b                  XREF[1]: main:00404d4e (*)
0054b59b  5b 2b 5d 20 4c 6f 6f 6b 73  ds  "[+] Looks Good ^_^ \n\n\n"
```

In `main`, the important part is:

```c
exatlon(extraout_XMM0_Qa, param_2, param_3, param_4, param_5, param_6, param_7, param_8, local_38, local_58);
bVar1 = std::operator==(local_38,
    "1152 1344 1056 1968 1728 816 1648 784 1584 816 1728 1520 1840 1664 784 1632 1856 1520 1728 816 1632 1856 1520 784 1760 1840 1824 816 1584 1856 784 1776 1760 528 528 2000 "
);
```

So `exatlon()` transforms the input somehow, and the result gets compared against that hardcoded number string. Following `exatlon()` into the decompiler, the key part is:

```c
std::__cxx11::to_string(extraout_XMM0_Qa, param_2, param_3, param_4, param_5, param_6, param_7, param_8, local_48,
    (int)local_21 << 4);
```

`local_21 << 4` is a logical shift left by 4 — i.e. each character's value gets multiplied by 16 — then converted to a string with a trailing space. So the function takes every character of the input, multiplies its ASCII value by 16, and builds up that space-separated number string.

## Cracking the Password

Reversing it is just the opposite operation — take the target number string from `main`, divide every value by 16, and convert each result from decimal to its ASCII character:

```
1152 1344 1056 1968 1728 816 1648 784 1584 816 1728 1520 1840 1664 784 1632 1856 1520 1728 816 1632 1856 1520 784 1760 1840 1824 816 1584 1856 784 1776 1760 528 528 2000

÷ 16

72 84 66 123 108 51 103 49 99 51 108 95 115 104 49 102 116 95 108 51 102 116 95 49 110 115 114 51 99 116 49 111 110 33 33 125

→ ASCII

HTB{REDACTED}
```

Which is the password, and the flag.

## Flag

```
HTB{REDACTED}
```
