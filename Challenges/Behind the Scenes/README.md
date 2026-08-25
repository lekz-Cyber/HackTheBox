# HTB: Behind the Scenes

**Category:** Reverse Engineering
**Tools:** HxD, WSL (Ubuntu), Ghidra

A short reverse engineering challenge built around an ELF binary that uses a `UD2` instruction paired with a custom `sigaction` signal handler as an anti-decompilation trick.

---

## Initial Recon

First, I used a hex editor (HxD) to check the file type — turned out to be an ELF executable, so I'd need WSL Ubuntu to actually run it. I moved the file over to my Ubuntu directory.

```bash
chmod +x behindthescenes
./behindthescenes
```

Running it with no arguments just printed usage info:

```
./challenge <password>
```

So the binary expects a password as an argument.

## Static Analysis in Ghidra

I loaded the binary into Ghidra and checked the decompiler view for `main`, but it came back empty — nothing useful to look at.

So I switched to the Listing view and looked at where `main` actually gets called. Right after the call to `sigaction`, there's a `UD2` instruction — this deliberately triggers an invalid opcode exception, which is a common anti-decompilation trick (a lot of tools stop analysing, or hide code, right after something like this). By forcing Ghidra to decompile the bytes underneath it anyway, most of the real logic showed up:

```asm
LAB_0010130b:                                  ; XREF[1]: 001012ef (j)
0010130b  0f 0b                 UD2
0010130d  48 8b 85 50 ff ff ff  MOV   RAX, qword ptr [RBP + -0xb0]
00101314  48 83 c0 08           ADD   RAX, 0x8
00101318  48 8b 00              MOV   RAX, qword ptr [RAX]
0010131b  48 89 c7              MOV   RDI, RAX
0010131e  e8 cd fd ff ff        CALL  <EXTERNAL>::strlen        ; size_t strlen(char *__s)
00101323  48 83 f8 0c           CMP   RAX, 0xc
00101327  0f 85 05 01 00 00     JNZ   LAB_00101432
```

The `strlen` check means the password has to be exactly `0xc` (12) characters, or execution jumps straight to the fail path.

### Cracking the Password Checks

Following the `RSI` loads from there shows a chain of four `strncmp` calls, each one checking 3 characters against a hardcoded string, with another `UD2` bouncing past the anti-decompilation trap after every successful match:

```asm
00101342  48 8d 35 d2 0c 00 00  LEA   RSI, [DAT_0010201b]      ; = 49h  I
00101349  48 89 c7              MOV   RDI, RAX
0010134c  e8 6f fd ff ff        CALL  <EXTERNAL>::strncmp      ; int strncmp(char *__s1, char *__s2, size_t __n)
00101351  85 c0                 TEST  EAX, EAX
00101353  0f 85 d0 00 00 00     JNZ   LAB_00101429
00101359  0f 0b                 UD2
0010135b  48 8b 85 50 ff ff ff  MOV   RAX, qword ptr [RBP + -0xb0]
00101362  48 83 c0 08           ADD   RAX, 0x8
00101366  48 8b 00              MOV   RAX, qword ptr [RAX]
00101369  48 83 c0 03           ADD   RAX, 0x3
0010136d  ba 03 00 00           MOV   EDX, 0x3
00101372  48 8d 35 a6 0c 00 00  LEA   RSI, [DAT_0010201f]      ; = 5Fh  _
00101379  48 89 c7              MOV   RDI, RAX
0010137c  e8 3f fd ff ff        CALL  <EXTERNAL>::strncmp
00101381  85 c0                 TEST  EAX, EAX
00101383  0f 85 97 00 00 00     JNZ   LAB_00101420
00101389  0f 0b                 UD2
0010138b  48 8b 85 50 ff ff ff  MOV   RAX, qword ptr [RBP + -0xb0]
00101392  48 83 c0 08           ADD   RAX, 0x8
00101396  48 8b 00              MOV   RAX, qword ptr [RAX]
00101399  48 83 c0 06           ADD   RAX, 0x6
0010139d  ba 03 00 00           MOV   EDX, 0x3
001013a2  48 8d 35 7a 0c 00 00  LEA   RSI, [DAT_00102023]      ; = 4Ch  L
001013a9  48 89 c7              MOV   RDI, RAX
001013ac  e8 0f fd ff ff        CALL  <EXTERNAL>::strncmp
001013b1  85 c0                 TEST  EAX, EAX
001013b3  75 62                 JNZ   LAB_00101417
001013b5  0f 0b                 UD2
001013b7  48 8b 85 50 ff ff ff  MOV   RAX, qword ptr [RBP + -0xb0]
001013be  48 83 c0 08           ADD   RAX, 0x8
001013c2  48 8b 00              MOV   RAX, qword ptr [RAX]
001013c5  48 83 c0 09           ADD   RAX, 0x9
001013c9  ba 03 00 00           MOV   EDX, 0x3
001013ce  48 8d 35 52 0c 00 00  LEA   RSI, [DAT_00102027]      ; = 55h  U
001013d5  48 89 c7              MOV   RDI, RAX
001013d8  e8 e3 fc ff ff        CALL  <EXTERNAL>::strncmp
001013dd  85 c0                 TEST  EAX, EAX
001013df  75 2d                 JNZ   LAB_0010140e
001013e1  0f 0b                 UD2
001013e3  48 8b 85 50 ff ff ff  MOV   RAX, qword ptr [RBP + -0xb0]
001013ea  48 83 c0 08           ADD   RAX, 0x8
001013ee  48 8b 00              MOV   RAX, qword ptr [RAX]
001013f1  48 89 c6              MOV   RSI, RAX
001013f4  48 8d 3d 30 0c 00 00  LEA   RDI, [s_>_HTB{%s}_0010202b]  ; = "> HTB{%s}\n"
001013fb  b8 00 00 00 00        MOV   EAX, 0x0
00101400  e8 0b fd ff ff        CALL  <EXTERNAL>::printf      ; int printf(char *__format, ...)
```

Decompiling each of these individually (pushing past the `UD2` every time) makes the logic obvious. For example, `RSI, [DAT_0010201b]` decompiles to:

```c
void UndefinedFunction_00101330(void)
{
  code *pcVar1;
  int iVar2;
  long unaff_RBP;

  iVar2 = strncmp(*(char **)((ulong)*(uint *)(unaff_RBP + -0xb0) + 8), "Itz", 3);
  if (iVar2 == 0) {
    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}
```

Repeating that for each of the four checks gives four 3-character chunks — concatenated: `Itz` + `_0n` + `Ly_` + `UD2` = `Itz_0nLy_UD2`.

And the final `printf` call confirms the flag format:

```c
void UndefinedFunction_001013e3(void)
{
  code *pcVar1;
  long unaff_RBP;

  printf("> HTB{%s}\n", *(undefined8 *)(*(long *)(unaff_RBP + -0xb0) + 8));
  /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}
```

## Flag

```
HTB{REDACTED}
```
