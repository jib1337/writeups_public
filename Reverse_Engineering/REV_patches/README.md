# Patches | NACTF2020

## Problem
This binary does nothing.

## Solution
### 1. Check out the binary
```bash
┌──(kali㉿kali)-[~/Desktop/nactf/patches]
└─$ ./patches
Goodbye.
```
Ok then.

### 2. Static analysis 
```bash                                                                                                                                                         
┌──(kali㉿kali)-[~/Desktop/nactf/patches]
└─$ r2 patches
[0x00001050]> aaaa
[Cannot find function at 0x00001050 sym. and entry0 (aa)
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Finding function preludes
[x] Enable constraint types analysis for variables
[0x00001050]> s main; pdf
            ; DATA XREF from entry0 @ +0x21
┌ 23: int main (int argc, char **argv, char **envp);
│           0x000012d9      55             push rbp
│           0x000012da      4889e5         mov rbp, rsp
│           0x000012dd      488d3dac0e00.  lea rdi, qword str.Goodbye. ; 0x2190 ; "Goodbye." ; const char *s
│           0x000012e4      e847fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000012e9      b800000000     mov eax, 0
│           0x000012ee      5d             pop rbp
└           0x000012ef      c3             ret
[0x000012d9]> afl
0x000012d9    1 23           main
0x00001030    1 6            sym.imp.puts
0x00001261    3 120          sym.print_flag
0x00001149    4 280          fcn.00001149
0x00001040    1 6            sym.imp.__stack_chk_fail
0x00001080    4 41   -> 34   fcn.00001080
[0x000012d9]> pdf @ sym.print_flag
┌ 120: sym.print_flag ();
│           ; var int64_t var_170h @ rbp-0x170
│           ; var char *s @ rbp-0x60
│           ; var int64_t canary @ rbp-0x8
│           0x00001261      55             push rbp
│           0x00001262      4889e5         mov rbp, rsp
│           0x00001265      4881ec700100.  sub rsp, 0x170
│           0x0000126c      64488b042528.  mov rax, qword fs:[0x28]
│           0x00001275      488945f8       mov qword [canary], rax
│           0x00001279      31c0           xor eax, eax
│           0x0000127b      488d8590feff.  lea rax, qword [var_170h]
│           0x00001282      488d15f70d00.  lea rdx, qword [0x00002080]
│           0x00001289      b922000000     mov ecx, 0x22               ; '"'
│           0x0000128e      4889c7         mov rdi, rax
│           0x00001291      4889d6         mov rsi, rdx
│           0x00001294      f348a5         rep movsq qword [rdi], qword ptr [rsi]
│           0x00001297      488d55a0       lea rdx, qword [s]          ; int64_t arg3
│           0x0000129b      488d8590feff.  lea rax, qword [var_170h]
│           0x000012a2      b949000000     mov ecx, 0x49               ; rcx ; int64_t arg4
│           0x000012a7      488d35720d00.  lea rsi, qword [rsi]        ; 0x2020 ; int64_t arg2
│           0x000012ae      4889c7         mov rdi, rax                ; int64_t arg1
│           0x000012b1      e893feffff     call fcn.00001149
│           0x000012b6      488d45a0       lea rax, qword [s]
│           0x000012ba      4889c7         mov rdi, rax                ; const char *s
│           0x000012bd      e86efdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000012c2      90             nop
│           0x000012c3      488b45f8       mov rax, qword [canary]
│           0x000012c7      64482b042528.  sub rax, qword fs:[0x28]
│       ┌─< 0x000012d0      7405           je 0x12d7
│       │   0x000012d2      e869fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from sym.print_flag @ 0x12d0
│       └─> 0x000012d7      c9             leave
└           0x000012d8      c3             ret
[0x000012d9]> q
```
In the function list there is a function called print_flag. The function deobfuscates the flag from a file and prints it. Since there is no precondition to this function being called, the binary can be modified to redirect execution to this function instead of printf.

### 2. Patch binary and get flag
```bash
┌──(kali㉿kali)-[~/Desktop/nactf/patches]
└─$ r2 -w patches 
[0x00001050]> s main; pdf
p: Cannot find function at 0x000012d9
[0x000012d9]> aaaa
[Cannot find function at 0x00001050 sym. and entry0 (aa)
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Finding function preludes
[x] Enable constraint types analysis for variables
[0x000012d9]> s main; pdf
            ; DATA XREF from entry0 @ +0x21
┌ 23: int main (int argc, char **argv, char **envp);
│           0x000012d9      55             push rbp
│           0x000012da      4889e5         mov rbp, rsp
│           0x000012dd      488d3dac0e00.  lea rdi, qword str.Goodbye. ; 0x2190 ; "Goodbye." ; const char *s
│           0x000012e4      e847fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000012e9      b800000000     mov eax, 0
│           0x000012ee      5d             pop rbp
└           0x000012ef      c3             ret
[0x000012d9]> afl
0x000012d9    1 23           main
0x00001030    1 6            sym.imp.puts
0x00001261    3 120          sym.print_flag
0x00001149    4 280          fcn.00001149
0x00001040    1 6            sym.imp.__stack_chk_fail
0x00001080    4 41   -> 34   fcn.00001080
[0x000012d9]> wa jmp 0x00001261 @ 0x000012e4
Written 5 byte(s) (jmp 0x00001261) = wx e978ffffff
[0x000012d9]> pdf
        ╎   ; DATA XREF from entry0 @ +0x21
┌ 23: int main (int argc, char **argv, char **envp);
│       ╎   0x000012d9      55             push rbp
│       ╎   0x000012da      4889e5         mov rbp, rsp
│       ╎   0x000012dd      488d3dac0e00.  lea rdi, qword str.Goodbye. ; 0x2190 ; "Goodbye." ; const char *s
│       └─< 0x000012e4      e978ffffff     jmp sym.print_flag
│           0x000012e9      b800000000     mov eax, 0
│           0x000012ee      5d             pop rbp
└           0x000012ef      c3             ret
[0x000012d9]> q
                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Desktop/nactf/patches]
└─$ ./patches 
nactf{unl0ck_s3cr3t_funct10n4l1ty_w1th_b1n4ry_p4tch1ng_L9fcKhyPupGVfCMZ}
```