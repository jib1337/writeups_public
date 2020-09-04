# reverse_cipher | PicoCTF2019

## Problem
We have recovered a binary and a text file. Can you reverse the flag.

## Solution
### 1. Examine the binary
```bash
kali@kali:~/Desktop/pctf/reverse_cipher$ rabin2 -I rev
arch     x86
baddr    0x0
binsz    14935
bintype  elf
bits     64
canary   false
class    ELF64
compiler GCC: (Debian 8.2.0-14) 8.2.0
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      true
relocs   true
relro    partial
rpath    NONE
sanitiz  false
static   false
stripped false
subsys   linux
va       true
kali@kali:~/Desktop/pctf/reverse_cipher$ r2 rev
[0x000010a0]> aaaa
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
[0x000010a0]> afl
0x000010a0    1 42           entry0
0x000010d0    4 41   -> 34   sym.deregister_tm_clones
0x00001100    4 57   -> 51   sym.register_tm_clones
0x00001140    5 57   -> 50   entry.fini0
0x00001180    1 5            entry.init0
0x00001000    3 23           sym._init
0x00001330    1 1            sym.__libc_csu_fini
0x00001334    1 9            sym._fini
0x000012d0    4 93           sym.__libc_csu_init
0x00001185   16 324          main
0x00001030    1 6            sym.imp.puts
0x00001040    1 6            sym.imp.fread
0x00001050    1 6            sym.imp.fclose
0x00001060    1 6            sym.imp.fputc
0x00001070    1 6            sym.imp.fopen
0x00001080    1 6            sym.imp.exit
[0x000010a0]> s main; pdf
            ; DATA XREF from entry0 @ 0x10bd
┌ 324: int main (int argc, char **argv, char **envp);
│           ; var void *ptr @ rbp-0x50
│           ; var int64_t var_39h @ rbp-0x39
│           ; var size_t var_24h @ rbp-0x24
│           ; var file*var_20h @ rbp-0x20
│           ; var file*stream @ rbp-0x18
│           ; var signed int64_t var_ch @ rbp-0xc
│           ; var signed int64_t var_8h @ rbp-0x8
│           ; var int64_t c @ rbp-0x1
│           0x00001185      55             push rbp
│           0x00001186      4889e5         mov rbp, rsp
│           0x00001189      4883ec50       sub rsp, 0x50
│           0x0000118d      488d35740e00.  lea rsi, qword [0x00002008] ; "r" ; const char *mode
│           0x00001194      488d3d6f0e00.  lea rdi, qword str.flag.txt ; 0x200a ; "flag.txt" ; const char *filename
│           0x0000119b      e8d0feffff     call sym.imp.fopen          ; file*fopen(const char *filename, const char *mode)
│           0x000011a0      488945e8       mov qword [stream], rax
│           0x000011a4      488d35680e00.  lea rsi, qword [0x00002013] ; "a" ; const char *mode
│           0x000011ab      488d3d630e00.  lea rdi, qword str.rev_this ; 0x2015 ; "rev_this" ; const char *filename
│           0x000011b2      e8b9feffff     call sym.imp.fopen          ; file*fopen(const char *filename, const char *mode)
│           0x000011b7      488945e0       mov qword [var_20h], rax
│           0x000011bb      48837de800     cmp qword [stream], 0
│       ┌─< 0x000011c0      750c           jne 0x11ce
│       │   0x000011c2      488d3d570e00.  lea rdi, qword str.No_flag_found__please_make_sure_this_is_run_on_the_server ; 0x2020 ; "No flag found, please make sure this is run on the server" ; const char *s
│       │   0x000011c9      e862feffff     call sym.imp.puts           ; int puts(const char *s)
│       │   ; CODE XREF from main @ 0x11c0
│       └─> 0x000011ce      48837de000     cmp qword [var_20h], 0
│       ┌─< 0x000011d3      750c           jne 0x11e1
│       │   0x000011d5      488d3d7e0e00.  lea rdi, qword str.please_run_this_on_the_server ; 0x205a ; "please run this on the server" ; const char *s
│       │   0x000011dc      e84ffeffff     call sym.imp.puts           ; int puts(const char *s)
│       │   ; CODE XREF from main @ 0x11d3
│       └─> 0x000011e1      488b55e8       mov rdx, qword [stream]
│           0x000011e5      488d45b0       lea rax, qword [ptr]
│           0x000011e9      4889d1         mov rcx, rdx                ; FILE *stream
│           0x000011ec      ba01000000     mov edx, 1                  ; size_t nmemb
│           0x000011f1      be18000000     mov esi, 0x18               ; size_t size
│           0x000011f6      4889c7         mov rdi, rax                ; void *ptr
│           0x000011f9      e842feffff     call sym.imp.fread          ; size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
│           0x000011fe      8945dc         mov dword [var_24h], eax
│           0x00001201      837ddc00       cmp dword [var_24h], 0
│       ┌─< 0x00001205      7f0a           jg 0x1211
│       │   0x00001207      bf00000000     mov edi, 0                  ; int status
│       │   0x0000120c      e86ffeffff     call sym.imp.exit           ; void exit(int status)
│       │   ; CODE XREF from main @ 0x1205
│       └─> 0x00001211      c745f8000000.  mov dword [var_8h], 0
│       ┌─< 0x00001218      eb23           jmp 0x123d
│       │   ; CODE XREF from main @ 0x1241
│      ┌──> 0x0000121a      8b45f8         mov eax, dword [var_8h]
│      ╎│   0x0000121d      4898           cdqe
│      ╎│   0x0000121f      0fb64405b0     movzx eax, byte [rbp + rax - 0x50]
│      ╎│   0x00001224      8845ff         mov byte [c], al
│      ╎│   0x00001227      0fbe45ff       movsx eax, byte [c]
│      ╎│   0x0000122b      488b55e0       mov rdx, qword [var_20h]
│      ╎│   0x0000122f      4889d6         mov rsi, rdx                ; FILE *stream
│      ╎│   0x00001232      89c7           mov edi, eax                ; int c
│      ╎│   0x00001234      e827feffff     call sym.imp.fputc          ; int fputc(int c, FILE *stream)
│      ╎│   0x00001239      8345f801       add dword [var_8h], 1
│      ╎│   ; CODE XREF from main @ 0x1218
│      ╎└─> 0x0000123d      837df807       cmp dword [var_8h], 7
│      └──< 0x00001241      7ed7           jle 0x121a
│           0x00001243      c745f4080000.  mov dword [var_ch], 8
│       ┌─< 0x0000124a      eb43           jmp 0x128f
│       │   ; CODE XREF from main @ 0x1293
│      ┌──> 0x0000124c      8b45f4         mov eax, dword [var_ch]
│      ╎│   0x0000124f      4898           cdqe
│      ╎│   0x00001251      0fb64405b0     movzx eax, byte [rbp + rax - 0x50]
│      ╎│   0x00001256      8845ff         mov byte [c], al
│      ╎│   0x00001259      8b45f4         mov eax, dword [var_ch]
│      ╎│   0x0000125c      83e001         and eax, 1
│      ╎│   0x0000125f      85c0           test eax, eax
│     ┌───< 0x00001261      750c           jne 0x126f
│     │╎│   0x00001263      0fb645ff       movzx eax, byte [c]
│     │╎│   0x00001267      83c005         add eax, 5
│     │╎│   0x0000126a      8845ff         mov byte [c], al
│    ┌────< 0x0000126d      eb0a           jmp 0x1279
│    ││╎│   ; CODE XREF from main @ 0x1261
│    │└───> 0x0000126f      0fb645ff       movzx eax, byte [c]
│    │ ╎│   0x00001273      83e802         sub eax, 2
│    │ ╎│   0x00001276      8845ff         mov byte [c], al
│    │ ╎│   ; CODE XREF from main @ 0x126d
│    └────> 0x00001279      0fbe45ff       movsx eax, byte [c]
│      ╎│   0x0000127d      488b55e0       mov rdx, qword [var_20h]
│      ╎│   0x00001281      4889d6         mov rsi, rdx                ; FILE *stream
│      ╎│   0x00001284      89c7           mov edi, eax                ; int c
│      ╎│   0x00001286      e8d5fdffff     call sym.imp.fputc          ; int fputc(int c, FILE *stream)
│      ╎│   0x0000128b      8345f401       add dword [var_ch], 1
│      ╎│   ; CODE XREF from main @ 0x124a
│      ╎└─> 0x0000128f      837df416       cmp dword [var_ch], 0x16
│      └──< 0x00001293      7eb7           jle 0x124c
│           0x00001295      0fb645c7       movzx eax, byte [var_39h]
│           0x00001299      8845ff         mov byte [c], al
│           0x0000129c      0fbe45ff       movsx eax, byte [c]
│           0x000012a0      488b55e0       mov rdx, qword [var_20h]
│           0x000012a4      4889d6         mov rsi, rdx                ; FILE *stream
│           0x000012a7      89c7           mov edi, eax                ; int c
│           0x000012a9      e8b2fdffff     call sym.imp.fputc          ; int fputc(int c, FILE *stream)
│           0x000012ae      488b45e0       mov rax, qword [var_20h]
│           0x000012b2      4889c7         mov rdi, rax                ; FILE *stream
│           0x000012b5      e896fdffff     call sym.imp.fclose         ; int fclose(FILE *stream)
│           0x000012ba      488b45e8       mov rax, qword [stream]
│           0x000012be      4889c7         mov rdi, rax                ; FILE *stream
│           0x000012c1      e88afdffff     call sym.imp.fclose         ; int fclose(FILE *stream)
│           0x000012c6      90             nop
│           0x000012c7      c9             leave
└           0x000012c8      c3             ret
```
When examining the disassembled code in R2, I understand the following to be occuring in the binary:
- Opens flag.txt (containing unencrypted flag) in read mode, pointer stored in "stream"
- Opens rev_me in append mode, pointer stored in "var_20"
	- Obviously if these files arent present, the program exits with errors.
- Read the unencrypted flag value into memory
- Move forward in the value to the flag value (past "picoctf{"), printing each byte in the string.
- For the entire encrypted section of the flag:
	- Move the loop value into eax and make it relative to the string (so the counter for the first character is 0, the next is 1 etc)
	- Store this new loop value in a variable (c)
	- Perform an and instruction supplying two instances of EAX containing the loop counter.
	- Using a test instruction, determine if the outcome of the and operation was 0 or not (based on zf).
		- If not 0, subtract 2 from the character byte.
		- If 0, add 5 to the character byte.
	- Output the character byte and then increment the counter, repeat the process again.

### 2. Reverse the encryption
Based on what I've derived from the above instructions, I can now write a thing to reverse the encryption.
```python
#!/usr/bin/env python3

with open('rev_this', 'r') as flagFile:
    flag = flagFile.read().rstrip('\n')

print(flag[:8], end='')

for i, byte in enumerate(flag[8:-2]):
    if i & 1 == 0:
        print(chr(ord(byte)-5), end='')
    else:
        print(chr(ord(byte)+2), end='')

print(flag[-1])
```

### 3. Get the flag
```bash
kali@kali:~/Desktop/pctf/reverse_cipher$ ./revving_this.py 
picoCTF{r3v3rs35f207e7}
```
