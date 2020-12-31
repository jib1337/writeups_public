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
