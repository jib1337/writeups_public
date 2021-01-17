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
  

