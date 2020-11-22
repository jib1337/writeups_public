# Shocker | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.48]─[htb-jib1337@htb-bzghcnhtz1]─[~]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.1.175
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-22 13:30 UTC
Nmap scan report for 10.129.1.175
Host is up (0.22s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=11/22%OT=80%CT=1%CU=38512%PV=Y%DS=2%DC=T%G=Y%TM=5FBA68
OS:89%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=106%TI=Z%CI=I%II=I%TS=8)OP
OS:S(O1=M54DST11NW6%O2=M54DST11NW6%O3=M54DNNT11NW6%O4=M54DST11NW6%O5=M54DST
OS:11NW6%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)EC
OS:N(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   223.41 ms 10.10.14.1
2   223.58 ms 10.129.1.175

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 155.69 seconds
```
The machine is running Apache 2.4.18 and SSH.

### 2. Enumeration
When browsing to the machine over a web browser, a single page is returned with an image of a bug hitting itself with a hammer and some text - "Don't bug me!". When scanning for files and directories, I find a cgi-bin and icons, both cannot be read. I don't find any other files. However, knowing there may be CGI scripts is valuable information. The name of the box is a bit of a hint here, I can try to exploit the Apache mod_cgi (shellshock) to get command execution. Of course it relies on a vulnerable version of bash being installed which I have no idea if this is the case, so without the machine name this would be a wild shot in the dark.

Still, I need to enumerate the cgi-bin directory first to find a target.

### 3. Get a shell


