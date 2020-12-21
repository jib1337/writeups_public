# Solidstate | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-cidvmbkzfc]─[~]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.29.189
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-21 03:09 UTC
Nmap scan report for 10.129.29.189
Host is up (0.22s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3?
119/tcp  open  nntp?
4555/tcp open  rsip?
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/21%OT=22%CT=1%CU=32269%PV=Y%DS=2%DC=T%G=Y%TM=5FE014
OS:56%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10E%TI=Z%CI=I%II=I%TS=8)OP
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

TRACEROUTE (using port 199/tcp)
HOP RTT       ADDRESS
1   218.04 ms 10.10.14.1
2   218.17 ms 10.129.29.189

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 599.38 seconds
```
The machine is running SSH, a HTTP server on port 80, and there are some other ports open - 25, 110, 119 and 4555.

### 2. Enumeration
Firstly check out and get the version for smtp/pop3 as nmap wasn't able to do it.
```bash
msf5 auxiliary(scanner/smtp/smtp_version) > run

[+] 10.129.29.189:25      - 10.129.29.189:25 SMTP 220 solidstate SMTP Server (JAMES SMTP Server 2.3.2) ready Sun, 20 Dec 2020 22:47:41 -0500 (EST)\x0d\x0a
[*] 10.129.29.189:25      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf5 auxiliary(scanner/pop3/pop3_version) > run

[+] 10.129.29.189:110     - 10.129.29.189:110 POP3 +OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready \x0d\x0a
[*] 10.129.29.189:110     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
These ports are running services from JAMES SMTP Server 2.3.2. The remote administration panel is on port 4555, so I can attempt to log in over telnet.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-cidvmbkzfc]─[~]
└──╼ [★]$ telnet 10.129.29.189 4555
Trying 10.129.29.189...
Connected to 10.129.29.189.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
HELP
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit
```
I get logged in with the default creds. From here I can list users:
```bash
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```
The good news from here is that there is an authenticated remote command execution exploit I can leverage to run commands on the machine: https://www.exploit-db.com/exploits/35513. A better explanation can be found at: https://www.rapid7.com/db/modules/exploit/linux/smtp/apache_james_exec/. The key part is this:
  
*Messages for a given user are stored in a directory partially defined by the username. By creating a user with a directory traversal payload as the username, commands can be written to a given directory.*
