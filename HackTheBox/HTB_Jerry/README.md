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

