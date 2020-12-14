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

