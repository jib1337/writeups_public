## Doctor | HackTheBox

### 1. Scan
```bash
kali@kali:~/Desktop/htb/doctor$ sudo nmap -A -p- -T4 10.10.10.209
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-06 05:29 EDT
Nmap scan report for 10-10-10-209.tpgi.com.au (10.10.10.209)
Host is up (0.32s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Crestron XPanel control system (90%), Linux 2.6.32 (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Adtran 424RG FTTH gateway (86%), Linux 2.6.32 - 3.1 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   334.88 ms 10.10.14.1
2   340.12 ms 10-10-10-209.tpgi.com.au (10.10.10.209)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 424.57 seconds
```
The machine is running SSH, a HTTP server on port 80, and a Splunk server on port 8089.

### 2. Look at the website
The webpage being hosted by the machine is a themed around a medical clinic. There is a contact e-mail with the domain doctors.htb. A lot of the text is placeholder, so special attention can be paid to anything that has been added in. Three doctors are listed:
- Jade Guzman
- Hannah Ford
- James Wilson  
Additionally, the blog shows comments being posted by an "admin" account. Aside from this, there is not much information to get from the site. I did run a dirbust:
```bash
kali@kali:~$ dirb http://10.10.10.209

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Oct  6 22:27:50 2020
URL_BASE: http://10.10.10.209/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.209/ ----
==> DIRECTORY: http://10.10.10.209/css/                                                                                                                                                                                                   
==> DIRECTORY: http://10.10.10.209/fonts/                                                                                                                                                                                                 
==> DIRECTORY: http://10.10.10.209/images/                                                                                                                                                                                                
+ http://10.10.10.209/index.html (CODE:200|SIZE:19848)                                                                                                                                                                                    
==> DIRECTORY: http://10.10.10.209/js/                                                                                                                                                                                                    
+ http://10.10.10.209/server-status (CODE:403|SIZE:277)                                                                                                                                                                                   
                                                                                                                                                                                                                                          
---- Entering directory: http://10.10.10.209/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                          
---- Entering directory: http://10.10.10.209/fonts/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                          
---- Entering directory: http://10.10.10.209/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                          
---- Entering directory: http://10.10.10.209/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)                                                                                                                                                                                          
                                                                                                                                                                                                                                           
-----------------                                                                                                                                                                                                                          
END_TIME: Tue Oct  6 22:56:34 2020                                                                                                                                                                                                         
DOWNLOADED: 4612 - FOUND: 2  
```
  
When visiting the server using the hostname, we get directed to a "Doctors Secure Messaging" login page. There is a link to register an account, and addionally a source code comment indicates there is also an archive page.
```html
<!--archive still under beta testing<a class="nav-item nav-link" href="/archive">Archive</a>-->
```
Accounts are created with a "time limit of 20 minutes". Accounts have the ability to create messages to be shared between doctors. The archive page remains blank before I created an account, as well as before and after making posts once logged in.