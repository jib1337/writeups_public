# Bandit OverTheWire
https://overthewire.org/wargames/bandit/
  
## WARNING: SPOILERS AHEAD

```
      ,----..            ,----,          .---.
     /   /   \         ,/   .`|         /. ./|
    /   .     :      ,`   .'  :     .--'.  ' ;
   .   /   ;.  \   ;    ;     /    /__./ \ : |
  .   ;   /  ` ; .'___,/    ,' .--'.  '   \' .
  ;   |  ; \ ; | |    :     | /___/ \ |    ' '
  |   :  | ; | ' ;    |.';  ; ;   \  \;      :
  .   |  ' ' ' : `----'  |  |  \   ;  `      |
  '   ;  \; /  |     '   :  ;   .   \    .\  ;
   \   \  ',  /      |   |  '    \   \   ' \ |
    ;   :    /       '   :  |     :   '  |--"
     \   \ .'        ;   |.'       \   \ ;
  www. `---` ver     '---' he       '---" ire.org


Welcome to OverTheWire!

If you find any problems, please report them to Steven or morla on
irc.overthewire.org.

--[ Playing the games ]--

  This machine might hold several wargames.
  If you are playing "somegame", then:

    * USERNAMES are somegame0, somegame1, ...
    * Most LEVELS are stored in /somegame/.
    * PASSWORDS for each level are stored in /etc/somegame_pass/.

  Write-access to homedirectories is disabled. It is advised to create a
  working directory with a hard-to-guess name in /tmp/.  You can use the
  command "mktemp -d" in order to generate a random and hard to guess
  directory in /tmp/.  Read-access to both /tmp/ and /proc/ is disabled
  so that users can not snoop on eachother. Files and directories with
  easily guessable or short names will be periodically deleted!

  Please play nice:

    * don't leave orphan processes running
    * don't leave exploit-files laying around
    * don't annoy other players
    * don't post passwords or spoilers
    * again, DONT POST SPOILERS!
      This includes writeups of your solution on your blog or website!

--[ Tips ]--

  This machine has a 64bit processor and many security-features enabled
  by default, although ASLR has been switched off.  The following
  compiler flags might be interesting:

    -m32                    compile for 32bit
    -fno-stack-protector    disable ProPolice
    -Wl,-z,norelro          disable relro

  In addition, the execstack tool can be used to flag the stack as
  executable on ELF binaries.

  Finally, network-access is limited for most levels by a local
  firewall.

--[ Tools ]--

 For your convenience we have installed a few usefull tools which you can find
 in the following locations:

    * peda (https://github.com/longld/peda.git) in /usr/local/peda/
    * gdbinit (https://github.com/gdbinit/Gdbinit) in /usr/local/gdbinit/
    * pwntools (https://github.com/Gallopsled/pwntools)
    * radare2 (http://www.radare.org/)
    * checksec.sh (http://www.trapkit.de/tools/checksec.html) in /usr/local/bin/checksec.sh

--[ More information ]--

  For more information regarding individual wargames, visit
  http://www.overthewire.org/wargames/

  For support, questions or comments, contact us through IRC on
  irc.overthewire.org #wargames.

  Enjoy your stay!
```

### 0-1
The password for the next level is stored in a file called readme located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH (on port 2220) to log into that level and continue the game.
```bash
bandit0@bandit:~$ ls
readme
bandit0@bandit:~$ cat readme
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
```

### 1-2
The password for the next level is stored in a file called - located in the home directory
```bash
bandit1@bandit:~$ ls
-
bandit1@bandit:~$ cat ./-
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
```

### 2-3
The password for the next level is stored in a file called spaces in this filename located in the home directory
```bash
bandit2@bandit:~$ ls
spaces in this filename
bandit2@bandit:~$ cat "spaces in this filename"
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```

### 3-4
The password for the next level is stored in a hidden file in the inhere directory.
```bash
bandit3@bandit:~$ ls
inhere
bandit3@bandit:~$ cd inhere
bandit3@bandit:~/inhere$ find
.
./.hidden
bandit3@bandit:~/inhere$ cat .hidden
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
```

### 4-5
The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.
```bash
bandit4@bandit:~$ cd inhere
bandit4@bandit:~/inhere$ ls
-file00  -file02  -file04  -file06  -file08
-file01  -file03  -file05  -file07  -file09
bandit4@bandit:~/inhere$ cat ./-file00
ykC6q▒+▒▒▒z▒C|▒▒▒M▒     ▒rkA▒▒▒▒A
bandit4@bandit:~/inhere$ cat ./-file07
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
```

### 5-6
The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties:
* human-readable
* 1033 bytes in size
* not executable
```bash
bandit5@bandit:~$ ls
inhere
bandit5@bandit:~$ cd inhere
bandit5@bandit:~/inhere$ ls -la
total 88
drwxr-x--- 22 root bandit5 4096 Dec 28  2017 .
drwxr-xr-x  3 root root    4096 Dec 28  2017 ..
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere00
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere01
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere02
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere03
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere04
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere05
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere06
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere07
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere08
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere09
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere10
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere11
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere12
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere13
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere14
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere15
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere16
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere17
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere18
drwxr-x---  2 root bandit5 4096 Dec 28  2017 maybehere19
bandit5@bandit:~/inhere$ ls -la maybehere00
total 72
-rwxr-x---  1 root bandit5 1039 Dec 28  2017 -file1
-rw-r-----  1 root bandit5 9388 Dec 28  2017 -file2
-rwxr-x---  1 root bandit5 7378 Dec 28  2017 -file3
drwxr-x---  2 root bandit5 4096 Dec 28  2017 .
drwxr-x--- 22 root bandit5 4096 Dec 28  2017 ..
-rwxr-x---  1 root bandit5  551 Dec 28  2017 .file1
-rw-r-----  1 root bandit5 7836 Dec 28  2017 .file2
-rwxr-x---  1 root bandit5 4802 Dec 28  2017 .file3
-rwxr-x---  1 root bandit5 6118 Dec 28  2017 spaces file1
-rw-r-----  1 root bandit5 6850 Dec 28  2017 spaces file2
-rwxr-x---  1 root bandit5 1915 Dec 28  2017 spaces file3
bandit5@bandit:~/inhere$ ls -la maybehere01
total 80
-rwxr-x---  1 root bandit5 6028 Dec 28  2017 -file1
-rw-r-----  1 root bandit5  288 Dec 28  2017 -file2
-rwxr-x---  1 root bandit5 9641 Dec 28  2017 -file3
drwxr-x---  2 root bandit5 4096 Dec 28  2017 .
drwxr-x--- 22 root bandit5 4096 Dec 28  2017 ..
-rwxr-x---  1 root bandit5 8944 Dec 28  2017 .file1
-rw-r-----  1 root bandit5 3070 Dec 28  2017 .file2
-rwxr-x---  1 root bandit5 3792 Dec 28  2017 .file3
-rwxr-x---  1 root bandit5 4139 Dec 28  2017 spaces file1
-rw-r-----  1 root bandit5 4543 Dec 28  2017 spaces file2
-rwxr-x---  1 root bandit5 8834 Dec 28  2017 spaces file3
bandit5@bandit:~/inhere$ ls -la maybehere07
total 56
-rwxr-x---  1 root bandit5 3663 Dec 28  2017 -file1
-rw-r-----  1 root bandit5 2488 Dec 28  2017 -file2
-rwxr-x---  1 root bandit5 3362 Dec 28  2017 -file3
drwxr-x---  2 root bandit5 4096 Dec 28  2017 .
drwxr-x--- 22 root bandit5 4096 Dec 28  2017 ..
-rwxr-x---  1 root bandit5 3065 Dec 28  2017 .file1
-rw-r-----  1 root bandit5 1033 Dec 28  2017 .file2
-rwxr-x---  1 root bandit5 1997 Dec 28  2017 .file3
-rwxr-x---  1 root bandit5 4130 Dec 28  2017 spaces file1
-rw-r-----  1 root bandit5 9064 Dec 28  2017 spaces file2
-rwxr-x---  1 root bandit5 1022 Dec 28  2017 spaces file3
bandit5@bandit:~/inhere$ cd maybehere07
bandit5@bandit:~/inhere/maybehere07$ cat .file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
````

### 6-7
The password for the next level is stored somewhere on the server and has all of the following properties:
* owned by user bandit7
* owned by group bandit6
* 33 bytes in size
```bash
bandit6@bandit:~$ find / -type f -user bandit7 -group bandit6 -size 33c
find: '/etc/ssl/private': Permission denied
find: '/etc/polkit-1/localauthority': Permission denied
find: '/run/lxcfs': Permission denied
find: '/run/user/11003': Permission denied
find: '/run/user/11007': Permission denied
find: '/run/user/11002': Permission denied
find: '/run/user/11022': Permission denied
find: '/run/user/11004': Permission denied
find: '/run/user/11024': Permission denied
find: '/run/user/11021': Permission denied
find: '/run/user/11019': Permission denied
find: '/run/user/11026': Permission denied
find: '/run/user/11027': Permission denied
find: '/run/user/11008': Permission denied
find: '/run/user/0': Permission denied
find: '/run/user/11011': Permission denied
find: '/run/user/11020': Permission denied
find: '/run/user/11000': Permission denied
find: '/run/user/11025': Permission denied
find: '/run/user/11005': Permission denied
find: '/run/user/11009': Permission denied
find: '/run/user/11012': Permission denied
find: '/run/user/11015': Permission denied
find: '/run/user/11016': Permission denied
find: '/run/user/11014': Permission denied
find: '/run/user/11017': Permission denied
find: '/run/user/11013': Permission denied
find: '/run/sudo': Permission denied
find: '/run/log/journal/0d8e66480c320675a338622759f86ace': Permission denied
find: '/run/lvm': Permission denied
find: '/run/systemd/ask-password-block': Permission denied
find: '/run/systemd/inaccessible': Permission denied
find: '/run/lock/lvm': Permission denied
find: '/dev/mqueue': Permission denied
find: '/dev/shm': Permission denied
find: '/lost+found': Permission denied
find: '/root': Permission denied
find: '/opt/splunkforwarder/etc/auth': Permission denied
find: '/opt/splunkforwarder/etc/apps/learned/local': Permission denied
find: '/opt/splunkforwarder/var': Permission denied
find: '/home/bandit5/inhere': Permission denied
find: '/home/bandit30-git': Permission denied
find: '/home/bandit28-git': Permission denied
find: '/home/bandit29-git': Permission denied
find: '/home/bandit31-git': Permission denied
find: '/home/bandit27-git': Permission denied
find: '/var/log': Permission denied
find: '/var/lib/puppet': Permission denied
find: '/var/lib/apt/lists/partial': Permission denied
find: '/var/lib/update-notifier/package-data-downloads/partial': Permission denied
/var/lib/dpkg/info/bandit7.password <---------------------------------------------------FILE
find: '/var/lib/polkit-1': Permission denied
find: '/var/spool/rsyslog': Permission denied
find: '/var/spool/bandit24': Permission denied
find: '/var/spool/cron/atspool': Permission denied
find: '/var/spool/cron/atjobs': Permission denied
find: '/var/spool/cron/crontabs': Permission denied
find: '/var/crash': Permission denied
find: '/var/tmp': Permission denied
find: '/var/cache/apt/archives/partial': Permission denied
find: '/var/cache/ldconfig': Permission denied
find: '/tmp': Permission denied
find: '/sys/fs/fuse/connections/39': Permission denied
find: '/sys/kernel/debug': Permission denied
find: '/proc/tty/driver': Permission denied
find: '/proc/3170/task/3170/fdinfo/6': No such file or directory
find: '/proc/3170/fdinfo/5': No such file or directory

bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```

### 7-8
The password for the next level is stored in the file data.txt next to the word millionth
```bash
bandit7@bandit:~$ ls
data.txt
bandit7@bandit:~$ grep "millionth" data.txt
millionth       cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```

### 8-9
The password for the next level is stored in the file data.txt and is the only line of text that occurs only once
```bash
bandit8@bandit:~$ sort data.txt | uniq -u
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```

### 9-10
The password for the next level is stored in the file data.txt in one of the few human-readable strings, beginning with several ‘=’ characters.
```bash
bandit9@bandit:~$ ls
data.txt
bandit9@bandit:~$ strings data.txt | grep "=="
========== theP`
========== password
L========== isA
========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
```

### 10-11
The password for the next level is stored in the file data.txt, which contains base64 encoded data
```bash
bandit10@bandit:~$ ls
data.txt
bandit10@bandit:~$ cat data.txt | base64 --decode
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```

### 11-12
The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions
```bash
bandit11@bandit:~$ ls
data.txt
bandit11@bandit:~$ cat data.txt | tr '[a-z]' '[n-za-m]' | tr '[A-Z]' '[N-ZA-M]'
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
```

### 12-13
The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work using mkdir. For example: mkdir /tmp/myname123. Then copy the datafile using cp, and rename it using mv (read the manpages!)
```bash
bandit12@bandit:/tmp/hax$ ls
data.bin  data.txt  data2.txt
bandit12@bandit:/tmp/hax$ zcat data.bin | bzcat | zcat | tar xO | tar xO | bzcat | tar xO | zcat | cat
The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
```

### 13-14
The password for the next level is stored in /etc/bandit_pass/bandit14 and can only be read by user bandit14. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. Note: localhost is a hostname that refers to the machine you are working on
```bash
bandit13@bandit:~$ ls
sshkey.private
bandit13@bandit:~$ ssh -i ./sshkey.private bandit14@localhost
Could not create directory '/home/bandit13/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit13/.ssh/known_hosts).
Welcome to OverTheWire!
Enjoy your stay!

bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
```

### 14-15
The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost.
```bash
bandit14@bandit:~$ python -c "print('4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e')" | nc localhost 30000
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr
```

### 15-16
The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL encryption.

Helpful note: Getting “HEARTBEATING” and “Read R BLOCK”? Use -ign_eof and read the “CONNECTED COMMANDS” section in the manpage. Next to ‘R’ and ‘Q’, the ‘B’ command also works in this version of that command…
```bash
bandit15@bandit:~$ openssl s_client -connect localhost:30001 -ign_eof
CONNECTED(00000003)
depth=0 CN = bandit
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = bandit
verify return:1
---
Certificate chain
 0 s:/CN=bandit
   i:/CN=bandit
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICsjCCAZqgAwIBAgIJAKZI1xYeoXFuMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
BAMMBmJhbmRpdDAeFw0xNzEyMjgxMzIzNDBaFw0yNzEyMjYxMzIzNDBaMBExDzAN
BgNVBAMMBmJhbmRpdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOcX
ruVcnQUBeHJeNpSYayQExCJmcHzSCktnOnF/H4efWzxvLRWt5z4gYaKvTC9ixLrb
K7a255GEaUbP/NVFpB/sn56uJc1ijz8u0hWQ3DwVe5ZrHUkNzAuvC2OeQgh2HanV
5LwB1nmRZn90PG1puKxktMjXsGY7f9Yvx1/yVnZqu2Ev2uDA0RXij/T+hEqgDMI7
y4ZFmuYD8z4b2kAUwj7RHh9LUKXKQlO+Pn8hchdR/4IK+Xc4+GFOin0XdQdUJaBD
8quOUma424ejF5aB6QCSE82MmHlLBO2tzC9yKv8L8w+fUeQFECH1WfPC56GcAq3U
IvgdjGrU/7EKN5XkONcCAwEAAaMNMAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsF
AAOCAQEAnrOty7WAOpDGhuu0V8FqPoKNwFrqGuQCTeqhQ9LP0bFNhuH34pZ0JFsH
L+Y/q4Um7+66mNJUFpMDykm51xLY2Y4oDNCzugy+fm5Q0EWKRwrq+hIM+5hs0RdC
nARP+719ddmUiXF7r7IVP2gK+xqpa8+YcYnLuoXEtpKkrrQCCUiqabltU5yRMR77
3wqB54txrB4IhwnXqpO23kTuRNrkG+JqDUkaVpvct+FAdT3PODMONP/oHII3SH9i
ar/rI9k+4hjlg4NqOoduxX9M+iLJ0Zgj6HAg3EQVn4NHsgmuTgmknbhqTU3o4IwB
XFnxdxVy0ImGYtvmnZDQCGivDok6jA==
-----END CERTIFICATE-----
subject=/CN=bandit
issuer=/CN=bandit
---
No client certificate CA names sent
---
SSL handshake has read 1015 bytes and written 631 bytes
---
New, TLSv1/SSLv3, Cipher is AES128-SHA
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1
    Cipher    : AES128-SHA
    Session-ID: DC8495FBCAFD306657BB1812AF6598C5820481E841D296FD11B53E35B3DF7AB5
    Session-ID-ctx:
    Master-Key: 3E6F82D7EC0A690E46C864396432C4F0297AB449BA808393C5A3DF45A4B670E7484120012ADA3BFC0E047EAB6B31105F
    Key-Arg   : None
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 08 f0 15 a5 d6 6f a0 e8-06 d6 bb a4 0c 33 eb 04   .....o.......3..
    0010 - 08 73 0a 77 1f b6 59 66-88 3d 23 c5 d2 8b 2d 72   .s.w..Yf.=#...-r
    0020 - 0f d7 f5 b2 59 09 38 63-c4 cf ef 19 55 54 72 d0   ....Y.8c....UTr.
    0030 - dd 35 80 e1 b5 f6 61 02-0a 2b 97 95 57 58 1f 28   .5....a..+..WX.(
    0040 - d6 92 ee c8 d8 2e 50 9e-d5 3a e3 0e e2 80 1b 44   ......P..:.....D
    0050 - 04 5f ae 57 ce 67 51 a2-fe 9a 3b c8 3b ed c3 29   ._.W.gQ...;.;..)
    0060 - 81 8f 3f 63 0e 43 77 8e-25 68 74 85 8a 4b c0 b5   ..?c.Cw.%ht..K..
    0070 - 4a 8e 44 24 75 ea 23 8f-40 9b 55 d5 8e 94 69 8a   J.D$u.#.@.U...i.
    0080 - 20 0c c6 64 e7 bd dd eb-b0 ad 2f a6 4e 5e da 65    ..d....../.N^.e
    0090 - cf e7 cd f5 6c 03 4c 50-0b d0 87 f7 76 fc 92 06   ....l.LP....v...

    Start Time: 1534336947
    Timeout   : 300 (sec)
    Verify return code: 18 (self signed certificate)
---
BfMYroe26WYalil77FoDi9qh59eK5xNr
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd

closed
```

### 16-17
The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.
```bash
bandit16@bandit:~$ nmap -sV -p 31000-32000 localhost

Starting Nmap 7.40 ( https://nmap.org ) at 2020-06-22 05:18 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00028s latency).
Not shown: 996 closed ports
PORT      STATE SERVICE     VERSION
31046/tcp open  echo
31518/tcp open  ssl/echo
31691/tcp open  echo
31790/tcp open  ssl/unknown
31960/tcp open  echo
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31790-TCP:V=7.40%T=SSL%I=7%D=6/22%Time=5EF02332%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20cu
SF:rrent\x20password\n")%r(GetRequest,31,"Wrong!\x20Please\x20enter\x20the
SF:\x20correct\x20current\x20password\n")%r(HTTPOptions,31,"Wrong!\x20Plea
SF:se\x20enter\x20the\x20correct\x20current\x20password\n")%r(RTSPRequest,
SF:31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x20password\
SF:n")%r(Help,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x
SF:20password\n")%r(SSLSessionReq,31,"Wrong!\x20Please\x20enter\x20the\x20
SF:correct\x20current\x20password\n")%r(TLSSessionReq,31,"Wrong!\x20Please
SF:\x20enter\x20the\x20correct\x20current\x20password\n")%r(Kerberos,31,"W
SF:rong!\x20Please\x20enter\x20the\x20correct\x20current\x20password\n")%r
SF:(FourOhFourRequest,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20c
SF:urrent\x20password\n")%r(LPDString,31,"Wrong!\x20Please\x20enter\x20the
SF:\x20correct\x20current\x20password\n")%r(LDAPSearchReq,31,"Wrong!\x20Pl
SF:ease\x20enter\x20the\x20correct\x20current\x20password\n")%r(SIPOptions
SF:,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x20password
SF:\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.81 seconds

bandit16@bandit:~$ openssl s_client -connect localhost:31790 -ign_eof
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:/CN=localhost
   i:/CN=localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICBjCCAW+gAwIBAgIEUnONgjANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjAwNTE0MTIwMzM4WhcNMjEwNTE0MTIwMzM4WjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALOw+M6/
qSBJExGueg6T0HQRqfr80ysnqbuIAeQJ3VOwXg3BB8u7HtlA6JUrvQy66TWw5szi
uLBAyCffNHMx7Y2DF6L2vdSTxoOuDTLynRj7Xrw4f39NbgezfpfPbOd7/m3qNpcG
766Y46MT8w8j144VKK6qWhkBl9CPy8E2/frdAgMBAAGjZTBjMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDBLBglghkgBhvhCAQ0EPhY8QXV0b21hdGljYWxseSBnZW5lcmF0
ZWQgYnkgTmNhdC4gU2VlIGh0dHBzOi8vbm1hcC5vcmcvbmNhdC8uMA0GCSqGSIb3
DQEBBQUAA4GBAEj2rWLwLHxQMk8uuUTFHnXrtnpXP3GDch8zdUbiln4chTISKG9O
akG/gohigTEo9V3PupKcaO/zXqAbuB6iaJxOEezuLEmoGAMThHqeXusLNEPtYl5N
nM/qYplbcQtOqvYYODdP9N5dQFa54xkNmkP7oPiQkOFFKIucVzpxwzuo
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---
No client certificate CA names sent
Peer signing digest: SHA512
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1019 bytes and written 269 bytes
Verification error: self signed certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 1024 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 162966DFEC8D0C0F26E2A2BECA2F789B0C9A9FFF0DFF447A093EDA46DC1F5CFE
    Session-ID-ctx:
    Master-Key: BF8C1C3B2CB1EFEF8541943464454BA044664A465B053BD49B790FCF1C155CFF48A661A7A1985B048A97CB2A2F228420
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 15 f8 3e c0 71 51 2c d3-79 e7 dc 31 91 05 ba 3b   ..>.qQ,.y..1...;
    0010 - 56 98 6e 0a 11 22 7e 6c-41 5a ad c8 1d 3b 2d c1   V.n.."~lAZ...;-.
    0020 - 76 55 8d 3b bc c4 dd 65-45 6b be b5 5b 64 09 af   vU.;...eEk..[d..
    0030 - 4e 4e 0d 94 6e 75 e3 47-1c 4f 58 84 8b 54 57 68   NN..nu.G.OX..TWh
    0040 - 21 e9 56 48 d8 62 ac b5-6e 52 06 46 ef 91 7b 0a   !.VH.b..nR.F..{.
    0050 - f9 09 ed 01 05 87 fa bd-89 1d 0b c0 6a d6 ce 74   ............j..t
    0060 - da 6e d7 1d 0e ba 04 be-61 0e 44 00 7a ae 27 15   .n......a.D.z.'.
    0070 - fd b1 c2 b2 2f 65 37 ee-39 1d 07 17 ea a6 fa cf   ..../e7.9.......
    0080 - db cd ba 55 7a f7 de 52-ae 63 6c 38 52 94 e7 64   ...Uz..R.cl8R..d
    0090 - 0b af bb 9f e5 8c 9e 9e-1c b0 a7 89 b6 45 17 c4   .............E..

    Start Time: 1592796112
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: yes
---
cluFn7wTiGryunymYOu4RcffSxQluehd
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----

closed
```

### 17-18
There are 2 files in the homedirectory: passwords.old and passwords.new. The password for the next level is in passwords.new and is the only line that has been changed between passwords.old and passwords.new.
```bash
jib1337@LAPTOP-HRLBD1LQ:~/bandit$ ssh -i bandit17.key bandit17@bandit.labs.overthewire.org -p 2220
bandit17@bandit:~$ diff passwords.new passwords.old
42c42
< kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
---
> w0Yfolrc5bwjS4qw5mq1nnQi6mF03bii
```

### 18-19
The password for the next level is stored in a file readme in the homedirectory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.
```bash
jib1337@LAPTOP-HRLBD1LQ:~/bandit$ ssh bandit18@bandit.labs.overthewire.org -p 2220 ls
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password:
readme
jib1337@LAPTOP-HRLBD1LQ:~/bandit$ ssh bandit18@bandit.labs.overthewire.org -p 2220 'cat readme'
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password:
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```

### 19-20
To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.
```bash
bandit19@bandit:~$ ./bandit20-do
Run a command as another user.
  Example: ./bandit20-do id
bandit19@bandit:~$ ls -la /etc/bandit_pass
total 144
drwxr-xr-x  2 root     root     4096 May  7 20:14 .
drwxr-xr-x 87 root     root     4096 May 14 09:41 ..
-r--------  1 bandit0  bandit0     8 May  7 20:14 bandit0
-r--------  1 bandit1  bandit1    33 May  7 20:14 bandit1
-r--------  1 bandit10 bandit10   33 May  7 20:14 bandit10
-r--------  1 bandit11 bandit11   33 May  7 20:14 bandit11
-r--------  1 bandit12 bandit12   33 May  7 20:14 bandit12
-r--------  1 bandit13 bandit13   33 May  7 20:14 bandit13
-r--------  1 bandit14 bandit14   33 May  7 20:14 bandit14
-r--------  1 bandit15 bandit15   33 May  7 20:14 bandit15
-r--------  1 bandit16 bandit16   33 May  7 20:14 bandit16
-r--------  1 bandit17 bandit17   33 May  7 20:14 bandit17
-r--------  1 bandit18 bandit18   33 May  7 20:14 bandit18
-r--------  1 bandit19 bandit19   33 May  7 20:14 bandit19
-r--------  1 bandit2  bandit2    33 May  7 20:14 bandit2
-r--------  1 bandit20 bandit20   33 May  7 20:14 bandit20
-r--------  1 bandit21 bandit21   33 May  7 20:14 bandit21
-r--------  1 bandit22 bandit22   33 May  7 20:14 bandit22
-r--------  1 bandit23 bandit23   33 May  7 20:14 bandit23
-r--------  1 bandit24 bandit24   33 May  7 20:14 bandit24
-r--------  1 bandit25 bandit25   33 May  7 20:14 bandit25
-r--------  1 bandit26 bandit26   33 May  7 20:14 bandit26
-r--------  1 bandit27 bandit27   33 May  7 20:14 bandit27
-r--------  1 bandit28 bandit28   33 May  7 20:14 bandit28
-r--------  1 bandit29 bandit29   33 May  7 20:14 bandit29
-r--------  1 bandit3  bandit3    33 May  7 20:14 bandit3
-r--------  1 bandit30 bandit30   33 May  7 20:14 bandit30
-r--------  1 bandit31 bandit31   33 May  7 20:14 bandit31
-r--------  1 bandit32 bandit32   33 May  7 20:14 bandit32
-r--------  1 bandit33 bandit33   33 May  7 20:14 bandit33
-r--------  1 bandit4  bandit4    33 May  7 20:14 bandit4
-r--------  1 bandit5  bandit5    33 May  7 20:14 bandit5
-r--------  1 bandit6  bandit6    33 May  7 20:14 bandit6
-r--------  1 bandit7  bandit7    33 May  7 20:14 bandit7
-r--------  1 bandit8  bandit8    33 May  7 20:14 bandit8
-r--------  1 bandit9  bandit9    33 May  7 20:14 bandit9
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```
### 20-21
There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

```bash
bandit20@bandit:~$ tmux new -s mysession -n mywindow
```
- Ctrl + b then % to split pane
- Shift between the panes with Ctrl + b <-/->
- https://tmuxcheatsheet.com/

```bash
bandit20@bandit:~$                                          │ bandit20@bandit:~$ nc -lvp 20000
bandit20@bandit:~$ ./suconnect 20000                        │ listening on [any] 20000 ...
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j                      │ connect to [127.0.0.1] from localhost [127.0.0.1] 54402
Password matches, sending next password                     │ GbKksEFF4yrVs6il55v6gwY5aVje5f0j
bandit20@bandit:~$                                          │ gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
```

### 21-22
A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.
```bash
bandit21@bandit:~$ cat /etc/cron.d/*
* * * * * root /usr/bin/cronjob_bandit15_root.sh &> /dev/null
* * * * * root /usr/bin/cronjob_bandit17_root.sh &> /dev/null
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * root /usr/bin/cronjob_bandit25_root.sh &> /dev/null
bandit21@bandit:~$ cat /usr/bin/cronjob_bandit22.sh

#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv

bandit21@bandit:~$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
```

### 22-23
A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.  
NOTE: Looking at shell scripts written by other people is a very useful skill. The script for this level is intentionally made easy to read. If you are having problems understanding what it does, try executing it to see the debug information it prints.
```bash
bandit22@bandit:~$ cat /etc/cron.d/*
* * * * * root /usr/bin/cronjob_bandit15_root.sh &> /dev/null
* * * * * root /usr/bin/cronjob_bandit17_root.sh &> /dev/null
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * root /usr/bin/cronjob_bandit25_root.sh &> /dev/null
bandit22@bandit:~$ cat /usr/bin/cronjob_bandit23.sh

#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget

bandit22@bandit:~$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:~$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```

### 23-24
A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.  
NOTE: This level requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this level!
```bash
bandit23@bandit:~$ cat /etc/cron.d/*
* * * * * root /usr/bin/cronjob_bandit15_root.sh &> /dev/null
* * * * * root /usr/bin/cronjob_bandit17_root.sh &> /dev/null
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * root /usr/bin/cronjob_bandit25_root.sh &> /dev/null
bandit23@bandit:~$ cat /usr/bin/cronjob_bandit24.sh

#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname
echo "Executing and deleting all scripts in /var/spool/$myname:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done

bandit23@bandit:~$ cd /tmp
bandit23@bandit:/tmp$ mkdir keyout; cd keyout
bandit23@bandit:/tmp/keyout$ touch key.txt
bandit23@bandit:/tmp/keyout$ chmod 777 key.txt
bandit23@bandit:/tmp/keyout$ nano getkey.sh
```
Made script:
```bash
#!/bin/bash
cat /etc/bandit_pass/bandit24 >> /tmp/keyout/key.txt
```
Adjusted permissions and placed:
```bash
bandit23@bandit:/tmp/keyout$ chmod 777 getkey.sh
bandit23@bandit:/tmp/keyout$ cp getkey.sh /var/spool/bandit24/
bandit23@bandit:/tmp/keyout$ cat key.txt
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
```

### 24-25
A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.  
Created script:
```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect(('127.0.0.1', 30002))
print s.recv(1024)

for k in range(0,10000):
key = str(k).rjust(4,'0')
    s.sendall('UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ %s\r\n' % key)
    response = s.recv(1024)
    if 'Try' not in response:
        print response
        break
    else:
        if k % 100 == 0:
            print 'Up to %s key.' % key

s.close()
```
Output:
```bash
bandit24@bandit:/tmp/jackworking$ python brute.py
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.

Up to 0000 key.
Up to 0100 key.
Up to 0200 key.
Up to 0300 key.
Up to 0400 key.
Up to 0500 key.
Up to 0600 key.
Up to 0700 key.
Up to 0800 key.
Up to 0900 key.
Up to 1000 key.
Up to 1100 key.
Up to 1200 key.
Up to 1300 key.
Up to 1400 key.
Up to 1500 key.
Up to 1600 key.
Up to 1700 key.
Up to 1800 key.
Up to 1900 key.
Up to 2000 key.
Up to 2100 key.
Up to 2200 key.
Up to 2300 key.
Up to 2400 key.
Up to 2500 key.
Correct!
The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG
```

### 25-26
Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not /bin/bash, but something else. Find out what it is, how it works and how to break out of it.
```bash
bandit25@bandit:~$ ls
bandit26.sshkey
bandit25@bandit:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false
messagebus:x:101:104::/var/run/dbus:/bin/false
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
identd:x:103:65534::/var/run/identd:/bin/false
ntp:x:104:107::/home/ntp:/bin/false
bandit0:x:11000:11000:bandit level 0:/home/bandit0:/bin/bash
bandit1:x:11001:11001:bandit level 1:/home/bandit1:/bin/bash
bandit10:x:11010:11010:bandit level 10:/home/bandit10:/bin/bash
bandit11:x:11011:11011:bandit level 11:/home/bandit11:/bin/bash
bandit12:x:11012:11012:bandit level 12:/home/bandit12:/bin/bash
bandit13:x:11013:11013:bandit level 13:/home/bandit13:/bin/bash
bandit14:x:11014:11014:bandit level 14:/home/bandit14:/bin/bash
bandit15:x:11015:11015:bandit level 15:/home/bandit15:/bin/bash
bandit16:x:11016:11016:bandit level 16:/home/bandit16:/bin/bash
bandit17:x:11017:11017:bandit level 17:/home/bandit17:/bin/bash
bandit18:x:11018:11018:bandit level 18:/home/bandit18:/bin/bash
bandit19:x:11019:11019:bandit level 19:/home/bandit19:/bin/bash
bandit2:x:11002:11002:bandit level 2:/home/bandit2:/bin/bash
bandit20:x:11020:11020:bandit level 20:/home/bandit20:/bin/bash
bandit21:x:11021:11021:bandit level 21:/home/bandit21:/bin/bash
bandit22:x:11022:11022:bandit level 22:/home/bandit22:/bin/bash
bandit23:x:11023:11023:bandit level 23:/home/bandit23:/bin/bash
bandit24:x:11024:11024:bandit level 24:/home/bandit24:/bin/bash
bandit25:x:11025:11025:bandit level 25:/home/bandit25:/bin/bash
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
bandit27:x:11027:11027:bandit level 27:/home/bandit27:/bin/bash
bandit28:x:11028:11028:bandit level 28:/home/bandit28:/bin/bash
bandit29:x:11029:11029:bandit level 29:/home/bandit29:/bin/bash
bandit3:x:11003:11003:bandit level 3:/home/bandit3:/bin/bash
bandit30:x:11030:11030:bandit level 30:/home/bandit30:/bin/bash
bandit31:x:11031:11031:bandit level 31:/home/bandit31:/bin/bash
bandit32:x:11032:11032:bandit level 32:/home/bandit32:/home/bandit32/uppershell
bandit33:x:11033:11033:bandit level 33:/home/bandit33:/bin/bash
bandit4:x:11004:11004:bandit level 4:/home/bandit4:/bin/bash
bandit5:x:11005:11005:bandit level 5:/home/bandit5:/bin/bash
bandit6:x:11006:11006:bandit level 6:/home/bandit6:/bin/bash
bandit7:x:11007:11007:bandit level 7:/home/bandit7:/bin/bash
bandit8:x:11008:11008:bandit level 8:/home/bandit8:/bin/bash
bandit9:x:11009:11009:bandit level 9:/home/bandit9:/bin/bash
bandit27-git:x:11527:11527::/home/bandit27-git:/usr/bin/git-shell
bandit28-git:x:11528:11528::/home/bandit28-git:/usr/bin/git-shell
bandit29-git:x:11529:11529::/home/bandit29-git:/usr/bin/git-shell
bandit30-git:x:11530:11530::/home/bandit30-git:/usr/bin/git-shell
bandit31-git:x:11531:11531::/home/bandit31-git:/usr/bin/git-shell

bandit25@bandit:~$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

more ~/text.txt
exit 0

bandit25@bandit:~$ cat bandit26.sshkey
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEApis2AuoooEqeYWamtwX2k5z9uU1Afl2F8VyXQqbv/LTrIwdW
pTfaeRHXzr0Y0a5Oe3GB/+W2+PReif+bPZlzTY1XFwpk+DiHk1kmL0moEW8HJuT9
/5XbnpjSzn0eEAfFax2OcopjrzVqdBJQerkj0puv3UXY07AskgkyD5XepwGAlJOG
xZsMq1oZqQ0W29aBtfykuGie2bxroRjuAPrYM4o3MMmtlNE5fC4G9Ihq0eq73MDi
1ze6d2jIGce873qxn308BA2qhRPJNEbnPev5gI+5tU+UxebW8KLbk0EhoXB953Ix
3lgOIrT9Y6skRjsMSFmC6WN/O7ovu8QzGqxdywIDAQABAoIBAAaXoETtVT9GtpHW
qLaKHgYtLEO1tOFOhInWyolyZgL4inuRRva3CIvVEWK6TcnDyIlNL4MfcerehwGi
il4fQFvLR7E6UFcopvhJiSJHIcvPQ9FfNFR3dYcNOQ/IFvE73bEqMwSISPwiel6w
e1DjF3C7jHaS1s9PJfWFN982aublL/yLbJP+ou3ifdljS7QzjWZA8NRiMwmBGPIh
Yq8weR3jIVQl3ndEYxO7Cr/wXXebZwlP6CPZb67rBy0jg+366mxQbDZIwZYEaUME
zY5izFclr/kKj4s7NTRkC76Yx+rTNP5+BX+JT+rgz5aoQq8ghMw43NYwxjXym/MX
c8X8g0ECgYEA1crBUAR1gSkM+5mGjjoFLJKrFP+IhUHFh25qGI4Dcxxh1f3M53le
wF1rkp5SJnHRFm9IW3gM1JoF0PQxI5aXHRGHphwPeKnsQ/xQBRWCeYpqTme9amJV
tD3aDHkpIhYxkNxqol5gDCAt6tdFSxqPaNfdfsfaAOXiKGrQESUjIBcCgYEAxvmI
2ROJsBXaiM4Iyg9hUpjZIn8TW2UlH76pojFG6/KBd1NcnW3fu0ZUU790wAu7QbbU
i7pieeqCqSYcZsmkhnOvbdx54A6NNCR2btc+si6pDOe1jdsGdXISDRHFb9QxjZCj
6xzWMNvb5n1yUb9w9nfN1PZzATfUsOV+Fy8CbG0CgYEAifkTLwfhqZyLk2huTSWm
pzB0ltWfDpj22MNqVzR3h3d+sHLeJVjPzIe9396rF8KGdNsWsGlWpnJMZKDjgZsz
JQBmMc6UMYRARVP1dIKANN4eY0FSHfEebHcqXLho0mXOUTXe37DWfZza5V9Oify3
JquBd8uUptW1Ue41H4t/ErsCgYEArc5FYtF1QXIlfcDz3oUGz16itUZpgzlb71nd
1cbTm8EupCwWR5I1j+IEQU+JTUQyI1nwWcnKwZI+5kBbKNJUu/mLsRyY/UXYxEZh
ibrNklm94373kV1US/0DlZUDcQba7jz9Yp/C3dT/RlwoIw5mP3UxQCizFspNKOSe
euPeaxUCgYEAntklXwBbokgdDup/u/3ms5Lb/bm22zDOCg2HrlWQCqKEkWkAO6R5
/Wwyqhp/wTl8VXjxWo+W+DmewGdPHGQQ5fFdqgpuQpGUq24YZS8m66v5ANBwd76t
IZdtF5HXs2S5CADTwniUS5mX1HO9l5gUkk+h0cH5JnPtsMCnAUM+BRY=
-----END RSA PRIVATE KEY-----
```
Logging into bandit26 and starting VI:
```bash
jib1337@LAPTOP-HRLBD1LQ:~/bandit$ ssh -i bandit26.key bandit26@bandit.labs.overthewire.org -p 2220
:e  /etc/bandit_pass/bandit26
5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z
```

### 26-27
Good job getting a shell! Now hurry and grab the password for bandit27!
  
Back on the bandit26 vi screen:
```bash
:set shell=/bin/bash
:shell

[No write since last change]
bandit26@bandit:~$ whoami
bandit26
bandit26@bandit:~$ ls
bandit27-do  text.txt
bandit26@bandit:~$ ./bandit27-do
Run a command as another user.
  Example: ./bandit27-do id
bandit26@bandit:~$ ./bandit27-do cat /etc/bandit_pass/bandit27
3ba3118a22e93127a4ed485be72ef5ea
```

### 27-28
There is a git repository at ssh://bandit27-git@localhost/home/bandit27-git/repo. The password for the user bandit27-git is the same as for the user bandit27.
Clone the repository and find the password for the next level.
```bash
jib1337@LAPTOP-HRLBD1LQ:~/bandit$ git clone ssh://bandit27-git@bandit.labs.overthewire.org:2220/home/bandit27-git/repo
Cloning into 'repo'...
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit27-git@bandit.labs.overthewire.org's password:
remote: Counting objects: 3, done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 3 (delta 0), reused 0 (delta 0)
Receiving objects: 100% (3/3), done.
jib1337@LAPTOP-HRLBD1LQ:~/bandit$ cd repo/
jib1337@LAPTOP-HRLBD1LQ:~/bandit/repo$ ls
README
jib1337@LAPTOP-HRLBD1LQ:~/bandit/repo$ cat README
The password to the next level is: 0ef186ac70e04ea33b4c1853d2526fa2
```

## 28-29
There is a git repository at ssh://bandit28-git@localhost/home/bandit28-git/repo. The password for the user bandit28-git is the same as for the user bandit28.
Clone the repository and find the password for the next level.
```bash
jib1337@LAPTOP-HRLBD1LQ:~/bandit$ git clone ssh://bandit28-git@bandit.labs.overthewire.org:2220/home/bandit28-git/repo
Cloning into 'repo'...
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit28-git@bandit.labs.overthewire.org's password:
remote: Counting objects: 9, done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 9 (delta 2), reused 0 (delta 0)
Receiving objects: 100% (9/9), done.
Resolving deltas: 100% (2/2), done.
jib1337@LAPTOP-HRLBD1LQ:~/bandit$ cd repo/
jib1337@LAPTOP-HRLBD1LQ:~/bandit/repo$ ls
README.md
jib1337@LAPTOP-HRLBD1LQ:~/bandit/repo$ cat README.md
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx

jib1337@LAPTOP-HRLBD1LQ:~/bandit/repo$ git log --oneline
edd935d (HEAD -> master, origin/master, origin/HEAD) fix info leak
c086d11 add missing data
de2ebe2 initial commit of README.md

jib1337@LAPTOP-HRLBD1LQ:~/bandit/repo$ git checkout c086d11
Note: checking out 'c086d11'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by performing another checkout.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -b with the checkout command again. Example:

  git checkout -b <new-branch-name>

HEAD is now at c086d11 add missing data
jib1337@LAPTOP-HRLBD1LQ:~/bandit/repo$ cat README.md
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: bbc96594b4e001778eee9975372716b2
```

## 29-30
There is a git repository at ssh://bandit29-git@localhost/home/bandit29-git/repo. The password for the user bandit29-git is the same as for the user bandit29.
Clone the repository and find the password for the next level.
```bash
jib1337@LAPTOP-HRLBD1LQ:~/bandit$ git clone ssh://bandit29-git@bandit.labs.overthewire.org:2220/home/bandit29-git/repo
Cloning into 'repo'...
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit29-git@bandit.labs.overthewire.org's password:
remote: Counting objects: 16, done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 16 (delta 2), reused 0 (delta 0)
Receiving objects: 100% (16/16), done.
Resolving deltas: 100% (2/2), done.
jib1337@LAPTOP-HRLBD1LQ:~/bandit$ cd repo/
jib1337@LAPTOP-HRLBD1LQ:~/bandit/repo$ ls
README.md
jib1337@LAPTOP-HRLBD1LQ:~/bandit/repo$ cat README.md
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <no passwords in production!>

jib1337@LAPTOP-HRLBD1LQ:~/bandit/repo$ git branch -r
  origin/HEAD -> origin/master
  origin/dev
  origin/master
  origin/sploits-dev
jib1337@LAPTOP-HRLBD1LQ:~/bandit/repo$ git checkout origin/dev
Note: checking out 'origin/dev'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by performing another checkout.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -b with the checkout command again. Example:

  git checkout -b <new-branch-name>

HEAD is now at bc83328 add data needed for development
jib1337@LAPTOP-HRLBD1LQ:~/bandit/repo$ cat README.md
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: 5b90576bedb2cc04c86a9e924ce42faf
```