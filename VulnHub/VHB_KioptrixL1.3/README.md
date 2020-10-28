# Kioptrix Level 1.3 | VulnHub
https://www.vulnhub.com/entry/kioptrix-level-11-2,23/

### 1. Scan
```bash
kali@kali:~/Desktop/osc/kiol3$ sudo nmap -A -T4 -p- 192.168.34.144
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-28 05:27 EDT
Nmap scan report for 192.168.34.144
Host is up (0.00073s latency).
Not shown: 39528 closed ports, 26003 filtered ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey: 
|   1024 9b:ad:4f:f2:1e:c5:f2:39:14:b9:d3:a0:0b:e8:41:71 (DSA)
|_  2048 85:40:c6:d5:41:26:05:34:ad:f8:6e:f2:a7:6b:4f:0e (RSA)
80/tcp  open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.28a (workgroup: WORKGROUP)
MAC Address: 00:0C:29:6A:43:4C (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 10h00m00s, deviation: 2h49m43s, median: 7h59m59s
|_nbstat: NetBIOS name: KIOPTRIX4, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.28a)
|   Computer name: Kioptrix4
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: Kioptrix4.localdomain
|_  System time: 2020-10-28T13:28:22-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE
HOP RTT     ADDRESS
1   0.73 ms 192.168.34.144

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.14 seconds
```
The machine is running SSH, Apache on port 80 and SMB - Samba smbd 3.0.28a. The scripts have also retrieved the domain/FQDN.

### 2. Enumerate SMB
Listing shares (as an anoynomous user):
```bash
kali@kali:~$ smbclient -L \\\\192.168.34.144\\ --option='client min protocol=NT1'
Enter WORKGROUP\kali's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (Kioptrix4 server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            KIOPTRIX4
```
Trying to connect to the shares:
```bash
kali@kali:~$ smbclient \\\\192.168.34.144\\IPC$ --option='client min protocol=NT1'
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_NETWORK_ACCESS_DENIED listing \*
smb: \> quit
kali@kali:~$ smbclient \\\\192.168.34.144\\print$ --option='client min protocol=NT1'
Enter WORKGROUP\kali's password: 
tree connect failed: NT_STATUS_ACCESS_DENIED
```
No luck. Aside from trying to interact with shares I can check out the actual SMB version and see if there are any vulnerabilities that can be exploited. There are a few, but none of them look very promising.
```bash
kali@kali:~$ searchsploit samba 3.0.
------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                                                            | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                                                                  | unix/remote/16320.rb
Samba 3.0.29 (Client) - 'receive_smb_raw()' Buffer Overflow (PoC)                                                                                                 | multiple/dos/5712.pl
------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
```
After taking a look at these (and attempting the MSF module) and not having any luck, it's time to move on.

### 4. Enumerate web server