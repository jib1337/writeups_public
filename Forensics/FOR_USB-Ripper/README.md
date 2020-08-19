# USB-Ripper | Hack The Box

## Problem
There is a sysadmin, who has been dumping all the USB events on his Linux host all the year... Recently, some bad guys managed to steal some data from his machine when they broke into the office. Can you help him to put a tail on the intruders? Note: once you find it, "crack" it.

## Solution
### 1. Find the violation
Some googling for "usb auth.log" turns up the application https://github.com/snovvcrash/usbrip.  
This can be used to search for violations against authorized devices through the provided syslog file.

```bash
kali@kali:~/Desktop/htb/challenges/usb-ripper$ sudo usbrip events violations auth.json -f syslog 
                       
         _     {{4}}    {v2.2.2-1}
 _ _ ___| |_ ___[E]___ 
| | |_ -| . |  _[N] . |
|___|___|___|_| [S]  _|
               x[1]_|   https://github.com/snovvcrash/usbrip
                       

[*] Started at 2020-08-14 01:20:07
[01:20:10] [INFO] Reading "/home/kali/Desktop/htb/challenges/usb-ripper/syslog"
100%|██████████████████████████████| 900000/900000 [00:19<00:00, 45767.23line/s]
[01:20:30] [INFO] Opening authorized device list: "/home/kali/Desktop/htb/challenges/usb-ripper/auth.json"
[01:20:30] [INFO] Searching for violations
100%|██████████████████████████████| 100000/100000 [00:00<00:00, 475417.46dev/s]
[?] How would you like your violation list to be generated?

    1. Terminal stdout
    2. JSON-file

[>] Please enter the number of your choice (default 1): 1
[01:20:36] [INFO] Preparing collected events
[01:20:36] [INFO] Representation: table

┌USB-Violation-Events─┬──────┬──────┬──────┬───────────────────────────┬──────────────────────────┬──────────────────────────────────┬──────┬─────────────────────┐
│           Connected │ Host │  VID │  PID │                   Product │             Manufacturer │                    Serial Number │ Port │        Disconnected │
├─────────────────────┼──────┼──────┼──────┼───────────────────────────┼──────────────────────────┼──────────────────────────────────┼──────┼─────────────────────┤
│ ????-08-03 •••••••• │ −−−− │ −−−− │ −−−− │ −−−−−−−−−−−−−−−−−−−−−−−−− │ −−−−−−−−−−−−−−−−−−−−−−−− │ −−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−− │ −−−− │ −−−−−−−−−−−−−−−−−−− │
│ ????-08-03 07:18:01 │ kali │ 3993 │ 9324 │ 1F8ADAEE73D993944FC7C7783 │ 884CCC9A3DF08F49C621373E │ 71DF5A33EFFDEA5B1882C9FBDC1240C6 │  1-1 │ ????-08-03 07:18:10 │
└─────────────────────┴──────┴──────┴──────┴───────────────────────────┴──────────────────────────┴──────────────────────────────────┴──────┴─────────────────────┘
[*] Shut down at 2020-08-14 01:20:36
[*] Time taken: 0:00:29.030885
```
### 2. Get the flag
The serial number looks the right length for a hash, so it's just a matter of googling it.
https://md5.gromweb.com/?md5=71DF5A33EFFDEA5B1882C9FBDC1240C6   
`HTB{mychemicalromance}`  