# Illumination | Hack The Box

A Junior Developer just switched to a new source control platform. Can you find the secret token?

```bash
kali@kali:~/Desktop/htb/challenges/Illumination.JS$ git log
commit edc5aabf933f6bb161ceca6cf7d0d2160ce333ec (HEAD -> master)
Author: SherlockSec <dan@lights.htb>
Date:   Fri May 31 14:16:43 2019 +0100

    Added some whitespace for readability!

commit 47241a47f62ada864ec74bd6dedc4d33f4374699
Author: SherlockSec <dan@lights.htb>
Date:   Fri May 31 12:00:54 2019 +0100

    Thanks to contributors, I removed the unique token as it was a security risk. Thanks for reporting responsibly!

commit ddc606f8fa05c363ea4de20f31834e97dd527381
Author: SherlockSec <dan@lights.htb>
Date:   Fri May 31 09:14:04 2019 +0100

    Added some more comments for the lovely contributors! Thanks for helping out!

commit 335d6cfe3cdc25b89cae81c50ffb957b86bf5a4a
Author: SherlockSec <dan@lights.htb>
Date:   Thu May 30 22:16:02 2019 +0100

    Moving to Git, first time using it. First Commit!

```
I now know the commit hash with the token. We can diff now to see what changes were made in the commit.
```
kali@kali:~/Desktop/htb/challenges/Illumination.JS$ git diff ddc606f8fa05c363ea4de20f31834e97dd527381

...
--- a/config.json
+++ b/config.json
@@ -1,9 +1,9 @@
-{
-
-       "token": "SFRCe3YzcnNpMG5fYzBudHIwbF9hbV9JX3JpZ2h0P30=",
-       "prefix": "~",
-       "lightNum": "1337",
-       "username": "UmVkIEhlcnJpbmcsIHJlYWQgdGhlIEpTIGNhcmVmdWxseQ==",
-       "host": "127.0.0.1"
-
+{
+
+       "token": "Replace me with token when in use! Security Risk!",
+       "prefix": "~",
+       "lightNum": "1337",
+       "username": "UmVkIEhlcnJpbmcsIHJlYWQgdGhlIEpTIGNhcmVmdWxseQ==",
+       "host": "127.0.0.1"
+
 }
\ No newline at end of file
...
```
Then just decode the bas64.
```bash
kali@kali:~$ echo SFRCe3YzcnNpMG5fYzBudHIwbF9hbV9JX3JpZ2h0P30= | base64 -d
HTB{v3rsi0n_c0ntr0l_am_I_right?}
```