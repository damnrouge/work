Comprehensive Windows Privilege Escalation Techniques
This document covers all major privilege escalation techniques checked by the winPeas.ps1 script, a PowerShell adaptation of the WinPEAS tool for enumerating vulnerabilities on Windows systems. Each technique includes a description of the vulnerability or misconfiguration, how the script checks for it, and the corresponding command-line operations.
1. Unquoted Service Paths
Description:Services with unquoted paths containing spaces can be exploited if a user has write access to a parent directory in the path, allowing a malicious executable to be executed instead of the intended binary. The script checks for services with unquoted paths, excluding those in C:\Windows\, and filters by start mode (Auto/Manual) and state (Running/Stopped).
CommandLine:  
Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and ($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and ($_.State -eq "Running" -or $_.State -eq "Stopped") } | ForEach-Object { Write-Host "Unquoted Service Path found!" -ForegroundColor red; Write-Host Name: $_.Name; Write-Host PathName: $_.PathName; Write-Host StartName: $_.StartName; Write-Host StartMode: $_.StartMode; Write-Host Running: $_.State }

2. Weak Service Permissions
Description:Services where the current user has excessive permissions (e.g., FullControl, Write, Modify) on the executable can be modified to run malicious code. The script checks ACLs of service executables and their parent directories.
CommandLine:  
Get-WmiObject Win32_Service | Where-Object { $_.PathName -like '*.exe*' } | ForEach-Object { $Path = ($_.PathName -split '(?<=\.exe\b)')[0].Trim('"'); Start-ACLCheck -Target $Path -ServiceName $_.Name }

3. Service Registry Permissions
Description:Weak permissions on service registry keys (HKLM:\System\CurrentControlSet\services) may allow modification of service configurations, enabling privilege escalation. The script checks ACLs for each service registry key.
CommandLine:  
Get-ChildItem 'HKLM:\System\CurrentControlSet\services\' | ForEach-Object { $target = $_.Name.Replace("HKEY_LOCAL_MACHINE", "hklm:"); Start-ACLCheck -Target $target }

4. AlwaysInstallElevated Registry Setting
Description:If AlwaysInstallElevated is set to 1 in HKLM or HKCU, users can install MSI packages with SYSTEM privileges, allowing arbitrary code execution. The script checks both registry hives.
CommandLine:  
if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1) { Write-Host "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer).AlwaysInstallElevated = 1" -ForegroundColor red }; if ((Get-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1) { Write-Host "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer).AlwaysInstallElevated = 1" -ForegroundColor red }

5. WDigest Plaintext Passwords
Description:If UseLogonCredential=1 in the WDigest registry, plaintext passwords are stored in LSASS, extractable via tools like Mimikatz. The script checks this setting.
CommandLine:  
$WDigest = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest).UseLogonCredential; switch ($WDigest) { 0 { Write-Host "Value 0 found. Plain-text Passwords are not stored in LSASS" } 1 { Write-Host "Value 1 found. Plain-text Passwords may be stored in LSASS" -ForegroundColor red } Default { Write-Host "The system was unable to find the specified registry value: UseLogonCredential" } }

6. LSA Protection Disabled
Description:LSA Protection (RunAsPPL) prevents unauthorized LSASS memory access. If disabled (RunAsPPL=0), credentials can be dumped. The script checks RunAsPPL and RunAsPPLBoot values.
CommandLine:  
$RunAsPPL = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPL; switch ($RunAsPPL) { 2 { Write-Host "RunAsPPL: 2. Enabled without UEFI Lock" } 1 { Write-Host "RunAsPPL: 1. Enabled with UEFI Lock" } 0 { Write-Host "RunAsPPL: 0. LSA Protection Disabled. Try mimikatz." -ForegroundColor red } Default { "The system was unable to find the specified registry value: RunAsPPL / RunAsPPLBoot" } }

7. Credential Guard Disabled
Description:Credential Guard isolates credentials in a virtualized environment. If disabled (LsaCfgFlags=0), credentials are vulnerable. The script checks the LsaCfgFlags value.
CommandLine:  
$LsaCfgFlags = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).LsaCfgFlags; switch ($LsaCfgFlags) { 2 { Write-Host "LsaCfgFlags 2. Enabled without UEFI Lock" } 1 { Write-Host "LsaCfgFlags 1. Enabled with UEFI Lock" } 0 { Write-Host "LsaCfgFlags 0. LsaCfgFlags Disabled." -ForegroundColor red } Default { "The system was unable to find the specified registry value: LsaCfgFlags" } }

8. Unattended Installation Files
Description:Unattended installation files (e.g., sysprep.xml, unattend.xml) may contain plaintext credentials. The script searches common locations for these files.
CommandLine:  
@("C:\Windows\sysprep\sysprep.xml", "C:\Windows\sysprep\sysprep.inf", "C:\Windows\sysprep.inf", "C:\Windows\Panther\Unattended.xml", "C:\Windows\Panther\Unattend.xml", "C:\Windows\Panther\Unattend\Unattend.xml", "C:\Windows\Panther\Unattend\Unattended.xml", "C:\Windows\System32\Sysprep\unattend.xml", "C:\Windows\System32\Sysprep\unattended.xml", "C:\unattend.txt", "C:\unattend.inf") | ForEach-Object { if (Test-Path $_) { Write-Host "$_ found." } }

9. SAM/SYSTEM Backup Files
Description:Backup copies of SAM or SYSTEM registry hives may contain credentials and be accessible to non-admin users. The script checks common locations.
CommandLine:  
@("$Env:windir\repair\SAM", "$Env:windir\System32\config\RegBack\SAM", "$Env:windir\System32\config\SAM", "$Env:windir\repair\system", "$Env:windir\System32\config\SYSTEM", "$Env:windir\System32\config\RegBack\system") | ForEach-Object { if (Test-Path $_ -ErrorAction SilentlyContinue) { Write-Host "$_ Found!" -ForegroundColor red } }

10. Weak File/Folder Permissions
Description:Writable files or folders in critical locations (e.g., startup folders) can be modified to execute malicious code. The script checks ACLs for startup folders and their contents.
CommandLine:  
@("C:\Documents and Settings\All Users\Start Menu\Programs\Startup", "C:\Documents and Settings\$env:Username\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "$env:Appdata\Microsoft\Windows\Start Menu\Programs\Startup") | ForEach-Object { if (Test-Path $_) { Start-ACLCheck $_; Get-ChildItem -Recurse -Force -Path $_ | ForEach-Object { $SubItem = $_.FullName; if (Test-Path $SubItem) { Start-ACLCheck -Target $SubItem } } } }

11. Sensitive Data in Files
Description:Files (e.g., .xml, .txt, .config) may contain credentials or API keys. The script searches drives for files with specific extensions and matches them against regex patterns for sensitive data (e.g., passwords, usernames, tokens).
CommandLine:  
$Drives.Root | ForEach-Object { $Drive = $_; Get-ChildItem $Drive -Recurse -Include $fileExtensions -ErrorAction SilentlyContinue -Force | ForEach-Object { $path = $_; $regexSearch.keys | ForEach-Object { $passwordFound = Get-Content $path.FullName -ErrorAction SilentlyContinue -Force | Select-String $regexSearch[$_]; if ($passwordFound) { Write-Host "Possible Password found: $_" -ForegroundColor Yellow; Write-Host $Path.FullName; Write-Host -ForegroundColor Blue "$_ triggered"; Write-Host $passwordFound -ForegroundColor Red } } } }

12. Sensitive Data in Registry
Description:Registry keys may store credentials or tokens. The script searches HKCU and HKLM for values matching regex patterns (e.g., passwords, API keys).
CommandLine:  
$regPath = @("registry::\HKEY_CURRENT_USER\", "registry::\HKEY_LOCAL_MACHINE\"); foreach ($r in $regPath) { (Get-ChildItem -Path $r -Recurse -Force -ErrorAction SilentlyContinue) | ForEach-Object { $property = $_.property; $Name = $_.Name; $property | ForEach-Object { $Prop = $_; $regexSearch.keys | ForEach-Object { $value = $regexSearch[$_]; if ($Prop | Where-Object { $_ -like $value }) { Write-Host "Possible Password Found: $Name\$Prop"; Write-Host "Key: $_" -ForegroundColor Red } } } } }

13. Cloud Credentials
Description:Cloud configuration files (e.g., AWS, Azure, Google Cloud) may contain access keys or tokens. The script checks user directories for these files.
CommandLine:  
$Users = (Get-ChildItem C:\Users).Name; $CCreds = @(".aws\credentials", "AppData\Roaming\gcloud\credentials.db", "AppData\Roaming\gcloud\legacy_credentials", "AppData\Roaming\gcloud\access_tokens.db", ".azure\accessTokens.json", ".azure\azureProfile.json"); foreach ($u in $users) { $CCreds | ForEach-Object { if (Test-Path "c:\Users\$u\$_") { Write-Host "$_ found!" -ForegroundColor Red } } }

14. RDP Saved Connections
Description:Saved RDP connections in the registry may reveal server addresses or credentials. The script checks HKEY_USERS and HKEY_CURRENT_USER for Terminal Server Client settings.
CommandLine:  
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue; Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object { $HKUSID = $_.Name.Replace('HKEY_USERS\', ""); if (Test-Path "registry::HKEY_USERS\$HKUSID\Software\Microsoft\Terminal Server Client\Default") { Write-Host "Server Found: $((Get-ItemProperty "registry::HKEY_USERS\$HKUSID\Software\Microsoft\Terminal Server Client\Default" -Name MRU0).MRU0)" } }; if (Test-Path "registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default") { Write-Host "Server Found: $((Get-ItemProperty "registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" -Name MRU0).MRU0)" }

15. PuTTY Stored Credentials
Description:PuTTY session configurations may store usernames or proxy credentials, exploitable for session hijacking. The script checks HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions.
CommandLine:  
if (Test-Path HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions) { Get-ChildItem HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions | ForEach-Object { $RegKeyName = Split-Path $_.Name -Leaf; Write-Host "Key: $RegKeyName"; @("HostName", "PortNumber", "UserName", "PublicKeyFile", "PortForwardings", "ConnectionSharing", "ProxyUsername", "ProxyPassword") | ForEach-Object { Write-Host "$_ :"; Write-Host "$((Get-ItemProperty HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions\$RegKeyName).$_)" } } }

16. OpenVPN Credentials
Description:OpenVPN stores encrypted credentials in the registry, which can be decrypted if accessible. The script checks HKCU:\Software\OpenVPN-GUI\configs and decrypts auth-data.
CommandLine:  
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs" -ErrorAction SilentlyContinue; if ($Keys) { Add-Type -AssemblyName System.Security; $items = $keys | ForEach-Object { Get-ItemProperty $_.PsPath }; foreach ($item in $items) { $encryptedbytes = $item.'auth-data'; $entropy = $item.'entropy'; $entropy = $entropy[0..(($entropy.Length) - 2)]; $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes)) } }

17. WiFi Passwords
Description:WiFi profiles may store plaintext passwords, accessible if the user has permissions. The script extracts SSIDs and passwords using netsh wlan show profile.
CommandLine:  
((netsh.exe wlan show profiles) -match '\s{2,}:\s').replace("    All User Profile     : ", "") | ForEach-Object { netsh wlan show profile name="$_" key=clear }

18. Scheduled Tasks with Writable Executables
Description:Scheduled tasks running as SYSTEM with writable executables can be modified for privilege escalation. The script checks access to C:\Windows\System32\Tasks and audits task actions.
CommandLine:  
if (Get-ChildItem "c:\windows\system32\tasks" -ErrorAction SilentlyContinue) { Write-Host "Access confirmed, may need further investigation"; Get-ChildItem "c:\windows\system32\tasks" } else { Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | ForEach-Object { $Actions = $_.Actions.Execute; if ($Actions -ne $null) { foreach ($a in $actions) { if ($a -like "%windir%*") { $a = $a.replace("%windir%", $Env:windir) }; elseif ($a -like "%SystemRoot%*") { $a = $a.replace("%SystemRoot%", $Env:windir) }; elseif ($a -like "%localappdata%*") { $a = $a.replace("%localappdata%", "$env:UserProfile\appdata\local") }; elseif ($a -like "%appdata%*") { $a = $a.replace("%localappdata%", $env:Appdata) }; $a = $a.Replace('"', ''); Start-ACLCheck -Target $a } } } }

19. Group Policy Passwords
Description:Group Policy preference files (e.g., Groups.xml) may contain encrypted credentials, decryptable if accessible. The script searches Group Policy history paths.
CommandLine:  
$GroupPolicy = @("Groups.xml", "Services.xml", "Scheduledtasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml"); if (Test-Path "$env:SystemDrive\Microsoft\Group Policy\history") { Get-ChildItem -Recurse -Force "$env:SystemDrive\Microsoft\Group Policy\history" -Include @GroupPolicy }; if (Test-Path "$env:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history") { Get-ChildItem -Recurse -Force "$env:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history" }

20. Startup Application Registry Permissions
Description:Registry keys for startup applications (Run/RunOnce) may reference writable executables, allowing malicious code execution. The script checks ACLs for these executables.
CommandLine:  
@("registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce") | ForEach-Object { $ROPath = $_; (Get-Item $_) | ForEach-Object { $ROProperty = $_.property; $ROProperty | ForEach-Object { Start-ACLCheck ((Get-ItemProperty -Path $ROPath).$_ -split '(?<=\.exe\b)')[0].Trim('"') } } }

21. Running Process Permissions
Description:Running processes with writable executables can be replaced with malicious binaries. The script checks ACLs for unique process paths.
CommandLine:  
Get-Process | Select-Object Path -Unique | ForEach-Object { Start-ACLCheck -Target $_.path }

22. System Processes
Description:System processes running as SYSTEM may be vulnerable if their executables are writable. The script lists these processes for manual review.
CommandLine:  
Start-Process tasklist -ArgumentList '/v /fi "username eq system"' -Wait -NoNewWindow

23. Audit Log Settings
Description:Missing audit log settings may indicate weak monitoring, allowing attackers to operate undetected. The script checks for audit policy registry entries.
CommandLine:  
if ((Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\).Property) { Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ } else { Write-Host "No Audit Log settings, no registry entry found." }

24. Windows Event Forwarding (WEF)
Description:Lack of WEF configuration may indicate logs are not centralized, reducing detection capabilities. The script checks for WEF registry settings.
CommandLine:  
if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager) { Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager } else { Write-Host "Logs are not being forwarded, no registry entry found." }

25. LAPS (Local Administrator Password Solution)
Description:LAPS randomizes local admin passwords, enhancing security. If absent, local admin accounts may be exploitable. The script checks for LAPS DLL and registry settings.
CommandLine:  
if (Test-Path 'C:\Program Files\LAPS\CSE\Admpwd.dll') { Write-Host "LAPS dll found on this machine at C:\Program Files\LAPS\CSE\" -ForegroundColor Green } elseif (Test-Path 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll' ) { Write-Host "LAPS dll found on this machine at C:\Program Files (x86)\LAPS\CSE\" -ForegroundColor Green } else { Write-Host "LAPS dlls not found on this machine" }; if ((Get-ItemProperty HKLM:\Software\Policies\Microsoft Services\AdmPwd -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1) { Write-Host "LAPS registry key found on this machine" -ForegroundColor Green }

26. Cached WinLogon Credentials
Description:Cached credentials in the WinLogon registry may expose usernames or passwords, though only SYSTEM can view them directly. The script checks for cached credential counts and alternate credentials.
CommandLine:  
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CACHEDLOGONSCOUNT").CACHEDLOGONSCOUNT }; (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultDomainName; (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultUserName; (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultPassword; (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultDomainName; (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultUserName; (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultPassword

27. RDCMan Settings
Description:Remote Desktop Connection Manager (RDCMan) settings may store credentials or connection details. The script checks for the RDCMan settings file.
CommandLine:  
if (Test-Path "$env:USERPROFILE\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings") { Write-Host "RDCMan Settings Found at: $($env:USERPROFILE)\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" -ForegroundColor Red } else { Write-Host "No RDCMan.Settings found." }

28. SSH Key Checks
Description:PuTTY and OpenSSH keys in the registry may be extractable, allowing access to remote systems. The script checks for PuTTY SSH host keys and OpenSSH agent keys.
CommandLine:  
if (Test-Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys) { Write-Host "$((Get-Item -Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys).Property)" } else { Write-Host "No putty ssh keys found" }; if (Test-Path HKCU:\Software\OpenSSH\Agent\Keys) { Write-Host "OpenSSH keys found. Try this for decryption: https://github.com/ropnop/windows_sshagent_extract" -ForegroundColor Yellow } else { Write-Host "No OpenSSH Keys found." }

29. WinVNC Passwords
Description:WinVNC stores passwords in the registry, potentially in plaintext or decryptable formats. The script checks for WinVNC password entries.
CommandLine:  
if (Test-Path "HKCU:\Software\ORL\WinVNC3\Password") { Write-Host " WinVNC found at HKCU:\Software\ORL\WinVNC3\Password" } else { Write-Host "No WinVNC found." }

30. SNMP Passwords
Description:SNMP community strings in the registry may be accessible, allowing network device access. The script checks for SNMP service registry keys.
CommandLine:  
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP") { Write-Host "SNMP Key found at HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" } else { Write-Host "No SNMP found." }

31. TightVNC Passwords
Description:TightVNC stores passwords in the registry, which may be exploitable. The script checks for TightVNC server registry keys.
CommandLine:  
if (Test-Path "HKCU:\Software\TightVNC\Server") { Write-Host "TightVNC key found at HKCU:\Software\TightVNC\Server" } else { Write-Host "No TightVNC found." }

32. UAC Settings
Description:Disabled UAC (EnableLUA=0) allows certain privilege escalation techniques without prompting. The script checks the UAC registry setting.
CommandLine:  
if ((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA -eq 1) { Write-Host "EnableLUA is equal to 1. Part or all of the UAC components are on." } else { Write-Host "EnableLUA value not equal to 1" }

33. Recently Run Commands
Description:Recently run commands (via Win+R) in the registry may reveal sensitive operations or credentials. The script checks RunMRU in HKEY_USERS and HKEY_CURRENT_USER.
CommandLine:  
Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object { $HKUSID = $_.Name.Replace('HKEY_USERS\', ""); $property = (Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property; if (Test-Path "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") { foreach ($p in $property) { Write-Host "$((Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).getValue($p))" } } }; $property = (Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property; foreach ($p in $property) { Write-Host "$((Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).getValue($p))" }

34. PowerShell Version
Description:Older PowerShell versions may have exploitable features or lack security controls. The script checks installed PowerShell versions.
CommandLine:  
(Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine).PowerShellVersion | ForEach-Object { Write-Host "PowerShell $_ available" }; (Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine).PowerShellVersion | ForEach-Object { Write-Host "PowerShell $_ available" }

35. PowerShell Transcription Logging
Description:Enabled PowerShell transcription logs sensitive commands, which may reveal credentials. The script checks transcription settings in HKCU and HKLM.
CommandLine:  
if (Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription) { Get-Item HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription }; if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription) { Get-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription }; if (Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription) { Get-Item HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription }; if (Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription) { Get-Item HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription }

36. PowerShell Module Logging
Description:Module logging may capture sensitive module usage. The script checks module logging settings in HKCU and HKLM.
CommandLine:  
if (Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) { Get-Item HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging }; if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) { Get-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging }; if (Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) { Get-Item HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging }; if (Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) { Get-Item HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging }

37. PowerShell Script Block Logging
Description:Script block logging captures executed scripts, potentially revealing sensitive data. The script checks script block logging settings.
CommandLine:  
if ( Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) { Get-Item HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging }; if ( Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) { Get-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging }; if ( Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) { Get-Item HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging }; if ( Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) { Get-Item HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging }

38. WSUS Misconfiguration
Description:WSUS using HTTP with UseWUServer=1 can be exploited to deliver malicious updates. The script checks WSUS registry settings.
CommandLine:  
if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate) { Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate }; if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "USEWUServer" -ErrorAction SilentlyContinue).UseWUServer) { (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "USEWUServer").UseWUServer }

39. Internet Settings
Description:Internet settings in the registry may reveal proxy credentials or configurations. The script checks HKCU and HKLM Internet Settings.
CommandLine:  
$property = (Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).Property; foreach ($p in $property) { Write-Host "$p - $((Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).getValue($p))" }; $property = (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).Property; foreach ($p in $property) { Write-Host "$p - $((Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).getValue($p))" }

40. Installed Applications
Description:Certain applications (e.g., SCCM, WSL) may have exploitable features. The script lists installed applications via registry queries.
CommandLine:  
Get-InstalledApplications

41. WSL (bash.exe/wsl.exe) Presence
Description:Windows Subsystem for Linux (WSL) may allow execution of Linux-based exploits. The script checks for bash.exe and wsl.exe.
CommandLine:  
Get-ChildItem C:\Windows\WinSxS\ -Filter "amd64_microsoft-windows-lxss-bash*" | ForEach-Object { Write-Host $((Get-ChildItem $_.FullName -Recurse -Filter "*bash.exe*").FullName) }; @("bash.exe", "wsl.exe") | ForEach-Object { Write-Host $((Get-ChildItem C:\Windows\System32\ -Filter $_).FullName) }

42. SCCM Client
Description:SCCM clients may have exploitable configurations or credentials. The script checks for the SCCM client executable and WMI objects.
CommandLine:  
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * -ErrorAction SilentlyContinue | Select-Object Name, SoftwareVersion; if ($result) { $result } elseif (Test-Path 'C:\Windows\CCM\SCClient.exe') { Write-Host "SCCM Client found at C:\Windows\CCM\SCClient.exe" -ForegroundColor Cyan } else { Write-Host "Not Installed." }

43. Hosts File
Description:Modifications to the hosts file may indicate DNS spoofing or redirection. The script displays its contents.
CommandLine:  
Get-Content "c:\windows\system32\drivers\etc\hosts"

44. Network Information
Description:Network configurations (IP, DNS, ports, routes, adapters) may reveal misconfigurations or open services. The script collects this data using multiple commands.
CommandLine:  
Start-Process ipconfig.exe -ArgumentList "/all" -Wait -NoNewWindow; ipconfig /displaydns | Select-String "Record" | ForEach-Object { Write-Host $('{0}' -f $_) }; Start-Process NETSTAT.EXE -ArgumentList "-ano" -Wait -NoNewWindow; Start-Process arp -ArgumentList "-A" -Wait -NoNewWindow; Start-Process route -ArgumentList "print" -Wait -NoNewWindow; Get-NetAdapter | ForEach-Object { Write-Host "----------"; Write-Host $_.Name; Write-Host $_.InterfaceDescription; Write-Host $_.ifIndex; Write-Host $_.Status; Write-Host $_.MacAddress; Write-Host "----------" }

45. Firewall Rules
Description:Weak firewall rules may allow unauthorized access. The script notes the command to display all rules (output not shown to avoid buffer overwrite).
CommandLine:  
Write-Host -ForegroundColor Blue "=========|| Enabled firewall rules - displaying command only - it can overwrite the display buffer"; Write-Host -ForegroundColor Blue "=========|| show all rules with: netsh advfirewall firewall show rule dir=in name=all"

46. SMB Share Permissions
Description:SMB shares with excessive permissions (e.g., Full, Change) for the current user can be exploited for data access or code execution. The script checks share permissions.
CommandLine:  
Get-SmbShare | Get-SmbShareAccess | ForEach-Object { $SMBShareObject = $_; whoami.exe /groups /fo csv | select-object -skip 2 | ConvertFrom-Csv -Header 'group name' | Select-Object -ExpandProperty 'group name' | ForEach-Object { if ($SMBShareObject.AccountName -like $_ -and ($SMBShareObject.AccessRight -like "Full" -or "Change") -and $SMBShareObject.AccessControlType -like "Allow") { Write-Host -ForegroundColor red "$($SMBShareObject.AccountName) has $($SMBShareObject.AccessRight) to $($SMBShareObject.Name)" } } }

47. User Directory Access
Description:Read access to other users’ directories (C:\Users\*) may reveal sensitive files. The script checks for read permissions.
CommandLine:  
Get-ChildItem C:\Users\* | ForEach-Object { if (Get-ChildItem $_.FullName -ErrorAction SilentlyContinue) { Write-Host -ForegroundColor red "Read Access to $($_.FullName)" } }

48. Local Group Membership
Description:Membership in privileged groups (e.g., Administrators, Backup Operators) may grant elevated access. The script lists all local group members.
CommandLine:  
Get-LocalGroup | ForEach-Object { "`n Group: $($_.Name) `n"; if(Get-LocalGroupMember -name $_.Name){ (Get-LocalGroupMember -name $_.Name).Name } else { "     {GROUP EMPTY}" } }

49. Token Privileges
Description:Privileges like SeImpersonatePrivilege or SeBackupPrivilege can be abused for escalation. The script runs whoami /all to display user tokens.
CommandLine:  
Start-Process whoami.exe -ArgumentList "/all" -Wait -NoNewWindow

50. APPcmd Presence
Description:The presence of appcmd.exe (IIS management tool) may allow configuration modifications for privilege escalation. The script checks for its existence.
CommandLine:  
if (Test-Path ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) { Write-Host "$Env:SystemRoot\System32\inetsrv\appcmd.exe exists!" -ForegroundColor Red }

51. PowerShell History
Description:PowerShell command history may contain sensitive commands or credentials. The script searches history files for “pass” patterns.
CommandLine:  
Write-Host $(Get-Content (Get-PSReadLineOption).HistorySavePath | Select-String pa); Write-Host $(Get-Content "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" | Select-String pa)

52. Sticky Notes
Description:Sticky Notes databases may contain plaintext credentials. The script checks for the plum.sqlite database.
CommandLine:  
if (Test-Path "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite") { Write-Host "Sticky Notes database found. Could have credentials in plain text: C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite" }

53. Cached Credentials
Description:Cached credentials (via cmdkey) may be exploitable with tools like Mimikatz. The script lists cached credentials.
CommandLine:  
cmdkey.exe /list

54. DPAPI Master Keys
Description:DPAPI master keys can be used to decrypt credentials, often requiring Mimikatz. The script checks for master key files.
CommandLine:  
$appdataRoaming = "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\"; $appdataLocal = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\"; if ( Test-Path "$appdataRoaming\Protect\") { Write-Host "found: $appdataRoaming\Protect\"; Get-ChildItem -Path "$appdataRoaming\Protect\" -Force | ForEach-Object { Write-Host $_.FullName } }; if ( Test-Path "$appdataLocal\Protect\") { Write-Host "found: $appdataLocal\Protect\"; Get-ChildItem -Path "$appdataLocal\Protect\" -Force | ForEach-Object { Write-Host $_.FullName } }

55. DPAPI Credential Files
Description:DPAPI credential files may contain decryptable credentials. The script checks for these files in user directories.
CommandLine:  
if ( Test-Path "$appdataRoaming\Credentials\") { Get-ChildItem -Path "$appdataRoaming\Credentials\" -Force }; if ( Test-Path "$appdataLocal\Credentials\") { Get-ChildItem -Path "$appdataLocal\Credentials\" -Force }

56. Current Logged-On Users
Description:Active user sessions may indicate accounts to target. The script runs quser to list logged-on users.
CommandLine:  
try { quser } catch { Write-Host "'quser' command not present on system" }

57. Remote Sessions
Description:Remote sessions (via qwinsta) may reveal active connections or credentials. The script lists these sessions.
CommandLine:  
try { qwinsta } catch { Write-Host "'qwinsta' command not present on system" }

58. Kerberos Tickets
Description:Kerberos tickets may be exploitable for privilege escalation if accessible. The script lists tickets with klist.
CommandLine:  
try { klist } catch { Write-Host "No active sessions" }

59. Clipboard Contents
Description:Clipboard data may contain sensitive information (e.g., passwords). The script retrieves clipboard text.
CommandLine:  
Add-Type -AssemblyName PresentationCore; $text = [Windows.Clipboard]::GetText(); if ($text) { Write-Host -ForegroundColor Blue "=========|| ClipBoard text found:"; Write-Host $text }

60. McAfee SiteList Files
Description:McAfee SiteList files may contain decryptable passwords. The script searches for SiteList.xml files.
CommandLine:  
Get-ChildItem $Drive -Recurse -Include $fileExtensions -ErrorAction SilentlyContinue -Force | ForEach-Object { if ($_.FullName | Select-String "(?i).*SiteList\.xml") { Write-Host "Possible McAfee Site List Found: $($_.FullName)"; Write-Host "Just going to leave this here: https://github.com/funoverip/mcafee-sitelist-pwd-decryption" -ForegroundColor Yellow } }

61. System Information
Description:System details (e.g., OS version, hotfixes) may reveal known vulnerabilities. The script runs systeminfo.exe and lists hotfixes.
CommandLine:  
systeminfo.exe; Get-HotFix | Sort-Object -Descending -Property InstalledOn -ErrorAction SilentlyContinue | Select-Object HotfixID, Description, InstalledBy, InstalledOn | Format-Table -AutoSize

62. Drive Information
Description:Drive details may indicate accessible storage for file-based exploits. The script queries Win32_LogicalDisk for drive info.
CommandLine:  
$diskSearcher = New-Object System.Management.ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3"); $systemDrives = $diskSearcher.Get(); foreach ($drive in $systemDrives) { $driveLetter = $drive.DeviceID; $driveLabel = $drive.VolumeName; $driveSize = [math]::Round($drive.Size / 1GB, 2); $driveFreeSpace = [math]::Round($drive.FreeSpace / 1GB, 2); Write-Output "Drive: $driveLetter"; Write-Output "Label: $driveLabel"; Write-Output "Size: $driveSize GB"; Write-Output "Free Space: $driveFreeSpace GB"; Write-Output "" }

63. Antivirus Detection
Description:Antivirus exclusions may allow malicious code execution. The script lists antivirus products and Defender exclusions.
CommandLine:  
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName; Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue

64. Net Accounts Policy
Description:Weak account policies (e.g., low lockout thresholds) may allow brute-forcing. The script runs net accounts to display policies.
CommandLine:  
net accounts

