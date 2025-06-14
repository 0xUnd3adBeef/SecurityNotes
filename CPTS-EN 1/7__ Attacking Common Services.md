#### Tools to Interact with Common Services

| **SMB**                                                                                  | **FTP**                                     | **Email**                                          | **Databases**                                                                                                                |
| ---------------------------------------------------------------------------------------- | ------------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)          | [ftp](https://linux.die.net/man/1/ftp)      | [Thunderbird](https://www.thunderbird.net/en-US/)  | [mssql-cli](https://github.com/dbcli/mssql-cli)                                                                              |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)                              | [lftp](https://lftp.yar.ru/)                | [Claws](https://www.claws-mail.org/)               | [mycli](https://github.com/dbcli/mycli)                                                                                      |
| [SMBMap](https://github.com/ShawnDEvans/smbmap)                                          | [ncftp](https://www.ncftp.com/)             | [Geary](https://wiki.gnome.org/Apps/Geary)         | [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)                             |
| [Impacket](https://github.com/SecureAuthCorp/impacket)                                   | [filezilla](https://filezilla-project.org/) | [MailSpring](https://getmailspring.com)            | [dbeaver](https://github.com/dbeaver/dbeaver)                                                                                |
| [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)   | [crossftp](http://www.crossftp.com/)        | [mutt](http://www.mutt.org/)                       | [MySQL Workbench](https://dev.mysql.com/downloads/workbench/)                                                                |
| [smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) |                                             | [mailutils](https://mailutils.org/)                | [SQL Server Management Studio or SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms) |
|                                                                                          |                                             | [sendEmail](https://github.com/mogaal/sendemail)   |                                                                                                                              |
|                                                                                          |                                             | [swaks](http://www.jetmore.org/john/code/swaks/)   |                                                                                                                              |
|                                                                                          |                                             | [sendmail](https://en.wikipedia.org/wiki/Sendmail) |                                                                                                                              |

---

![[Pasted image 20241103013958.png]]
Sensitive information may include, but is not limited to:

- Usernames.
- Email Addresses.
- Passwords.
- DNS records.
- IP Addresses.
- Source code.
- Configuration files.
- PII.
Can be found in : 
- File Shares.
- Email.
- Databases.

## Attacking FTP
To enumerate FTP we can use default nmap scripts : `sudo nmap -sC -sV -p 21 [target IP]`

We also can try to connect anonymously to an ftp server simply by providing `anonymous` user and no password (empty)

To bruteforce FTP with medusa we do `medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp`

FTP Bounce attack is a network attack that uses FTP servers to deliver outbound traffic to another device on the network. The attacker uses a `PORT` command to trick the FTP connection into running commands and getting information from a device other than the intended server.
It can be done using nmap : `nmap -Pn -v -n -p80 -b [user]:[password]@[target ip] [attacker IP]`

## Attacking SMB
You can enumerate SMB using `enum4linux`.

## Attacking RDP
Enable pth : `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`

## Attacking DNS
Recon : `nmap -p53 -Pn -sV -sC [target IP]`
AXFR Zone Transfer : `dig AXFR @ns1.inlanefreight.htb inlanefreight.htb`
Recon using fierce : `fierce --domain zonetransfer.me`

> find subdomains with any tool, in course there is `subfinder`

