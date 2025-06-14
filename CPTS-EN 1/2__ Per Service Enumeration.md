## FTP - File Transfer Protocol
 #FTP-Config File :  `cat /etc/vsftpd.conf | grep -v "#"`
 
| **Setting**                                                   | **Description**                                                                                          |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `listen=NO`                                                   | Run from inetd or as a standalone daemon?                                                                |
| `listen_ipv6=YES`                                             | Listen on IPv6 ?                                                                                         |
| `anonymous_enable=NO`                                         | Enable Anonymous access?                                                                                 |
| `local_enable=YES`                                            | Allow local users to login?                                                                              |
| `dirmessage_enable=YES`                                       | Display active directory messages when users go into certain directories?                                |
| `use_localtime=YES`                                           | Use local time?                                                                                          |
| `xferlog_enable=YES`                                          | Activate logging of uploads/downloads?                                                                   |
| `connect_from_port_20=YES`                                    | Connect from port 20?                                                                                    |
| `secure_chroot_dir=/var/run/vsftpd/empty`                     | Name of an empty directory                                                                               |
| `pam_service_name=vsftpd`                                     | This string is the name of the PAM service vsftpd will use.                                              |
| `rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem`          | The last three options specify the location of the RSA certificate to use for SSL encrypted connections. |
| `rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key` |                                                                                                          |
| `ssl_enable=NO`                                               |                                                                                                          |
FTP Users at : `cat /etc/ftpusers`

|**Command**|**Description**|
|---|---|
|`ftp <FQDN/IP>`|Interact with the FTP service on the target.|
|`nc -nv <FQDN/IP> 21`|Interact with the FTP service on the target.|
|`telnet <FQDN/IP> 21`|Interact with the FTP service on the target.|
|`openssl s_client -connect <FQDN/IP>:21 -starttls ftp`|Interact with the FTP service on the target using encrypted connection.|
|`wget -m --no-passive ftp://anonymous:anonymous@<target>`|Download all available files on the target FTP server.|



--------------------------------
## SMB / Samba - Server Message Block

| **SMB Version** | **Supported**                       | **Features**                                                           |
| --------------- | ----------------------------------- | ---------------------------------------------------------------------- |
| CIFS            | Windows NT 4.0                      | Communication via NetBIOS interface                                    |
| SMB 1.0         | Windows 2000                        | Direct connection via TCP                                              |
| SMB 2.0         | Windows Vista, Windows Server 2008  | Performance upgrades, improved message signing, caching feature        |
| SMB 2.1         | Windows 7, Windows Server 2008 R2   | Locking mechanisms                                                     |
| SMB 3.0         | Windows 8, Windows Server 2012      | Multichannel connections, end-to-end encryption, remote storage access |
| SMB 3.0.2       | Windows 8.1, Windows Server 2012 R2 |                                                                        |
| SMB 3.1.1       | Windows 10, Windows Server 2016     | Integrity checking, AES-128 encryption                                 |
#SMB-Config-files : `cat /etc/samba/smb.conf | grep -v "#\|\;" `

#SMC-Config

| **Setting**                    | **Description**                                                       |
| ------------------------------ | --------------------------------------------------------------------- |
| `[sharename]`                  | The name of the network share.                                        |
| `workgroup = WORKGROUP/DOMAIN` | Workgroup that will appear when clients query.                        |
| `path = /path/here/`           | The directory to which user is to be given access.                    |
| `server string = STRING`       | The string that will show up when a connection is initiated.          |
| `unix password sync = yes`     | Synchronize the UNIX password with the SMB password?                  |
| `usershare allow guests = yes` | Allow non-authenticated users to access defined share?                |
| `map to guest = bad user`      | What to do when a user login request doesn't match a valid UNIX user? |
| `browseable = yes`             | Should this share be shown in the list of available shares?           |
| `guest ok = yes`               | Allow connecting to the service without using a password?             |
| `read only = yes`              | Allow users to read files only?                                       |
| `create mask = 0700`           | What permissions need to be set for newly created files?              |
| **Setting**                    | **Description**                                                       |
| `browseable = yes`             | Allow listing available shares in the current share?                  |
| `read only = no`               | Forbid the creation and modification of files?                        |
| `writable = yes`               | Allow users to create and modify files?                               |
| `guest ok = yes`               | Allow connecting to the service without using a password?             |
| `enable privileges = yes`      | Honor privileges assigned to specific SID?                            |
| `create mask = 0777`           | What permissions must be assigned to the newly created files?         |
| `directory mask = 0777`        | What permissions must be assigned to the newly created directories?   |
| `logon script = script.sh`     | What script needs to be executed on the user's login?                 |
| `magic script = script.sh`     | Which script should be executed when the script gets closed?          |
| `magic output = script.out`    | Where the output of the magic script needs to be stored?              |
List #SMB-Shares : `smbclient -N -L //[IP]`
Connect to #SMB server : `smbclient //[IP]/[share]`*

##### #RPC-Client 
```bash
rpcclient -U "" [IP]
```

#bruteforce-rpc-user-rids : `for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done`

| **Query**                 | **Description**                                                    |
| ------------------------- | ------------------------------------------------------------------ |
| `srvinfo`                 | Server information.                                                |
| `enumdomains`             | Enumerate all domains that are deployed in the network.            |
| `querydominfo`            | Provides domain, server, and user information of deployed domains. |
| `netshareenumall`         | Enumerates all available shares.                                   |
| `netsharegetinfo <share>` | Provides information about a specific share.                       |
| `enumdomusers`            | Enumerates all domain users.                                       |
| `queryuser <RID>`         | Provides information about a specific user.                        |
|                           |                                                                    |

#SMBMap list shares : `smbmap -H [IP]`
#crackmapexec : `crackmapexec smb 10.129.14.128 --shares -u '' -p ''`
#enum4linux-ng : `enum4linux-ng [IP] -A`

## NFS - Network File System
|**Version**|**Features**|
|---|---|
|`NFSv2`|It is older but is supported by many systems and was initially operated entirely over UDP.|
|`NFSv3`|It has more features, including variable file size and better error reporting, but is not fully compatible with NFSv2 clients.|
|`NFSv4`|It includes Kerberos, works through firewalls and on the Internet, no longer requires portmappers, supports ACLs, applies state-based operations, and provides performance improvements and high security. It is also the first version to have a stateful protocol.|
#NFS-Config-File : `cat /etc/exports`
```shell
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
```

| **Option**         | **Description**                                                                                                                             |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `rw`               | Read and write permissions.                                                                                                                 |
| `ro`               | Read only permissions.                                                                                                                      |
| `sync`             | Synchronous data transfer. (A bit slower)                                                                                                   |
| `async`            | Asynchronous data transfer. (A bit faster)                                                                                                  |
| `secure`           | Ports above 1024 will not be used.                                                                                                          |
| `insecure`         | Ports above 1024 will be used.                                                                                                              |
| `no_subtree_check` | This option disables the checking of subdirectory trees.                                                                                    |
| `root_squash`      | Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents `root` from accessing files on an NFS mount. |
#NFS-Scan : `sudo nmap [IP] -p111,2049 -sV -sC` / `sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049`

#checkforNFS: `showmount -e [IP]` 

#Access-NFS-Share : `sudo mount -t nfs [IP]:/ ./target-NFS/ -o nolock`

##### NFS

| **Command**                                               | **Description**                                  |
| --------------------------------------------------------- | ------------------------------------------------ |
| `showmount -e <FQDN/IP>`                                  | Show available NFS shares.                       |
| `mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock` | Mount the specific NFS share.umount ./target-NFS |
| `umount ./target-NFS`                                     | Unmount the specific NFS share.                  |

## DNS - Domain Name System

|**Server Type**|**Description**|
|---|---|
|`DNS Root Server`|The root servers of the DNS are responsible for the top-level domains (`TLD`). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain and IP address. The [Internet Corporation for Assigned Names and Numbers](https://www.icann.org/) (`ICANN`) coordinates the work of the root name servers. There are `13` such root servers around the globe.|
|`Authoritative Nameserver`|Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is binding. If an authoritative name server cannot answer a client's query, the root name server takes over at that point.|
|`Non-authoritative Nameserver`|Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying.|
|`Caching DNS Server`|Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage.|
|`Forwarding Server`|Forwarding servers perform only one function: they forward DNS queries to another DNS server.|
|`Resolver`|Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router.|
![[Pasted image 20240808000110.png]]

#DNS-Records 

|**DNS Record**|**Description**|
|---|---|
|`A`|Returns an IPv4 address of the requested domain as a result.|
|`AAAA`|Returns an IPv6 address of the requested domain.|
|`MX`|Returns the responsible mail servers as a result.|
|`NS`|Returns the DNS servers (nameservers) of the domain.|
|`TXT`|This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam.|
|`CNAME`|This record serves as an alias for another domain name. If you want the domain www.hackthebox.eu to point to the same IP as hackthebox.eu, you would create an A record for hackthebox.eu and a CNAME record for www.hackthebox.eu.|
|`PTR`|The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.|
|`SOA`|Provides information about the corresponding DNS zone and email address of the administrative contact.|
#DNS-Config-Local-Files : `cat /etc/bind/named.conf.local`
#DNS-Zone-config-files : `cat /etc/bind/db.domain.com`
`Fully Qualified Domain Name` (`FQDN`)

|**Option**|**Description**|
|---|---|
|`allow-query`|Defines which hosts are allowed to send requests to the DNS server.|
|`allow-recursion`|Defines which hosts are allowed to send recursive requests to the DNS server.|
|`allow-transfer`|Defines which hosts are allowed to receive zone transfers from the DNS server.|
|`zone-statistics`|Collects statistical data of zones.|
#Subdomain-Bruteforce : `for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done`
#DNS-Enum : `dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb`


## SMTP - Simple Mail Transfer Protocol

Default port : 25 / 587

|Client (`MUA`)|`➞`|Submission Agent (`MSA`)|`➞`|Open Relay (`MTA`)|`➞`|Mail Delivery Agent (`MDA`)|`➞`|Mailbox (`POP3`/`IMAP`)|
|---|---|---|---|---|---|---|---|---|
#SMTP-Config-File : `cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"`

|**Command**|**Description**|
|---|---|
|`AUTH PLAIN`|AUTH is a service extension used to authenticate the client.|
|`HELO`|The client logs in with its computer name and thus starts the session.|
|`MAIL FROM`|The client names the email sender.|
|`RCPT TO`|The client names the email recipient.|
|`DATA`|The client initiates the transmission of the email.|
|`RSET`|The client aborts the initiated transmission but keeps the connection between client and server.|
|`VRFY`|The client checks if a mailbox is available for message transfer.|
|`EXPN`|The client also checks if a mailbox is available for messaging with this command.|
|`NOOP`|The client requests a response from the server to prevent disconnection due to time-out.|
|`QUIT`|The client terminates the session.|
#Scanning-SMTP : `sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v`
#Connect-SMTP : `telnet 10.129.14.128 25`
#Bruteforce-SMTP-Usernames : 
```bash 
#!/bin/bash

# Configuration
SMTP_SERVER="10.129.42.195"
WORDLIST="wordlist.txt"

# Read the wordlist and perform VRFY
while IFS= read -r email; do
  echo "Verifying $email..."
  swaks --to "$email" --server "$SMTP_SERVER" --port 25 --h "VRFY: $email" | tee -a results.txt
done < "$WORDLIST"```

## IMAP / POP3 - Internet Message Access Protocol / Post Office Protocol
Ports : 143 / 993


#### IMAP Commands

| **Command**                     | **Description**                                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `1 LOGIN username password`     | User's login.                                                                                                 |
| `1 LIST "" *`                   | Lists all directories.                                                                                        |
| `1 CREATE "INBOX"`              | Creates a mailbox with a specified name.                                                                      |
| `1 DELETE "INBOX"`              | Deletes a mailbox.                                                                                            |
| `1 RENAME "ToRead" "Important"` | Renames a mailbox.                                                                                            |
| `1 LSUB "" *`                   | Returns a subset of names from the set of names that the User has declared as being `active` or `subscribed`. |
| `1 SELECT INBOX`                | Selects a mailbox so that messages in the mailbox can be accessed.                                            |
| `1 UNSELECT INBOX`              | Exits the selected mailbox.                                                                                   |
| `1 FETCH <ID> all`              | Retrieves data associated with a message in the mailbox.                                                      |
| `1 CLOSE`                       | Removes all messages with the `Deleted` flag set.                                                             |
| `1 LOGOUT`                      | Closes the connection with the IMAP server.                                                                   |

#### POP3 Commands

|**Command**|**Description**|
|---|---|
|`USER username`|Identifies the user.|
|`PASS password`|Authentication of the user using its password.|
|`STAT`|Requests the number of saved emails from the server.|
|`LIST`|Requests from the server the number and size of all emails.|
|`RETR id`|Requests the server to deliver the requested email by ID.|
|`DELE id`|Requests the server to delete the requested email by ID.|
|`CAPA`|Requests the server to display the server capabilities.|
|`RSET`|Requests the server to reset the transmitted information.|
|`QUIT`|Closes the connection with the POP3 server.|
#IMAP-POP3-Footprining : `curl -k 'imaps://[IP]' --user user:p4ssw0rd` (-v)
##### IMAP/POP3

| **Command**                                            | **Description**                         |
| ------------------------------------------------------ | --------------------------------------- |
| `curl -k 'imaps://<FQDN/IP>' --user <user>:<password>` | Log in to the IMAPS service using cURL. |
| `openssl s_client -connect <FQDN/IP>:imaps`            | Connect to the IMAPS service.           |
| `openssl s_client -connect <FQDN/IP>:pop3s`            | Connect to the POP3s service.           |
|                                                        |                                         |
|                                                        |                                         |
[Hacktricks for POP3](https://book.hacktricks.xyz/network-services-pentesting/pentesting-pop)

A1 LOGIN robin robin
A1 STATUS DEV.DEPARTMENT.INT (MESSAGES UNSEEN RECENT)
A1 SELECT DEV.DEPARTMENT.INT
A1 UID FETCH 1 (UID RFC822.SIZE BODY.PEEK[])


## SNMP - Simple Network Management Protocol
port 161/162
#SNMP-Config-Files : `cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'`

|**Settings**|**Description**|
|---|---|
|`rwuser noauth`|Provides access to the full OID tree without authentication.|
|`rwcommunity <community string> <IPv4 address>`|Provides access to the full OID tree regardless of where the requests were sent from.|
|`rwcommunity6 <community string> <IPv6 address>`|Same access as with `rwcommunity` with the difference of using IPv6.|

---

---

#### Footprinting the Service

For footprinting SNMP, we can use tools like `snmpwalk`, `onesixtyone`, and `braa`. `Snmpwalk` is used to query the OIDs with their information. `Onesixtyone` can be used to brute-force the names of the community strings since they can be named arbitrarily by the administrator. Since these community strings can be bound to any source, identifying the existing community strings can take quite some time.

Footprint with SNMPWalk
```shell
snmpwalk -v2c -c public [IP]
```
##### SNMP

| **Command**                                       | **Description**                                     |
| ------------------------------------------------- | --------------------------------------------------- |
| `snmpwalk -v2c -c <community string> <FQDN/IP>`   | Querying OIDs using snmpwalk.                       |
| `onesixtyone -c community-strings.list <FQDN/IP>` | Bruteforcing community strings of the SNMP service. |
| `braa <community string>@<FQDN/IP>:.1.*`          | Bruteforcing SNMP service OIDs.                     |

## MySQL  
#Mysql-config-file `cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'`

| **Settings**       | **Description**                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------ |
| `user`             | Sets which user the MySQL service will run as.                                                               |
| `password`         | Sets the password for the MySQL user.                                                                        |
| `admin_address`    | The IP address on which to listen for TCP/IP connections on the administrative network interface.            |
| `debug`            | This variable indicates the current debugging settings                                                       |
| `sql_warnings`     | This variable controls whether single-row INSERT statements produce an information string if warnings occur. |
| `secure_file_priv` | This variable is used to limit the effect of data import and export operations.                              |
| Note 1             | `admin_address` matches for a single admin account                                                           |
| Note 2             | Default admin port is 3302                                                                                   |
Connect to mysql without a password (passwordless accounts) : `mysql -u root -h [IP]`
Connect with password : `mysql -u root -pP4SSw0rd -h [IP]`

#### #SQL-Queries (usefulaf)
| **Command**                                          | **Description**                                                                                       |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `mysql -u <user> -p<password> -h <IP address>`       | Connect to the MySQL server. There should **not** be a space between the '-p' flag, and the password. |
| `show databases;`                                    | Show all databases.                                                                                   |
| `use <database>;`                                    | Select one of the existing databases.                                                                 |
| `show tables;`                                       | Show all available tables in the selected database.                                                   |
| `show columns from <table>;`                         | Show all columns in the selected database.                                                            |
| `select * from <table>;`                             | Show everything in the desired table.                                                                 |
| `select * from <table> where <column> = "<string>";` | Search for needed `string` in the desired table.                                                      |
##### MySQL

|**Command**|**Description**|
|---|---|
|`mysql -u <user> -p<password> -h <FQDN/IP>`|Login to the MySQL server.|

## MsSQL
| Default System Database | Description                                                                                                                                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `master`                | Tracks all system information for an SQL server instance                                                                                                                                               |
| `model`                 | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database |
| `msdb`                  | The SQL Server Agent uses this database to schedule jobs & alerts                                                                                                                                      |
| `tempdb`                | Stores temporary objects                                                                                                                                                                               |
| `resource`              | Read-only database containing system objects included with SQL server                                                                                                                                  |
|                         |                                                                                                                                                                                                        |
|                         |                                                                                                                                                                                                        |
**footprinting the service** : `sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 [IP]`

w/ metasploit : `auxiliary/scanner/mssql/mssql_ping`

##### MSSQL

|**Command**|**Description**|
|---|---|
|`mssqlclient.py <user>@<FQDN/IP> -windows-auth`|Log in to the MSSQL server using Windows authentication.|
## Oracle TNS - Oracle Transparent Network Substrate (TNS)

|**Setting**|**Description**|
|---|---|
|`DESCRIPTION`|A descriptor that provides a name for the database and its connection type.|
|`ADDRESS`|The network address of the database, which includes the hostname and port number.|
|`PROTOCOL`|The network protocol used for communication with the server|
|`PORT`|The port number used for communication with the server|
|`CONNECT_DATA`|Specifies the attributes of the connection, such as the service name or SID, protocol, and database instance identifier.|
|`INSTANCE_NAME`|The name of the database instance the client wants to connect.|
|`SERVICE_NAME`|The name of the service that the client wants to connect to.|
|`SERVER`|The type of server used for the database connection, such as dedicated or shared.|
|`USER`|The username used to authenticate with the database server.|
|`PASSWORD`|The password used to authenticate with the database server.|
|`SECURITY`|The type of security for the connection.|
|`VALIDATE_CERT`|Whether to validate the certificate using SSL/TLS.|
|`SSL_VERSION`|The version of SSL/TLS to use for the connection.|
|`CONNECT_TIMEOUT`|The time limit in seconds for the client to establish a connection to the database.|
|`RECEIVE_TIMEOUT`|The time limit in seconds for the client to receive a response from the database.|
|`SEND_TIMEOUT`|The time limit in seconds for the client to send a request to the database.|
|`SQLNET.EXPIRE_TIME`|The time limit in seconds for the client to detect a connection has failed.|
|`TRACE_LEVEL`|The level of tracing for the database connection.|
|`TRACE_DIRECTORY`|The directory where the trace files are stored.|
|`TRACE_FILE_NAME`|The name of the trace file.|
|`LOG_FILE`|The file where the log information is stored.|
**recon TNS** : `sudo nmap -p1521 -sV [IP] --open` / `sudo nmap -p1521 -sV [IP] --open --script oracle-sid-brute`
TNS def port : 1521

┌──(fuzti㉿FuztiTower)-[~]
└─$ sqlplus scott/tiger@10.129.205.19/XE as sysdba


## IPMI

Port : 623
Proto : UDP
Basic V. enum : `sudo nmap -sU --script ipmi-version -p 623`
V. enum MSF : `use auxiliary/scanner/ipmi/ipmi_version`
MSF Dump hashes : `use auxiliary/scanner/ipmi/ipmi_dumphashes`





----------------


General cheat sheet

## Infrastructure-based Enumeration

|**Command**|**Description**|
|---|---|
|`curl -s https://crt.sh/\?q\=<target-domain>\&output\=json \| jq .`|Certificate transparency.|
|`for i in $(cat ip-addresses.txt);do shodan host $i;done`|Scan each IP address in a list using Shodan.|

---

## Host-based Enumeration

##### FTP

|**Command**|**Description**|
|---|---|
|`ftp <FQDN/IP>`|Interact with the FTP service on the target.|
|`nc -nv <FQDN/IP> 21`|Interact with the FTP service on the target.|
|`telnet <FQDN/IP> 21`|Interact with the FTP service on the target.|
|`openssl s_client -connect <FQDN/IP>:21 -starttls ftp`|Interact with the FTP service on the target using encrypted connection.|
|`wget -m --no-passive ftp://anonymous:anonymous@<target>`|Download all available files on the target FTP server.|

##### SMB

|**Command**|**Description**|
|---|---|
|`smbclient -N -L //<FQDN/IP>`|Null session authentication on SMB.|
|`smbclient //<FQDN/IP>/<share>`|Connect to a specific SMB share.|
|`rpcclient -U "" <FQDN/IP>`|Interaction with the target using RPC.|
|`samrdump.py <FQDN/IP>`|Username enumeration using Impacket scripts.|
|`smbmap -H <FQDN/IP>`|Enumerating SMB shares.|
|`crackmapexec smb <FQDN/IP> --shares -u '' -p ''`|Enumerating SMB shares using null session authentication.|
|`enum4linux-ng.py <FQDN/IP> -A`|SMB enumeration using enum4linux.|

##### NFS

|**Command**|**Description**|
|---|---|
|`showmount -e <FQDN/IP>`|Show available NFS shares.|
|`mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock`|Mount the specific NFS share.umount ./target-NFS|
|`umount ./target-NFS`|Unmount the specific NFS share.|

##### DNS

|**Command**|**Description**|
|---|---|
|`dig ns <domain.tld> @<nameserver>`|NS request to the specific nameserver.|
|`dig any <domain.tld> @<nameserver>`|ANY request to the specific nameserver.|
|`dig axfr <domain.tld> @<nameserver>`|AXFR request to the specific nameserver.|
|`dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld>`|Subdomain brute forcing.|

##### SMTP

|**Command**|**Description**|
|---|---|
|`telnet <FQDN/IP> 25`||

##### IMAP/POP3

|**Command**|**Description**|
|---|---|
|`curl -k 'imaps://<FQDN/IP>' --user <user>:<password>`|Log in to the IMAPS service using cURL.|
|`openssl s_client -connect <FQDN/IP>:imaps`|Connect to the IMAPS service.|
|`openssl s_client -connect <FQDN/IP>:pop3s`|Connect to the POP3s service.|

##### SNMP

|**Command**|**Description**|
|---|---|
|`snmpwalk -v2c -c <community string> <FQDN/IP>`|Querying OIDs using snmpwalk.|
|`onesixtyone -c community-strings.list <FQDN/IP>`|Bruteforcing community strings of the SNMP service.|
|`braa <community string>@<FQDN/IP>:.1.*`|Bruteforcing SNMP service OIDs.|

##### MySQL

|**Command**|**Description**|
|---|---|
|`mysql -u <user> -p<password> -h <FQDN/IP>`|Login to the MySQL server.|

##### MSSQL

|**Command**|**Description**|
|---|---|
|`mssqlclient.py <user>@<FQDN/IP> -windows-auth`|Log in to the MSSQL server using Windows authentication.|

##### IPMI

|**Command**|**Description**|
|---|---|
|`msf6 auxiliary(scanner/ipmi/ipmi_version)`|IPMI version detection.|
|`msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)`|Dump IPMI hashes.|

##### Linux Remote Management

|**Command**|**Description**|
|---|---|
|`ssh-audit.py <FQDN/IP>`|Remote security audit against the target SSH service.|
|`ssh <user>@<FQDN/IP>`|Log in to the SSH server using the SSH client.|
|`ssh -i private.key <user>@<FQDN/IP>`|Log in to the SSH server using private key.|
|`ssh <user>@<FQDN/IP> -o PreferredAuthentications=password`|Enforce password-based authentication.|

##### Windows Remote Management

|**Command**|**Description**|
|---|---|
|`rdp-sec-check.pl <FQDN/IP>`|Check the security settings of the RDP service.|
|`xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP>`|Log in to the RDP server from Linux.|
|`evil-winrm -i <FQDN/IP> -u <user> -p <password>`|Log in to the WinRM server.|
|`wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>"`|Execute command using the WMI service.|

##### Oracle TNS

|**Command**|**Description**|
|---|---|
|`./odat.py all -s <FQDN/IP>`|Perform a variety of scans to gather information about the Oracle database services and its components.|
|`sqlplus <user>/<pass>@<FQDN/IP>/<db>`|Log in to the Oracle database.|
|`./odat.py utlfile -s <FQDN/IP> -d <db> -U <user> -P <pass> --sysdba --putFile C:\\insert\\path file.txt ./file.txt`
|Upload a file with Oracle RDBMS.|

=======================================

# Remote Management Protocols Cheat Sheet

## Dashboard
- **Modules**
- **Paths**

---

## Footprinting

### Linux Remote Management Protocols

#### **SSH (Secure Shell)**

- **Port:** TCP 22
- **Protocols:** SSH-1, SSH-2
- **Key Authentication Methods:**
  - Password Authentication
  - Public Key Authentication
  - Host-based Authentication
  - Keyboard Authentication
  - Challenge-Response Authentication
  - GSSAPI Authentication
- **Public Key Authentication:**
  - Server verifies client via encrypted certificate.
  - Client uses a private key (secured with a passphrase) to authenticate.
- **Default Configuration:**
  - `ChallengeResponseAuthentication no`
  - `UsePAM yes`
  - `X11Forwarding yes`
  - `PrintMotd no`
  - `AcceptEnv LANG LC_*`
  - `Subsystem sftp /usr/lib/openssh/sftp-server`
- **Dangerous Settings:**
  - `PasswordAuthentication yes`
  - `PermitEmptyPasswords yes`
  - `PermitRootLogin yes`
  - `Protocol 1`
  - `X11Forwarding yes`
  - `AllowTcpForwarding yes`
  - `PermitTunnel`
  - `DebianBanner yes`
- **Fingerprinting Tools:**
  - **SSH-Audit:**
    ```bash
    git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
    ./ssh-audit.py [IP]
    ```

#### **Rsync**

- **Port:** TCP 873
- **Features:**
  - Delta-transfer algorithm
  - Used for backups and mirroring
  - Can be configured to use SSH
- **Scanning for Rsync:**
  ```bash
  sudo nmap -sV -p 873 [IP]
  ```
- **Probing Accessible Shares:**
  ```bash
  nc -nv [IP] 873
  rsync -av --list-only rsync://[IP]/[share]
  ```

#### **R-Services**

- **Ports:** 512, 513, 514
- **Commands:**
  - `rcp` - Remote copy (Port 514)
  - `rsh` - Remote shell (Port 514)
  - `rexec` - Remote execution (Port 512)
  - `rlogin` - Remote login (Port 513)
- **Access Control:**
  - **/etc/hosts.equiv**
  - **.rhosts**
- **Scanning for R-Services:**
  ```bash
  sudo nmap -sV -p 512,513,514 [IP]
  ```

#### **Examples**

- **Rsync Command Example:**
  ```bash
  rsync -av rsync://[IP]/[share]
  ```

- **Rlogin Command Example:**
  ```bash
  rlogin [IP] -l [username]
  ```

- **Rwho Command Example:**
  ```bash
  rwho
  ```

- **Rusers Command Example:**
  ```bash
  rusers -al [IP]
  ```

---

## Final Thoughts
- **Remote management services can be exploited for unauthorized access.**
- **Probe services thoroughly for potential vulnerabilities and configuration issues.** 


## Footprinting

### Windows Remote Management Protocols

Windows servers can be managed locally using Server Manager administration tasks or remotely. Remote management is enabled by default starting with Windows Server 2016 and includes a service that implements the WS-Management protocol, hardware diagnostics, and control through baseboard management controllers. It also offers a COM API and script objects for remote communication through WS-Management.

The main components used for remote management of Windows and Windows servers are:

- **Remote Desktop Protocol (RDP)**
- **Windows Remote Management (WinRM)**
- **Windows Management Instrumentation (WMI)**

---

### Remote Desktop Protocol (RDP)

**Overview:**  
The Remote Desktop Protocol (RDP) developed by Microsoft allows remote access to a Windows computer. It transmits display and control commands over IP networks with encryption. RDP typically uses TCP port 3389, though UDP port 3389 can also be used.

**Firewall and NAT Considerations:**  
To establish an RDP session, both the network firewall and the server firewall must permit connections. If NAT is used, the remote computer needs the public IP address, and port forwarding must be configured.

**Security:**  
Since Windows Vista, RDP supports Transport Layer Security (TLS/SSL), which protects data, including the login process, through encryption. However, many systems still accept inadequate encryption and use self-signed certificates that may cause certificate warnings.

**Default Settings:**  
Remote Desktop service is installed by default on Windows servers and can be activated through Server Manager. By default, it allows connections only to hosts with Network Level Authentication (NLA).

**Footprinting the Service:**  
Scanning the RDP service with tools like Nmap can reveal useful information about the host, including NLA status, product version, and hostname.

**Example Nmap Commands:**
```bash
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
```
This command detects the RDP service and its settings.

**RDP Security Check:**  
A Perl script `rdp-sec-check.pl` can be used to identify the security settings of RDP servers based on handshakes.

**Installation and Usage:**
```bash
sudo cpan
cpan[1]> install Encoding::BER
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl 10.129.201.248
```

**Connecting to RDP:**
```bash
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
```
*Note:* You may encounter certificate warnings due to mismatched or self-signed certificates.

---

### Windows Remote Management (WinRM)

**Overview:**  
WinRM is a command-line protocol that uses SOAP for remote connections. It relies on TCP ports 5985 (HTTP) and 5986 (HTTPS), with HTTPS being used more frequently for security.

**Footprinting the Service:**  
You can scan for WinRM using Nmap to check if the ports are open:
```bash
nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```

**PowerShell Command:**
```powershell
Test-WsMan -ComputerName <hostname>
```

**Linux Tool - Evil-WinRM:**
```bash
evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
```

---

### Windows Management Instrumentation (WMI)

**Overview:**  
WMI is Microsoft's implementation of the Common Information Model (CIM) and allows comprehensive read and write access to Windows settings. It is critical for administration in Windows environments.

## Footprinting the Service

The initialization of the WMI communication always takes place on `TCP` port `135`, and after the successful establishment of the connection, the communication is moved to a random port. For example, the program [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) from the Impacket toolkit can be used for this.

#### WMIexec.py

Windows Remote Management Protocols

```shell-session
ADNSecurity@htb[/htb]$ /usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
ILF-SQL-01
```

Again, it is necessary to mention that the knowledge gained from installing these services and playing around with the configurations on our own Windows Server VM for gaining experience and developing the functional principle and the administrator's point of view cannot be replaced by reading manuals. Therefore, we strongly recommend setting up your own Windows Server, experimenting with the settings, and scanning these services repeatedly to see the differences in the results.