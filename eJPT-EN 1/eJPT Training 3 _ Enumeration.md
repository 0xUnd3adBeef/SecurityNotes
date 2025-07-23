# SMB Enum
### Mount SMB :
- `net use [letter]: \\[remoteSMBip]\[remotesmbdrive]$ [smbpassword] /user:[username]`
### Enumerate SMB 
- To list versions of SMB / NT LM use :  `nmap -p[smbPort] --script smb-protocols [vcip]` 
- To check security options : `nmap -p[smbPort] --scrip smb-security-mode [vcip]`
- To verify what users are logged in / disponible use `nmap -p[smbPort] --script smb-enum-sessions [vcip]
- This may take a while but you can enumerate SMB share basically with the `smb-enum-shares` script
- Verify the server state with `smb-server-stats` 
- To enumerate users groups use the `smb-enum-groups` script
- To enumerate SMB services running use `smb-enum-groups` 
- To list shares use `smb-enum-shares,smb-ls` 
- Note : Certain of these scripts requirent you to use script args with `--script-args`  the script args can be : `smbusername=[smbuser],smbpassword=[smbpass]` and lot more.
### SMBmap (finally!)
- To list shares on an SMB server use `smbmap -u [smbUser] -p "[smbpass]" -d [domain] -H [vcip]` 
- To download file use `--download [remotefile] [localfile]`
- To upload file use `--upload [localfile] [remotefile]`
- To run a command on the remote system use `-x "[command]"` 
- `man smbmap` for more.
### SMBclient  
- `smbclient //[vcip]/[smbshare] -N` to access a share without password.
### RPCClient
- To try logging in SMB with a null session use `rpcclient -U "" -N [vcip]` 
-  `enumdomusers` is to list domain users
- get more info about users listed with `lookupnames [username]`
### Enum4Linux (infinite power!)
- Get os info : `enum4linux -o [vcip]`
- super cool command : `enum4linux [vcip]`

# no more SMB 
### Hydra 
- use `hydra -l [username] -P [wordlist] [vcip] [protocol]` to bruteforce passwords of a certain protocol.

### SSH (Not So Easy)
- To fetch SSH Banner use : `nc [vcip]`
- To check "encryption algorithms" supported by remote host : `nmap --script ssh2-enum-algos` 
- To see the ssh hostkey of the remote host `nmap --script ssh-hostkey --script-args ssh_hostkey=full`
- To check auth methods supported by user : `nmap --script ssh-auth-methods --script-args="ssh.user=[user]" [vcip]` 

### FTP (that cool door)
- You always must check for FTP Anonymous session
- I recommend anyone to list users with [this](https://pentestmonkey.net/tools/user-enumeration/ftp-user-enum) 
- You can perform an SSH bruteforce with `nmap --script ssh-brute --script-args userdb=/path/to/userdb [vcip]`  Note  : userdb can be a txt file with 1 user / line.
- You can use the `ssh_login` module in Metasploit.

## HTTP :)
### HTTP IIS
- Obtain info about the remote IIS server with Whatweb : `whatweb [vcip]`
- Use Dirbuster to discover disponible directories based on a wordlist : `dirb http://[vcip]`
- Enumerate potentially cool pages on the site :  `nmap --script http-enum -sV -p[srvport] [vcip]`
- Get headers with `nmap --script http-headers -sV -p[srvport] [vcip]` 
- Check supported methods with : `nmap --script http-methods --script-args http-methods.url-path=/[urpage]/ [vcip]`
- To check if Webdav is really installed use : `nmap --script http-webdav-scan --script-args http-methods.url-path=/webdav/ [vcip]`

# MySQL :o
- To connect onto MySQL database use : `mysql -h [vcip] -u [username]` 
- To show databases on MySQL server use `show databases;` 
- To make a database your working directory do : `use [database.name]`
- To display how many elements are present in a database use `select count(*) from [db.name];` 
- To show all the elements present in a database use : `select * from [db.name]`
- To load file from the host system use : `select load_file("[filepath]")`
- To check if there are users with empty password use : `nmap --script=mysql-empty-password [vcip]` 
- You can bruteforce MySQL with : `hydra -l [username] -P [wordlist] [vcip] mysql`
- Default port is 3306

# MSSQL :O
- To get (more) info about MSSQL use : `nmap --script ms-sql-info [vcip]`
- Default port is 1433
- To get NT LM info use `nmap [vcip] -p [mssqlport] --script ms-sql-ntlm-info --script-args mssql.instance-port=[mssqlport]`
- To bruteforce that service use `nmap [vcip] -p[mysqlport] --script ms-sql-brute --script-args userdb=[path/to/txt/file/with/users],passdb=[same/but/with/passwords]` 
- To check for empty passwords use the `--script ms-sql-empty-password` 
- To run a query on the database (authenticated query) use : `nmap [vcip] -p[mssqlport] --script ms-sql-query --script-args mssql.username=[username],mssql.password=[password],ms-sql-query.query="[your query (ex : SELECT * FROM master..syslogins)]"`
- Dump hashes using `nmap [vcip] -p[mssqlport] --script ms-sql-dump-hashes --script args mssql.username=[user],mssql.password=[password]` 
- To run a command (like powershell / CMD) use `nmap [vcip] -p[mssqlport] --script ms-sql-xp-cmdshell --script-args mssql.username=[username],mssql.password=[password],ms-sql-xp-cmdshell.cmd="[yoursystemcommand]"`
- Bruteforce with metasploit using the `auxiliary/scanner/mssql/mssql_login` module and setting the correct options :)
- Take useful info from the target service with `auxiliary/admin/mssql/mssql_enum` module, you should specify a password.
- [see more](https://assets.ine.com/labs/ad-manuals/walkthrough-2314.pdf) 