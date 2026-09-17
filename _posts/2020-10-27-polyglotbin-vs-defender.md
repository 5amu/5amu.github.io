---
title: "PolyglotBin vs Windows Defender"
description: "Tests whether Windows Defender detects malware (netcat, a keylogger, plink, PwDump) hidden inside binary polyglots — PDF, ZIP, ISO, TAR, RAR, 7z, ARJ, PCAP — built with Ange Albertini's mitra tool; a few combinations evaded detection entirely."
categories: [red, research]
thumbnail: /assets/img/polyglot_icon.png
---

Yesterday I saw this video from [LiveOverflow](https://twitter.com/liveoverflow):

{% include video.html id="VVdmmN0su6E" %}

Then, I was interested in seeing if antivirus software could detect an instance of binary polyglots in a Windows system.

So I generated 8 binaries (.7z, .arj, .iso, .pcap, .pdf, .rar, .tar, .zip) to combine with 4 generally considered malicious by antiviruses: (nc.exe, klogger.exe, plink64.exe and PwDump.exe), then I ran [mitra.py](https://github.com/corkami/mitra) combining every exe with every generic binary. The final set of test files was ready, and the great MS Windows Defender warm and in position.

Initially, I copied just the original exe files, and Windows Defender managed to detect (and with some delay, automatically delete) all threats! Kudos... I guess.

Then, I copied all of the polyglots and ran a full scan on the folder. Here's the results:

![image-20201027144220581](/assets/img/image-20201027144220581.png)

Out of 44 combinations (including the original exe files), these 19 survived! Given that plink64 is not seen by Windows Defender as a big enough threat to automatically remove it. Let's see what our beautiful tool says about these files with a full scan.

![image-20201027144457859](/assets/img/image-20201027144457859.png)

It actually managed to detect them as a Trojan! Let's delete the busted binaries, plink64 files (which aren't necessary a threat) and run the test again:

![image-20201027150041736](/assets/img/image-20201027150041736.png)

Unfortunately, we are busted again (I renamed nc.exe.pdf to nc.exe for testing). Even if nc.exe.arj was not in the folder, I deleted every busted file and ran a new test. Now it's definitive:

![image-20201027150435954](/assets/img/image-20201027150435954.png)

Here they are... the survivors:

![image-20201027150523251](/assets/img/image-20201027150523251.png)

It was fun and educational. Thanks to LiveOverflow and [Ange Albertini](https://github.com/angea) for the research and developing of mitra.
