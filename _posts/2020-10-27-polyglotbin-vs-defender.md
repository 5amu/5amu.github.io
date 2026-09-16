---
title: "PolyglotBin vs Windows Defender"
description: "Tests whether Windows Defender detects malware (netcat, a keylogger, plink, PwDump) hidden inside binary polyglots — PDF, ZIP, ISO, TAR, RAR, 7z, ARJ, PCAP — built with Ange Albertini's mitra tool; a few combinations evaded detection entirely."
categories: [red, research]
---

Yesterday I saw this video from [LiveOverflow](https://twitter.com/liveoverflow):

{% include video.html id="VVdmmN0su6E" %}

Then, I was interested in seeing if antivirus software could detect an instance of binary polyglots in a Windows system.

So I generated 8 binaries (.7z, .arj, .iso, .pcap, .pdf, .rar, .tar, .zip) to combine with 4 generally considered malicious by antiviruses: (nc.exe, klogger.exe, plink64.exe and PwDump.exe), then I ran [mitra.py](https://github.com/corkami/mitra) combining every exe with every generic binary. The final set of test files was ready, and the great MS Windows Defender warm and in position.

Initially, I copied just the original exe files, and Windows Defender managed to detect (and with some delay, automatically delete) all threats! Kudos... I guess.

Then, I copied all of the polyglots and ran a full scan on the folder. Out of 44 combinations (including the original exe files), 19 survived, given that plink64 is not seen by Windows Defender as a big enough threat to automatically remove it. Running a fresh full scan on those survivors, our beautiful tool actually managed to detect them as a Trojan!

Let's delete the busted binaries and the plink64 files (which aren't necessarily a threat), and run the test again: unfortunately, we are busted once more (I had renamed `nc.exe.pdf` back to `nc.exe` for testing). Even though `nc.exe.arj` was no longer in the folder, I deleted every busted file and ran a new test. This time it was definitive, and a small handful of polyglots survived every scan.

It was fun and educational. Thanks to LiveOverflow and [Ange Albertini](https://github.com/angea) for the research and developing of mitra.
