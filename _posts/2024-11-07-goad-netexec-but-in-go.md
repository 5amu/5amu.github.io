---
title: "GoAD: NetExec, But in Go"
description: "Progress notes on GoAD, my from-scratch Go rewrite of NetExec/CrackMapExec's core: SMB command execution, LDAP enumeration and writes, and Kerberos attacks, built by stitching together protocol libraries that Go simply doesn't have as a single package."
categories:
  - dev
  - ad
image: /assets/img/goad_logo.png
---
> **Update, April 2026:** [mandiant/gopacket](https://github.com/mandiant/gopacket) just dropped — a complete Go port of impacket, 63 CLI tools and 24 libraries, single dependency-free binary. Everything I hand-rolled below to fill that exact gap is now more or less redundant 🙂. Leaving the post up as a record of the "before" times.

If you've ever done an internal AD pentest, [NetExec](https://github.com/Pennyw0rth/NetExec) (the [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) fork that keeps it alive) is probably the second thing you open after `nmap`. Spray creds across a subnet, pop a shell over SMB, dump LDAP, kerberoast — one tool, one Python venv, done.

I've been staring at that codebase for a while thinking "this would be so much nicer as a single static binary", so a few months ago I started [GoAD](https://github.com/5amu/gonetexec/) — a learning project to rebuild the same core loop (auth against a target, then *do something* to it) in Go.

## This one broke me a little

The pitch sounds simple: "execute a command on a remote Windows machine." In Python this is a solved problem, `impacket` gives you SMB, MSRPC, Kerberos and NTLM all wired together already. In Go, there is no `impacket`. There's a decent SMB client here, a partial NTLM implementation there, nothing that speaks MS-RPCE, and nothing that ties them together the way you need to actually authenticate, open a named pipe, bind to a DCE/RPC interface and drive it.

So `pkg/` ended up as its own little impacket-in-miniature:

- `pkg/auth/providers/ntlm` — NTLMv2 negotiate/challenge/authenticate, written by hand
- `pkg/kclient` — a Kerberos client (AS-REQ/AS-REP, TGS-REQ/TGS-REP) for kerberoasting and AS-REP roasting
- `pkg/dcerpc` — MSRPC bind/request over named pipes, plus `scmr.go` implementing enough of [MS-SCMR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a3-e2454b330ee5) (`RCreateServiceW`, `RStartServiceW`, `RDeleteService`, ...) to create and run a service remotely
- `pkg/encoder` — because none of the above have a native Go wire format, this hand-rolls UTF-16LE and UUID (mis)marshaling

None of these exist as reusable Go packages elsewhere (or didn't when I went looking), so most of the "development" was really reverse-engineering wire captures and cross-checking against the MS-SMB2/MS-RPCE/MS-SCMR specs. Help is wanted (and kinda needed) if anyone wants to make any of this less broken.

## What actually works

The CLI is one binary, one subcommand per protocol:

```bash
go install -v "github.com/5amu/goad/cmd/goad@latest"
```

```go
// cmd/goad/main.go
ftp   "Own stuff using FTP"
ldap  "Own stuff using LDAP"
krb5  "Own stuff using KERBEROS"
smb   "Own stuff using SMB"
ssh   "Own stuff using SSH"
vnc   "Own stuff using VNC"
// mssql, rdp, winrm, wmi: wip / disabled — winrm in particular got ripped
// out again after fighting with it for a day
```

**`smb -x`** is the one I actually cared about getting right — command execution the old psexec/smbexec way: open the `C$` share, talk MSRPC over `\PIPE\svcctl`, `RCreateServiceW` a service pointing at `cmd.exe /c <command>`, start it, read the output back, clean up.

```go
Shares bool   `long:"shares" description:"list open shares"`
Exec   string `short:"x" long:"exec" description:"execute a command by creating a service via RPC"`
Client bool   `long:"client" description:"Open a client to the remote machine"`
```

**`ldap`** ended up more fully-featured than I expected going in — full UAC-flag filtering (`--trusted-for-delegation`, `--dont-require-preauth`, `--password-never-expires`, ...), `--gmsa` password retrieval, `--add-computer`/`--del-computer`, and the two I wanted since the [nuclei AD module post]({% post_url 2024-02-06-nuclei-can-now-speak-ad %}):

```go
Hashes struct {
    AsrepRoast string `long:"asreproast" description:"Grab AS_REP ticket(s) parsed to be cracked with hashcat"`
    Kerberoast string `long:"kerberoast" description:"Grab TGS ticket(s) parsed to be cracked with hashcat"`
} `group:"Hash Retrieval Options" description:"Hash Retrieval Options"`
```

**`krb5`** does username enumeration by abusing `KDC_ERR_PREAUTH_REQUIRED` vs. "no such principal" AS-REQ responses, plus credential bruteforcing in clusterbomb or pitchfork mode. There's also an early `--responder` mode hiding behind a "(testing)" label in the help text that just captures NTLM hashes off the wire — nowhere near Responder-the-tool, but the skeleton is there.

Everything routes through the standard proxy env vars, so `export ALL_PROXY="socks5://127.0.0.1:1080"` is enough to run the whole thing through a pivot without any extra flags.

## Closing thoughts

This is very much a "still in heavy development, don't expect production-grade anything" project — I broke SMB support at least twice this month alone rewriting the encoder. But the fact that `smb -x` reliably gets a shell on a domain-joined box using nothing but the standard library and a handful of hand-written protocol packages feels like a good milestone to write down. If you know Go and have ever been curious about what's actually inside MS-RPCE, [the repo](https://github.com/5amu/gonetexec/) could use the company 🙂.
