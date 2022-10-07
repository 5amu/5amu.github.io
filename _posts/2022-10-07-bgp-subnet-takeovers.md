---
image: https://xtom.com/icon/bgp.png
categories: [pentest,research]
---

> Sometimes, during security assessments and penetration tests an in-depth 
> analysis of the Autonomous Systems security posture and BGP routes is 
> overlooked. Here's my deep dive into a long forgotten protocol on which
> the internet is built upon.

## Nameservers and the Domain Name System

A nameserver is a server that hosts a DNS ([Domain Name System](https://www.cloudflare.com/learning/dns/what-is-dns/)), 
which is an application that runs on the nameserver responsible for translating
(resolving) human readable names (such as `www.example.com`) to the 
corresponding IP address(es) associated with it.

> For semplicity sake, in this article we will consider IPv4 only, but the can
> be applied to IPv6 as the process is exacly the same for the most part.

This is a simplified overview, but this is not the place to discuss this 
topic in more details, please do your own research.

![Very good scheme](/assets/img/bgp-subnet-takeover-schema-internet.png)

<p align="right">Image credits: <a href="https://twitter.com/manekinekko">@manekinekko</a></p>

## Autonomous Systems

To provide a more comprehensive assessment of DNS zones for every nameserver in
scope, the idea was to provide some edge case example that could invalidate at 
least one implemented security measure. Let's analyze the process:

1. A name server is asked an IP corresponding to the domain requested. (eg:`example.com`)
2. The nameserver, which has an IP itself, answers the request.
    ```bash
    # Example request to example.com to Google's DNS (ns.google.com)
    # the answer is: example.com has IP 93.184.216.34
    $ dig example.com +noall +answer @ns.google.com
    example.com.		83860	IN	A	93.184.216.34
    ```
3. The client who asked for the IP address simply visits the IP address and trusts the DNS.

In this process, the validity of the IP address is never questioned. Is there a
security measure to guarantee that that IP address will really bring me to the
legitimate `example.com`? 

> Short answer: **there is, but not everyone implements it**.

When an IP has to be routed to the correct server the entire world, in the
context of public internet, relies on massive public and private owned routers
that send the received requests to the hopefully intended next-hop. 

These massive routers and relative subnets are called 
[Autonomous Systems](https://www.cloudflare.com/learning/network-layer/what-is-an-autonomous-system/).

![Very good scheme](/assets/img/bgp-subnet-takeover-asn.png)

<p align="right">Image credits: <a href="https://www.cloudflare.com/learning/network-layer/what-is-an-autonomous-system/">Cloudflare</a></p>

## The Border Gateway Protocol

Bastion routers implement BGP ([Border Gateway Protocol](https://www.cloudflare.com/learning/security/glossary/what-is-bgp/))
because internet is a network of networks, or a network of autonomous systems.

![Very good scheme](/assets/img/bgp-subnet-takeover-net-of-nets.png)

<p align="right">Image credits: <a href="https://www.cloudflare.com/learning/security/glossary/what-is-bgp/">Cloudflare</a></p>

BGP is the protocol that allows gateways to know where to send a packet when
a certain IP address is requested. Typically, the smallest range of public IPs
that a border gateway running BGP can advertise is a 
[C class](https://www.meridianoutpost.com/resources/articles/IP-classes.php)
address range, having at least 254 IPs in the network.

> A powerful computer (BGP router), placed inside an important datacenter,
> could theoretically start to advertise subnets that should not be handled by
> it. One could configure a computer with the purpose of effectively stealing
> a company routes.

![Very good scheme](/assets/img/bgp-subnet-takeover-hijacking.png)

BGP has not a secure method to establish if a particular server is authorized
to present itself with a particular IP address, that is why it is so important
that the ones responsible for an IP address make sure that the subnets are
advertised correctly. This is done using workarounds to make the protocol secure.

The most effective workaround is [RPKI](https://en.wikipedia.org/wiki/Resource_Public_Key_Infrastructure)
(Resource Public Key Infrastructure) to extend the [IRR](https://www.irr.net/)
(Internet Routing Registry). Basically, RPKI is a cryptographically signed
entry associated with a route prefix and an autonomous system. To trust a route
coming from an autonomous system, a BGP router should check if the RPKI is
signed from the correct entity, if the autonomous system has the correct
number and if it is authorized to advertise that route. A practical example
with `google.com`:

```bash
$ dig google.com              
...
google.com.		99	IN	A	142.250.184.4
...

$ whois 142.250.184.46                                                                                               
...
NetRange:       142.250.0.0 - 142.251.255.255
CIDR:           142.250.0.0/15
NetName:        GOOGLE
...
OriginAS:       AS15169
...
```

One RPKI Validator: [https://rpki.cloudflare.com/?view=validator](https://rpki.cloudflare.com/?view=validator)

![Very good scheme](/assets/img/bgp-subnet-takeover-rpki.png)

Failing to configure this entry to validate the advertised routes might result
in an accidental, or intentional 
[BGP Hijacking](https://www.cloudflare.com/learning/security/glossary/bgp-hijacking/),
which has major consequences for businesses and government infrastructures,
some examples are:

* 2022 [Twitter traffic ... tunneled through Russian ISP ...](https://arstechnica.com/information-technology/2022/03/absence-of-malice-russian-isps-hijacking-of-twitter-ips-appears-to-be-a-goof/)
* 2022 [KlaySwap crypto users lose funds after BGP hijack](https://therecord.media/klayswap-crypto-users-lose-funds-after-bgp-hijack/)
* 2017 [Popular Destinations rerouted to Russia](https://www.bgpmon.net/popular-destinations-rerouted-to-russia/)
* 2016 [Large hijack affects reachability of high traffic destinations](https://www.bgpmon.net/large-hijack-affects-reachability-of-high-traffic-destinations/)
* 2015 [Large scale BGP hijack out of India](https://www.bgpmon.net/large-scale-bgp-hijack-out-of-india/)

## Exploit RPKI Misconfigurations
While this is a theoretical exercise, it would be absolutely possible to
exploit an unsigned route to effectively steal a subnet for a short amount
of time, which sometimes is enough to deal much damage to a business.

Kenneth Finnegan is a (legendary) engineer who made an exercise, as an
individual, to set up and deploy a BGP router borrowing some IP addresses from
a friend and demonstrating how it would be possible (and sort of easy) to start
being an autonomous system with a border gateway. His journey is described in 
[this blog post](https://blog.thelifeofkenneth.com/2017/11/creating-autonomous-system-for-fun-and.html).

Looking at this information with the eyes of a very motivated threat actor,
possibly state sponsored, it would be trivial to exploit this unsecured opening
to unleash all kinds of attacks: credential stealing, fund stealing, social
engineering, service denial, man in the middle attacks... etcetera. 

## Conclusions
While state owned assets are not usually misconfigured, many critical
businesses are. A BGP misconfiguration might lead to a brutal denial of service
in the best case, but in a consistent loss of funds AND a denial of service in
the worst case.   

Many businesses are vulnerable. Many are not exploited because they never had a
motivated and knowledgeable attacker that was willing to risk this kind of attack.
