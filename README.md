# Zimbra Weak Password Scanner

Weak password list can be fetched from https://github.com/danielmiessler/SecLists .

**Note**: This script consume a lot of CPU so don't to run this script while peak hours and we suggest to run this script separately out side Zimbra server.


## Installing

- Clone repository
```sh
git clone https://github.com/iomarmochtar/zmbr_weakpwd_scanner
```

- Change current directory to main directory
```
cd zmbr_weakpwd_scanner
```

- Install all requirements using pip command
```
pip install -r requirements.txt
```

## Using the Script

Requiring zimbra ldap password, use following command to show it (as zimbra user)
```sh
zmlocalconfig -s zimbra_ldap_password
```

Here's the arguments for this script

| name   |         long    | required | desc |    default |
|--------|-----------------|----------|---------|---------------|
|   -p   | --password-list |    Y     | Password file    | |
|   -r   | --result-file   |    Y     | LDAP url eg: ldap://ldap.someserver.com:389, use ldaps for ssl connection       |  |
|   -r   | --result-file   |    N     | Dump result to file |   /tmp/weak_user_passwd.txt  |
|   -s   | --show-password |    N     | Show weak password when it found   |  |
|   -b   | --ldap-basedn   |    N     | LDAP BaseDN, if not provide then all user will be scan     | |
|   -d   | --ldap-bind     |    N     | LDAP Bind Admin | uid=zimbra,cn=admins,cn=zimbra |
|   -f   | --ldap-filter   |    N     | LDAP Filter     | (&(objectClass=zimbraAccount)(!(zimbraIsSystemAccount=TRUE))(!(zimbraIsSystemResource=TRUE))) |


see it in action.
<img src="http://i.imgur.com/ZGzbQDO.gif">