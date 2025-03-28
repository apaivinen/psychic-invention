

## Description

This query over Azure Active Directory sign-in considers all user sign-ins for each Azure Active Directory application and picks out the most anomalous change in location profile for a user within an individual application.

An alert is generated for recent sign-ins that have location counts that are anomalous over last day but also over the last 3-day and 7-day periods.

Please note that on workspaces with larger volume of Signin data (~10M+ events a day) may timeout when using this default query time period. It is recommended that you test and tune this appropriately for the workspace.

### Tactics:

- Initial Access - The adversary is trying to get into your network.

### Techniques:

- T1078 - [Valid Accounts, Technique T1078 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1078/)

## Steps to investigate

Check SigninLogs last 3 - 7 days 

- Usually the user is targeted by a botnet previously, and later signs in successfully from multiple IPs

Check that all successful sign-ins are trusted. Good indicators:

- Location looks right
- Domain joined device
- Clean IP ([VirusTotal - Home](https://www.virustotal.com/gui/home/search))
- MFA satisfied

## Useful KQL

  
**SigninLogs**
```
SigninLogs 
| where UserPrincipalName contains "test1@.com" //change email
| extend displayName_ = tostring(DeviceDetail.displayName) , OS = tostring(DeviceDetail.operatingSystem), AppDisplayName 
| project displayName_,OS,AppDisplayName,IPAddress,TimeGenerated,ResultType,AuthenticationRequirement,ResultDescription,LocationDetails,UserPrincipalName,DeviceDetail
| sort by TimeGenerated asc
```

## Example comments

Example 1

> Several users was targeted by a botnet trying to authenticate to their accounts. All successful sign-ins came from Norway. User test1@innofactor.com had successful sign-ins from Sweden, using domain-joined device "LAPTOP-12345" where MFA was satisfied and clean IP. Not malicious.

Example 2

>   

## Steps to remediate

  

|ID|Mitigation|Description|
|---|---|---|
|[M1036](https://attack.mitre.org/mitigations/M1036)|[Account Use Policies](https://attack.mitre.org/mitigations/M1036)|Use conditional access policies to block logins from non-compliant devices or from outside defined organization IP ranges.|
|[M1015](https://attack.mitre.org/mitigations/M1015)|[Active Directory Configuration](https://attack.mitre.org/mitigations/M1015)|Disable legacy authentication, which does not support MFA, and require the use of modern authentication protocols instead.|
|[M1013](https://attack.mitre.org/mitigations/M1013)|[Application Developer Guidance](https://attack.mitre.org/mitigations/M1013)|Ensure that applications do not store sensitive data or credentials insecurely. (e.g. plaintext credentials in code, published credentials in repositories, or credentials in public cloud storage).|
|[M1027](https://attack.mitre.org/mitigations/M1027)|[Password Policies](https://attack.mitre.org/mitigations/M1027)|Applications and appliances that utilize default username and password should be changed immediately after the installation, and before deployment to a production environment. When possible, applications that use SSH keys should be updated periodically and properly secured.<br><br>Policies should minimize (if not eliminate) reuse of passwords between different user accounts, especially employees using the same credentials for personal accounts that may not be defended by enterprise security resources.|
|[M1026](https://attack.mitre.org/mitigations/M1026)|[Privileged Account Management](https://attack.mitre.org/mitigations/M1026)|Audit domain and local accounts as well as their permission levels routinely to look for situations that could allow an adversary to gain wide access by obtaining credentials of a privileged account. These audits should also include if default accounts have been enabled, or if new local accounts are created that have not be authorized. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.|
|[M1018](https://attack.mitre.org/mitigations/M1018)|[User Account Management](https://attack.mitre.org/mitigations/M1018)|Regularly audit user accounts for activity and deactivate or remove any that are no longer needed.|
|[M1017](https://attack.mitre.org/mitigations/M1017)|[User Training](https://attack.mitre.org/mitigations/M1017)|Applications may send push notifications to verify a login as a form of multi-factor authentication (MFA). Train users to only accept valid push notifications and to report suspicious push notifications.|
