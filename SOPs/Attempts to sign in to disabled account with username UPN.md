

## Description

Identifies failed attempts to sign in to disabled accounts across multiple Azure Applications. Default threshold for Azure Applications attempted to sign in to is 3._ 

### Tactics:

- Initial Access - The adversary is trying to get into your network.

### Techniques

- T1078 - [Valid Accounts, Technique T1078 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1078/)

## Steps to investigate

Check AADNonInteractiveUserSigninLogs or SigninLogs, (Depends on what Type of sign-in was attempted. Provided in the alert)

Usually when an account is disabled there are still applications running in the background trying to authenticate, so non-interactive sign-ins are expected for some time after account is disabled.

If a user tries to interactively authenticate, it could be suspicious

Check AuditLogs to see when the account was disabled

If we get repeated sign-in attempts from the same user, we can recommend the customer to look into weather the devices should still be registered/joined.

## Useful KQL
AADNonInteractiveUserSignInLogs
```
AADNonInteractiveUserSignInLogs 
| where UserPrincipalName contains "test1@.com" // Change email 
| extend DeviceName = tostring(parse_json(DeviceDetail).displayName) 
| project DeviceName, UserPrincipalName, IPAddress, TimeGenerated, ResultDescription, LocationDetails, AppDisplayName, AuthenticationRequirement, ResultType, DeviceDetail
```

SigninLogs
```
SigninLogs 
| where UserPrincipalName contains  "test1@.com" // Change email  
| extend displayName_ = tostring(DeviceDetail.displayName) , OS = tostring(DeviceDetail.operatingSystem), AppDisplayName 
| project displayName_,OS,AppDisplayName,IPAddress,TimeGenerated,ResultType,AuthenticationRequirement,ResultDescription,LocationDetails,UserPrincipalName,DeviceDetail
| sort by TimeGenerated asc
```

AuditLogs
```
AuditLogs 
| where OperationName contains "Disable account" 
| where TargetResources[0].userPrincipalName contains  "test1@.com" // Change email
```

## Example comments

Example 1


## Steps to remediate
  

|Mitigation|Description|
|---|---|
|[Account Use Policies](https://attack.mitre.org/mitigations/M1036)|Use conditional access policies to block logins from non-compliant devices or from outside defined organization IP ranges.|
|[Active Directory Configuration](https://attack.mitre.org/mitigations/M1015)|Disable legacy authentication, which does not support MFA, and require the use of modern authentication protocols instead.|
|[Application Developer Guidance](https://attack.mitre.org/mitigations/M1013)|Ensure that applications do not store sensitive data or credentials insecurely. (e.g. plaintext credentials in code, published credentials in repositories, or credentials in public cloud storage).|
|[Password Policies](https://attack.mitre.org/mitigations/M1027)|Applications and appliances that utilize default username and password should be changed immediately after the installation, and before deployment to a production environment. When possible, applications that use SSH keys should be updated periodically and properly secured.<br><br>Policies should minimize (if not eliminate) reuse of passwords between different user accounts, especially employees using the same credentials for personal accounts that may not be defended by enterprise security resources.|
|[Privileged Account Management](https://attack.mitre.org/mitigations/M1026)|Audit domain and local accounts as well as their permission levels routinely to look for situations that could allow an adversary to gain wide access by obtaining credentials of a privileged account. These audits should also include if default accounts have been enabled, or if new local accounts are created that have not be authorized. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.|
|[User Account Management](https://attack.mitre.org/mitigations/M1018)|Regularly audit user accounts for activity and deactivate or remove any that are no longer needed.|
|[User Training](https://attack.mitre.org/mitigations/M1017)|Applications may send push notifications to verify a login as a form of multi-factor authentication (MFA). Train users to only accept valid push notifications and to report suspicious push notifications.|
