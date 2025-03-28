## Description

Detects anomalous IP address usage by user accounts and then checks to see if a suspicious Teams action is performed.

Query calculates IP usage Delta for each user account and selects accounts where a delta >= 90% is observed between the most and least used IP.

To further reduce results the query performs a prevalence check on the lowest used IP's country, only keeping IP's where the country is unusual for the tenant (dynamic ranges)

Finally the user accounts activity within Teams logs is checked for suspicious commands (modifying user privileges or admin actions) during the period the suspicious IP was active.

  

### Tactics:

- Initial Access - The adversary is trying to get into your network.
- Persistence - The adversary is trying to maintain their foothold.

### Techniques:

- T1199 - [Trusted Relationship, Technique T1199 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1199/)
- T1136 - [Create Account, Technique T1136 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1136/)
- T1078 - [Valid Accounts, Technique T1078 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1078/)
- T1098 - [Account Manipulation, Technique T1098 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1098/)

## Steps to investigate

Check SigninLogs and get an understanding of why it is considered an anomalous login (Usually the rule triggers when a user has traveled)

Teams action can be just opening a teams chat, can be verified in OfficeActivity

Check if the IP is clean ([VirusTotal - Home](https://www.virustotal.com/gui/home/search))

## Useful KQL
SignInLogs
```
SigninLogs 
| where UserPrincipalName contains "test1@.com" //change email
| extend displayName_ = tostring(DeviceDetail.displayName) , OS = tostring(DeviceDetail.operatingSystem), AppDisplayName 
| project displayName_,OS,AppDisplayName,IPAddress,TimeGenerated,ResultType,AuthenticationRequirement,ResultDescription,LocationDetails,UserPrincipalName,DeviceDetail
| sort by TimeGenerated asc
```

OfficeActivity
```
OfficeActivity 
| where Operation in~ ("TeamsAdminAction", "MemberAdded", "MemberRemoved", "MemberRoleChanged", "AppInstalled", "BotAddedToTeam") 
| where UserId contains "test1@.com" //change email
```

## Example comments
