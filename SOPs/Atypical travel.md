

## Description

Sign-in from an atypical location based on the user’s recent sign-ins

This risk detection type identifies two sign-ins originating from geographically distant locations, where at least one of the locations may also be atypical for the user, given past behavior. The algorithm takes into account multiple factors including the time between the two sign-ins and the time it would have taken for the user to travel from the first location to the second. This risk may indicate that a different user is using the same credentials. ref: [What are risks in Microsoft Entra ID Protection | Microsoft Learn](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)

### Tactics:

- Initial Access - The adversary is trying to get into your network.

### Techniques

## Steps to investigate

1. If you're able to confirm the activity wasn't performed by a legitimate user:
    1. **Recommended action**: Mark the sign-in as compromised, and invoke a password reset if not already performed by self-remediation. Block user if attacker has access to reset password or perform MFA and reset password.
2. If a user is known to use the IP address in the scope of their duties:
    1. **Recommended action**: Dismiss the alert
3. If you're able to confirm that the user recently travelled to the destination mentioned detailed in the alert:
    1. **Recommended action**: Dismiss the alert.
4. If you're able to confirm that the IP address range is from a sanctioned VPN.
    1. **Recommended action**: Mark sign-in as safe and add the VPN IP address range to named locations in Azure AD and Microsoft Defender for Cloud Apps.

## Useful KQL
```
SigninLogs
| where UserId contains "87410-312345" //Change AadUserId from the alert
| extend displayName_ = tostring(DeviceDetail.displayName) , OS = tostring(DeviceDetail.operatingSystem), AppDisplayName
| project displayName_,OS,AppDisplayName,IPAddress,TimeGenerated,ResultType,AuthenticationRequirement,ResultDescription,LocationDetails,UserPrincipalName,DeviceDetail
| sort by TimeGenerated asc
// Uncomment the line below to only get successful sign-ins
//| where ResultType == 0
```

## Example comments
