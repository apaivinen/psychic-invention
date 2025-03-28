## Description

The "Account Created and Deleted in Short Timeframe" detection identifies instances where a user account is created and subsequently deleted within a 24-hour period. This activity may indicate malicious behavior, as attackers could create temporary accounts for their operations and delete them to cover their tracks. Investigating such alerts is critical to ensure no unauthorized actions were taken while the account was active.

### Tactics:

- **Persistence** - The adversary is trying to maintain their foothold.
- **Defense Evasion** - The adversary is trying to avoid detection.

### Techniques:

- **T1078** - [Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- **T1136** - Create Account

---

## Steps to investigate

1. **Validate the Alert**
    
    - Confirm the account creation and deletion event from the logs.
    - Cross-check timestamps to ensure the events occurred within the specified timeframe.
2. **Gather Context**
    
    - Identify the source of the account creation event (e.g., Azure AD, on-prem AD, or other).
    - Check who created the account and from where (IP address, device details, or admin portal).
3. **Determine Potential Usage**
    
    - Check if the account performed any actions during its existence:
        - Logged into systems or services.
        - Modified resources (files, configurations, etc.).
        - Triggered other alerts.
4. **Corroborate with Related Alerts**
    
    - Look for other alerts or anomalies that occurred around the same timeframe:
        - Failed or successful sign-ins.
        - Suspicious file access or modification events.
        - Network activity anomalies.
5. **Assess the Account’s Lifecycle**
    
    - Review Azure AD or Active Directory audit logs for the full lifecycle of the account.
    - Search for any other temporary accounts created by the same user or system.
6. **Review Permissions**
    
    - Identify the permissions assigned to the account. High-privilege accounts are particularly concerning.

---

## Useful KQL

[[AuditWhenWasAccountDisabled]]

```
PLACEHOLDER 
Rule to look within timegap of created to deleted
```
---

## Example comments

### Example 1:

---

## Steps to remediate

1. **Isolate and Investigate**
    
    - Isolate any affected systems or accounts associated with suspicious activity.
    - Perform a thorough investigation of all related activities.
2. **Enhance Audit Trails**
    
    - Enable detailed logging for account management activities in Azure AD or AD.
    - Implement alerts for short-lived accounts.
3. **Implement Account Controls**
    
    - Enforce stricter controls on who can create and delete accounts.
    - Require approval for account deletion within a short timeframe.
4. **Review and Apply Security Measures**
    
    - Evaluate the use of privileged accounts and ensure just-in-time (JIT) access is enabled for administrators.
    - Apply network restrictions and monitor for unusual IP activity.
5. **Educate Administrators**
    
    - Train IT staff to follow best practices for account management.
    - Highlight risks of temporary accounts and the need to document any such activity.
6. **Apply Mitigations for Related Techniques**
    
    - T1078 - [Valid Accounts](https://attack.mitre.org/techniques/T1078/)
    - T1136 - Create Account