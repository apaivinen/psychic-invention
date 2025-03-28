## Description

The "Admin promotion after Role Management Application Permission Grant" detection identifies scenarios where an administrative account is promoted shortly after a role management application permission is granted. This activity may signal a malicious actor exploiting permissions to escalate privileges or gain unauthorized administrative control. Such incidents should be investigated to confirm whether the activity was authorized or part of an attack.

### Tactics:
- **Privilege Escalation** - The adversary is trying to gain higher-level permissions.
- **Persistence** - The adversary is trying to maintain their foothold.

### Techniques:
- **T1078** - [Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- **T1098** - [Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- **T1548.002** - [Abuse Elevation Control Mechanism: Bypass User Access Control](https://attack.mitre.org/techniques/T1548/002/)

---

## Steps to investigate

1. **Validate the Alert**
   - Confirm the details of the role management application permission grant and the subsequent admin promotion.
   - Review the Azure AD Audit Logs for activity timelines.

2. **Identify the Context**
   - Determine who initiated the role management application permission grant.
   - Identify the account that was promoted and its associated permissions.

3. **Verify the Source**
   - Cross-check the IP address, device information, and location of the activity.
   - Check for any anomalies, such as IPs or devices not commonly associated with the organization.

4. **Review Related Activities**
   - Investigate additional activities performed by the promoted account, such as:
     - Sign-ins.
     - Role assignments or changes.
     - Resource access or modifications.

5. **Check for Related Alerts**
   - Look for other alerts involving the same account or source within the same timeframe.
   - Investigate any alerts related to suspicious application behavior or privilege escalation.

6. **Validate Justification**
   - Confirm whether the activity was authorized. Check with the relevant administrator or team if necessary.

---

## Useful KQL

## Example comments

### Example 1:

> Account: `john.doe@contoso.com` was granted permissions to the "Role Management Application" at 2:15 PM and was promoted to a Global Administrator role at 2:45 PM. Activity originated from IP `192.168.1.100`, which is not a registered corporate IP. The account also accessed Azure portal shortly after promotion. Recommend further investigation.

### Example 2:

> Account: `admin.temp@contoso.com` was promoted to "Billing Administrator" shortly after a role management application permission grant. Actions seem to originate from a known IP `10.10.1.20`, and no suspicious activities were detected afterward. Considered authorized but recommend documenting the incident.

### Example 3:

> Temporary admin account `tempadmin@contoso.com` was promoted from "User" to "Privileged Role Administrator" after an application permission grant. The IP address used (`203.0.113.10`) belongs to an unfamiliar location. Recommend immediate review of account activity and IP investigation.

---

## Steps to remediate

1. **Contain and Investigate**
    
    - Immediately suspend the account if unauthorized promotion is suspected.
    - Investigate all activities performed by the account after the promotion.
2. **Audit Permissions**
    
    - Review permissions granted to the role management application and validate their necessity.
    - Revoke any unnecessary or suspicious permissions.
3. **Enable Conditional Access**
    
    - Implement conditional access policies to limit access based on location, device compliance, and risk level.
4. **Implement MFA**
    
    - Ensure multi-factor authentication (MFA) is enforced for all administrative actions.
5. **Review Admin Role Assignments**
    
    - Regularly audit administrative role assignments to detect unauthorized changes.