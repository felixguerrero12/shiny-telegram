# Goal
Detect irregularities in the remote desktop protocol authentication where an actor is attempting to obtain a user's password by trial-and-error.

# Categorization
These attempts are categorized as [Credential Access / Brute Force](https://attack.mitre.org/techniques/T1110/).

# Strategy Abstract
The strategy will function as follows:

* Collect Windows Event Logs related to Active Directory Login Authentication. 
* Alert on any anomalies authentication requests. 

# Technical Context
Windows Event Logs provides a numerous amount of logs related to the Active Directory environment. Two logs that go hand on hand is 4624 and 4625 which are counterparts to authentication in a Window's environment. This method requires Logon Type 10 to identify authentication to the Remote Desktop Protocol, RDP.

When configured correctly, AD Domain Controllers will record Event IDs for authentication requests. The following event IDs are of interest for this ADS: 

|Event Code|Description|
|----------|-----------|
4624|An account was successfully logged on.
4625|An account failed to log on.

# Blind Spots and Assumptions
This strategy relies on the following assumptions:
* SIEM is successfully indexing logon authentication events.
* The DCs are correctly forwarding the group change events to WEF servers.
* Event auditing is disabled.
 
A blind spot will occur if any of the assumptions are violated. For instance, the following would not trip the alert:
* Windows event logging breaks.
* Authentication requests is made slow enough to bypass time-based detection logic.
* Authentication requests is not above the threshold for detection logic.

# False Positives
There are several instances where false positives for this ADS could occur:
* Legitimate user attempts to login multiple times hitting the threshold after being locked out from his account.
* Automated scripts misconfigured after password change.

# Priority
The priority is set to high under the following conditions:
* One or more authentication is successful for a user after a non-standard amount of Event ID 4625 with Logon Type 10 occur.

The priority is set to medium under the following conditions:
* Non-standard amount of Event ID 4625 with Logon Type 10 and Status Code 0xC000006A (user name is correct but the password is wrong
).

The priority is set to low under the following conditions:
* Non-standard amount of Event ID 4625 with Logon Type 10

# Validation
Validation can occur for this ADS by performing the following execution on a linux host with hydra installed:

```
hydra -t 1 -V -f -l administrator -P wordlist.txt rdp://10.0.0.1
``` 

This validation scenario will attempt to authenticate to the 10.0.0.1 host using the password list wordlist.txt. This should enumerate a large amount of Event ID 4625 triggering a detection for Window RDP Bruteforce.

# Response
In the event that this alert fires, the following response procedures are recommended:
* Validate where the authentication requests are coming from.
  * If authentication requests are coming from an external source network address and not successful, add firewall rule to block remote desktop from external.
  * If authentication requests are coming from an external source network address and successful, escalate to a security incident.
  * If authentication requests are coming from an internal source network address and not successful, track down the user making the requests.

* Validate if there is a change management ticket or announcement for the internal source network address authentication requests. 
  * If the user is unaware of the activity, escalate to a security incident.
  * If there is no change management ticket or announcement, contact the user who is making these requests.


# Additional Resources
* [4624: An account was successfully logged on](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624)
* [4625: An account failed to log on](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4625)
* [THREAT HUNTING FOR INTERNAL RDP BRUTE FORCE ATTEMPTS](https://sqrrl.com/threat-hunting-internal-rdp-brute-force-attempts/)
