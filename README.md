# SOC Project: Windows RDP Exposure Investigation

![SOC Badge](https://img.shields.io/badge/SOC-Project-blue) ![Security Badge](https://img.shields.io/badge/Security-Analysis-green) ![Windows Badge](https://img.shields.io/badge/Platform-Windows-orange)

## Platforms and Languages Leveraged
- **Platforms:** Microsoft Defender for Endpoint, Windows Server, Azure Network Security Groups (NSG)  
- **Languages/Scripts:** KQL


## Scenario
This project simulates a Security Operations Center (SOC) investigation focused on a Windows server exposed to the internet with Remote Desktop Protocol (RDP) open on port 3389. The investigation monitored failed and successful login attempts, analyzed remote IP activity, and implemented security measures to prevent unauthorized access.

### Objective
- Identify brute force attempts and unauthorized access to internet-facing systems.  
- Correlate logon activity with threat intelligence.  
- Mitigate risk by hardening exposed endpoints and enforcing security policies.  

## Steps Taken
1. **Identify Internet-Facing Host**  
   Queried device inventory to find systems with public-facing ports.
    ```kql
   DeviceInfo
   | where DeviceName == "windows-target-1"
   | where IsInternetFacing == True 
   | sort by Timestamp desc
   ```
      ![Incident Timeline](screenshots/screenshot1)
   - Last internet-facing timestamp: **Oct 21, 2025 6:14:29 AM**  
------------------------------------
2. **Analyze Failed Login Attempts**
   ```kql
   DeviceLogonEvents
    | where DeviceName == "windows-target-1"
    | where ActionType == "LogonFailed"
    | where isnotempty(RemoteIP)
    | summarize Attempts = count() by ActionType,RemoteIP, DeviceName
    | order by Attempts desc
    ```
      ![Incident Timeline](screenshots/screenshot2)
   - Aggregated failed logon events over the last 7 days to identify brute force attempts. Top 10 suspicious IPs were identified attempting repeated logins.
------------------------------------
3. **Verify Successful Logins**  
   Checked for any successful logins from suspect IPs.
      ```kql
   let SuspectRemoteIPs = dynamic(["85.208.84.187","143.110.169.74","194.180.49.103","57.129.140.32","162.243.203.54","175.143.2.185","31.57.97.186","159.100.20.23","180.100.208.89","85.215.203.219"]);
    DeviceLogonEvents
    | where DeviceName == "windows-target-1"
    | where LogonType has_any ("Interactive","Network","Unlock","RemoteInteractive")
    | where ActionType == "LogonSuccess"
    | where RemoteIP has_any (SuspectRemoteIPs)
      ```
   - **Result:** No successful logins from any of the top 10 suspicious IPs in the last 7 days.  
------------------------------------
4. **Review General Activity**  
   Analyzed successful logins over the past 30 days to detect anomalies.
      ```kql
    DeviceLogonEvents
    | where Timestamp > ago(30d)
    | where DeviceName == "windows-target-1"
    | where ActionType == "LogonSuccess"
      ```
   ![Incident Timeline](screenshots/screenshot3)
   - **Result:** 12 local interactive logins; no unusual activity detected.
------------------------------------
5. **Map to MITRE ATT&CK TTPs**  
   - **T1595.001 - Active Scanning:** Attackers scanned public IP ranges to discover exposed RDP services.  
   - **T1133 - External Remote Services (RDP):** Attempts to gain access to a system through exposed RDP on port 3389.  
   - **T1110 - Brute Force:** Repeated login attempts using guessed or stolen credentials to gain unauthorized access.
------------------------------------
6. **Incident Response**  
   - Hardened NSG rules to allow RDP only from specific endpoints.  
   - Implemented account lockout policy.  
   - Enforced Multi-Factor Authentication (MFA) for all accounts accessing the host.
------------------------------------
## Chronological Event Timeline
<details>
<summary>Click to expand timeline</summary>

| Time | Event |
|------|-------|
| Oct 21, 2025 6:14 AM | `windows-target-1` confirmed internet-facing with RDP open |
| Oct 21-27, 2025 | Multiple failed login attempts from top 10 suspicious IPs |
| Oct 21-27, 2025 | Verified zero successful logins from suspicious IPs |
| Oct 21-27, 2025 | Reviewed past 30 days: 12 local interactive logins; no anomalies |
| Oct 27, 2025 | Applied NSG hardening, account lockout policy, and MFA |

</details>

## Summary of Findings
- The Windows server `windows-target-1` was exposed to the internet with RDP open.  
- Multiple brute force attempts were detected from external IPs.  
- No successful breaches or unauthorized access were observed.  
- Local login activity was normal with no unusual patterns.  
- MITRE ATT&CK mapping identified relevant TTPs: scanning, external RDP exploitation, and brute force attempts.

## Response Actions Taken
- Hardened network access through NSG rules to restrict RDP traffic.  
- Implemented account lockout policy to prevent brute force attacks.  
- Enforced Multi-Factor Authentication (MFA) for all accounts accessing the host.  
- Documented the investigation, findings, and updated SOC playbooks.






