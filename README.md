<img width="500" height="500" alt="500px-Firefox_logo,_2019 svg" src="https://github.com/user-attachments/assets/ea39d605-0fd6-471e-9638-7e4105fa2c82" />



# Threat Hunt Report: Unauthorized Firefox Usage
- [Scenario Creation](https://github.com/jaredliverpool/threat-hunting-scenario-firefox/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

Management Directive:
Recently, cybersecurity news highlighted multiple zero-day vulnerabilities in Firefox that were actively being exploited in the wild. Management requested a proactive hunt to ensure employees are not installing or using unauthorized browsers (specifically Firefox) that may bypass corporate security policies and lead to data exfiltration or phishing attacks.


### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "Firefox Setup" in it and discovered what looks like the user "labuser" downloaded a Firefox installer, did something that resulted in a Firefox downloader being copied to the desktop.These events began at `2025-09-17T23:14:51.0026622Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "jaredthreat"
| where FileName startswith "Firefox Setup"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessCommandLine
```
<img width="1705" height="195" alt="Screenshot 2025-09-18 at 4 33 27 PM" src="https://github.com/user-attachments/assets/ad810d0b-cc48-45cb-a35a-0dcb9459b170" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "Firefox Setup 143.0.exe". Based on the logs returned, at `2025-09-18T00:59:14.924904Z`, an employee on the "jaredthreat" device ran the file `Firefox Setup 143.0.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "jaredthreat"
| where ProcessCommandLine contains "Firefox Setup" and ProcessCommandLine contains "/S"
| project Timestamp, AccountName DeviceName, ActionType, FileName, ProcessCommandLine
```
<img width="873" height="64" alt="Screenshot 2025-09-18 at 4 40 15 PM" src="https://github.com/user-attachments/assets/991a7fd8-c392-4eaa-adad-61273bb3f92e" />


---

### 3. Searched the `DeviceProcessEvents` Table for Firefox Browser Execution

Searched for any indication that user "labuser" actually opened the Firefox browser. There was evidence that they did open it at `2025-09-18T00:59:14.924904Z`. There were several other instances of `firefox.exe` afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "jaredthreat"
| where ProcessCommandLine contains "Firefox Setup" and ProcessCommandLine contains "/S"
| project Timestamp, AccountName DeviceName, ActionType, FileName, ProcessCommandLine
```
<img width="866" height="69" alt="Screenshot 2025-09-18 at 4 42 08 PM" src="https://github.com/user-attachments/assets/cd4fa11e-7889-4c55-b8fc-4f204e0b842c" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the Firefox browser was used to establish a connection using any ports At `2025-09-17T23:22:52.3475604Z`, an employee on the "jaredthreat" device successfully established a connection to the remote IP address `35.190.72.216` on port `443`. The connection was initiated by the process `firefox.exe`, located in the folder `c:\program files\mozilla firefox\firefox.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "jaredthreat"
| where InitiatingProcessFileName =~ "firefox.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
<img width="1623" height="298" alt="Screenshot 2025-09-18 at 5 08 16 PM" src="https://github.com/user-attachments/assets/b255fd05-f01d-491a-90b7-93c4f625ee02" />


---

## Chronological Event Timeline 

### 1. File Download - Firefox Installer

- **Timestamp:** `2025-09-17T23:14:51.0026622Z`
- **Event:** The user "labuser" downloaded a file named Firefox Setup 143.0.exe to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\Firefox Setup 143.0.exe`

### 2. Process Execution - Firefox Silent Installation

- **Timestamp:** `2025-09-18T00:59:14.924904Z`
- **Event:** The user "labuser" executed the file Firefox Setup 143.0.exe in silent mode, initiating a background installation of the Firefox browser.
- **Action:** Process creation detected.
- **Command:** `"C:\Users\employee\Downloads\Firefox Setup 143.0.exe" /S`
- **File Path:** `C:\Users\employee\Downloads\Firefox Setup 143.0.exe`

### 3. Process Execution - Firefox Browser Launch

- **Timestamp:** `2025-09-18T01:00:21.3747712Z`
- **Event:** The user "labuser" launched Firefox, resulting in the creation of the firefox.exe process, confirming that the browser was successfully installed and executed.
- **Action:** Process creation detected.
- **File Path:** `C:\Program Files\Mozilla Firefox\firefox.exe`

### 4. Network Connection - Firefox Activity

- **Timestamp:** `2025-09-18T14:16:12.522399Z`
- **Event:** A network connection to IP 34.104.35.123 on port 443 by user "labuser" was established using firefox.exe, confirming Firefox browser network activity.
- **Action:** Connection success.
- **Process:** `firefox.exe`
- **File Path:** `C:\Program Files\Mozilla Firefox\firefox.exe`

### 5. Additional Network Connections - Firefox Browsing Timestamps

- **Timestamps:**
  - `2025-09-18T01:00:33.2713177Z` - Connected to `13.35.107.117` on port `443`.
  - `2025-09-18T01:00:12.1931184Z` - Local connection to `146.75.31.19` on port `443`.
- **Event:** Additional Firefox network connections were established, indicating browsing activity by user "labuser" through the unauthorized browser.
- **Action:** Multiple successful connections detected.

---

## Summary

The user "labuser" on the "jaredthreat" device initiated and completed the installation of the Firefox browser using a silent installation method. The browser was launched successfully, and subsequent network activity confirmed that Firefox was actively used for browsing both legitimate and suspicious domains. This activity demonstrates that the user actively installed, configured, and used Firefox outside of corporate-approved software guidelines.

---

## Response Taken

TTOR usage was confirmed on endpoint jaredthreat. The device was isolated and the user's direct manager was notified.

---
