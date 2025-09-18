# Threat Event (Unauthorized Firefox Usage)
**Unauthorized Firefox Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the Firefox browser installer: https://www.firefox.com/en-US/?redirect_source=mozilla-org
2. Install it silently: ```"Firefox Setup 143.0.exe"/S```
3. Opens the Firefox browser from the folder on the desktop
4. Connect to Firefox and browse a few sites. For example:
   - **WARNING: The links to onion sites change a lot and these have changed. However if you connect to Tor and browse around normal sites a bit, the necessary logs should still be created:**
   - ```https://safebrowsing.googleapis.com```
   - ```ciscobinary.openh264.org```
   - ```https://www.mozilla.orgelysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login```


---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting Firefox download and installation. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of Firefox as well as the Firefox browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect Firefox network activity, specifically firefox.exe making connections over ports to be used by Firefox (443).|

---

## Related Queries:
```kql
// Installer name == Firefox Setup 143.0.exe
// Detect the installer being downloaded
DeviceFileEvents
| where DeviceName == "jaredthreat"
| where FileName startswith "Firefox Setup"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessCommandLine

// Firefox Browser being silently installed
// Take note of two spaces before the /S (I don't know why)
DeviceProcessEvents
| where DeviceName == "jaredthreat"
| where ProcessCommandLine contains "Firefox Setup" and ProcessCommandLine contains "/S"
| project Timestamp, AccountName DeviceName, ActionType, FileName, ProcessCommandLine

// Firefox Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where DeviceName == "jaredthreat"
| where FileName has "firefox.exe"
| project Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// Firefox Browser or service was launched
DeviceProcessEvents
| where DeviceName == "jaredthreat"
| where ProcessCommandLine has "firefox.exe"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Firefox Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where DeviceName == "jaredthreat"
| where InitiatingProcessFileName =~ "firefox.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, InitiatingProcessFolderPath, RemotePort, RemoteUrl
| order by Timestamp desc 

```

---

## Created By:
- **Author Name**: Jared Liverpool
- **Author Contact**: https://www.linkedin.com/in/jaredliverpool/
- **Date**: September 17, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `September  17, 2025`  | `Jared Liverpool`   
