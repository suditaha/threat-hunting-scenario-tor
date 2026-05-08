# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/suditaha/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the `DeviceFileEvents` table for any file that had the string “tor” in it and discovered what looks like the user `suditaha` downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-04-24T22:32:39.5057162Z`. These events began at `2026-04-24T21:28:59.5704809Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "tor"
| where DeviceName == "onboarding"
| where InitiatingProcessAccountName == "suditaha"
| where Timestamp >= datetime(2026-04-24T21:28:59.5704809Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the `DeviceProcessEvents` table for any `ProcessCommandLine` that contained the string `tor-browser-windows-x86_64-portable-15.0.10.exe`.

Based on the logs returned, at `2026-04-24T21:37:24.6466049Z`, an employee on the `onboarding` device ran the file `tor-browser-windows-x86_64-portable-15.0.10.exe` from their Downloads folder using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "onboarding"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.10.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table for any indication that user `suditaha` actually opened the TOR browser.

There was evidence that they opened it at `2026-04-24T21:37:50.9353631Z`. Several additional instances of `firefox.exe` (TOR) and `tor.exe` were also spawned afterward.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "onboarding"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the `DeviceNetworkEvents` table for any indication the TOR browser was used to establish a connection over known TOR ports.

On `2026-04-24T21:49:47.9142061Z`, the device `onboarding` successfully established an outbound connection initiated by the user `suditaha` through `tor.exe`.

The connection originated from:

```text
C:\Users\suditaha\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
```

It connected to remote IP `88.99.2.111` on port `9001` and accessed the URL:

```text
https://www.7fhjgi7lbkmtwipwwgckhs3j.com
```

Additional outbound TOR-related connections were also observed.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "onboarding"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP,
RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

# Chronological Event Timeline

## 1. File Download / TOR-Related File Activity

- **Timestamp:** `2026-04-24T21:28:59.5704809Z`
- **Event:** The user `suditaha` downloaded a file named `tor-browser-windows-x86_64-portable-15.0.10.exe` to the Downloads folder on the device `onboarding`.
- **Action:** File download detected.
- **File Path:** `C:\Users\suditaha\Downloads\tor-browser-windows-x86_64-portable-15.0.10.exe`

## 2. Process Execution – TOR Browser Installation

- **Timestamp:** `2026-04-24T21:37:24.6466049Z`
- **Event:** The user `suditaha` executed the file `tor-browser-windows-x86_64-portable-15.0.10.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.10.exe /S`
- **File Path:** `C:\Users\suditaha\Downloads\tor-browser-windows-x86_64-portable-15.0.10.exe`

## 3. Process Execution – TOR Browser Launch

- **Timestamp:** `2026-04-24T21:37:50.9353631Z`
- **Event:** User `suditaha` opened the TOR browser on the device `onboarding`. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\suditaha\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

## 4. Network Connection – TOR Network Activity

- **Timestamp:** `2026-04-24T21:49:47.9142061Z`
- **Event:** A network connection to IP `88.99.2.111` on port `9001` by user `suditaha` on the device `onboarding` was established using `tor.exe`, confirming TOR browser network activity. The connection also accessed the URL `https://www.7fhjgi7lbkmtwipwwgckhs3j.com`.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\suditaha\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

## 5. Additional Network Connections – TOR Browser Activity

- **Timestamp:** Following `2026-04-24T21:49:47.9142061Z`
- **Event:** Additional TOR-related outbound network connections were established, including connections over port `9001` and port `443`, indicating continued TOR browsing activity by user `suditaha` on the device `onboarding`.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
