## Detection Queries

#### 1. Failed Windows Logon (Event ID 4625)
`index=main LogName=Security EventCode=4625
| timechart span=5m count`

---

#### 2. Top Targeted User Accounts
`index=main LogName=Security EventCode=4625
| stats count by user
| sort -count
| head 10`

---

#### 3. Successful Windows Logons (Event ID 4624)
`index=main LogName=Security EventCode=4624 Logon_Type=2
| search NOT user IN ("SYSTEM","LOCAL SERVICE","NETWORK SERVICE","defaultuser0")
| where NOT like(user,"DWM-%")
| where NOT like(user,"UMFD-%")
| where NOT like(user,"%$$")
| timechart span=5m count`

---

#### 4. Successful Interactive Logon by Users
`index=main LogName=Security EventCode=4624 Logon_Type=2
| search NOT user IN ("SYSTEM","LOCAL SERVICE","NETWORK SERVICE","defaultuser0")
| where NOT like(user,"DWM-%")
| where NOT like(user,"UMFD-%")
| where NOT like(user,"%$$")
| stats count by user
| sort -count`

---

#### 5. Recently Created User Account Count
`index=main LogName=Security EventCode=4720
| stats count`

---


#### 6. Recently Created Local User Accounts
`index=main LogName=Security EventCode=4720
| rename user as New_User
| table _time host New_User
| sort -_time`

---

#### 7. Administrator Group Membership Changes
`index=main LogName=Security EventCode=4732 Group_Name=Administrators
| rename Account_Name as Created_By
| table _time host Created_By Group_Name
| sort -_time`

---

#### 8. PowerShell Executions by User
`index=sysmon EventCode=1
Image="*powershell.exe" AND CommandLine="*powershell*"
NOT ParentImage="*splunkd.exe"
NOT User="NT AUTHORITY\\SYSTEM"
| stats count by User
| sort -count`

---

#### 9. Encoded PowerShell Commands Executions
`index=sysmon EventCode=1 Image="*powershell.exe"
CommandLine="*-EncodedCommand*"
NOT ParentImage="*splunkd.exe"
NOT User="NT AUTHORITY\\SYSTEM"
| table _time User CommandLine
| sort -_time`

---

#### 10. PowerShell Spawned by Suspicious Parent Processes
`index=sysmon EventCode=1
Image="*powershell.exe"
(
ParentImage="*cmd.exe"
OR ParentImage="*winword.exe"
OR ParentImage="*excel.exe"
OR ParentImage="*wscript.exe"
OR ParentImage="*cscript.exe"
OR ParentImage="*mshta.exe"
OR ParentImage="*rundll32.exe"
)
NOT ParentImage="*splunkd.exe"
| table _time User ParentImage CommandLine
| sort -_time`

---

#### 11. Recent Network Connections
`index=sysmon EventCode=3 
| table _time SourceIp DestinationIp DestinationPort Protocol
| sort -_time`

---

#### 12. Network Connections by Process
`index=sysmon EventCode=3 Image != "*OneDrive*"
| stats count by Image 
| sort -count`

---

#### 13. Scheduled Task Creation Events
`index=sysmon EventCode=1 Image="*schtasks.exe"
CommandLine="*/create*"
| table _time User ParentImage CommandLine
| sort -_time`

---

#### 14. Registry Run Key Persistence
`index=sysmon EventCode=13
TargetObject="*CurrentVersion\\Run*"
| table _time User Image TargetObject Details
| sort -_time`

---


