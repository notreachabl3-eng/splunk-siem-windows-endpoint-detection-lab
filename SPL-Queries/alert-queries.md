## Alert Queries

#### 1. Network Scan Activity
`index=sysmon EventCode=3
| stats dc(DestinationPort) as UniquePorts values(DestinationPort) as ScannedPorts count as TotalConnections by SourceIp DestinationIp
| where UniquePorts >= 4
| sort - UniquePorts`

---

#### 2. Multiple Failed Login Attempts
`index=main EventCode=4625
| stats count by user 
| where count >= 5`

---

#### 3. Successful Login after Multiple Failed Attempts
`index=main source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625) Logon_Type=8
| eval User=lower(Account_Name)
| sort 0 User _time
| streamstats reset_after=(EventCode=4624) count(eval(EventCode=4625)) as FailedAttempts by User
| where EventCode=4624 AND FailedAttempts>=5
| table _time ComputerName User FailedAttempts`

---

#### 4. Host Discovery Commands Executed
`index=sysmon EventCode=1
(CommandLine=whoami OR CommandLine=hostname) 
| table _time User CommandLine ParentImage`

---

#### 5. Powershell Execution
`index=sysmon EventCode=1
Image="*\powershell.exe*" AND CommandLine="*powershell*"
User!="NT AUTHORITY\\SYSTEM"
| table _time User CommandLine ParentImage`

---

#### 6. Obsfucated Powershell Commands Detected
`index=sysmon EventCode=1 Image="*\\powershell.exe"
(CommandLine="*-enc*"
OR CommandLine="*-EncodedCommand*"
OR CommandLine="*IEX*"
OR CommandLine="*Invoke-Expression*"
OR CommandLine="*DownloadString*"
OR CommandLine="*FromBase64String*"
OR CommandLine="*-nop*"
OR CommandLine="*-w hidden*"
OR CommandLine="*ExecutionPolicy Bypass*")
| table _time User Computer ParentImage CommandLine`

---

#### 7. New User Account Created
`index=main source="WinEventLog:Security" EventCode=4720
| rename Subject_Account_Name as Created_by
| rename New_Account_Account_Name as New_User
| rename New_Account_Security_ID as SID
| table _time ComputerName Created_by New_User SID
| sort - _time`

---

#### 8. User Added to Administrators Group
`index=main source="WinEventLog:Security" EventCode=4732
| rename Subject_Account_Name as Added_By
| rename Group_Name as Local_Group
| rename Member_Security_ID as SID
| table _time ComputerName Added_By SID Local_Group
| sort - _time`

---

#### 9. Scheduled Task Created
`index=main source="WinEventLog:Security" EventCode=4698
| rename Subject_Account_Name as Created_By
| table _time ComputerName Created_By Task_Name Task_Content
| sort - _time`

---

#### 10. Registry Key Modified
`index=sysmon EventCode=13 Image="*\reg.exe"
(TargetObject="*\\CurrentVersion\\Run\\*" OR
 TargetObject="*\\Winlogon\\*")
| rename TargetObject as Registry_Key
| rename Image as Process
| rename Details as Registry_Value
| table _time Computer User Process Registry_Key Registry_Value
| sort - _time`

---

