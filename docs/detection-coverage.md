# Detection Coverage

## AccountCreationDetector

### Purpose
Detect Windows account creation events. Provides visibility into newly created accounts and supports investigation of subsequent privilege escalation activity.

### Detection Logic
- EventId = 4720

### Required Telemetry
- EventId

### Finding Context
- Timestamp
- TargetUser
- Username
- Computer
- SourceIp

### Known Gaps
- Does not detect account creation events from non-Windows systems
- Does not determine if the account creation was authorized or malicious
- Legitimate administrative or provisioning activity may trigger this detection

### Severity
Informational

## AccountPrivilegeCorrelationDetector

### Purpose
Detect correlations between newly created Windows accounts and subsequent privileged group membership addition occurring within 24 hours.

### Detection Logic
- Account creation EventId = 4720
- Subsequent group membership EventId = 4728 or 4732
- The created account's TargetSid must match the group membership event's MemberSid
- Both events must occur on the same Computer
- The group membership change must target a privileged group
- The privileged group membership change must occur within 24 hours of account creation

### Required Telemetry
- Timestamp
- EventId
- MemberSid
- TargetSid
- Computer

### Finding Context
- Timestamp
- Username
- SourceIp
- Computer
- TargetUser
- TargetGroup

### Known Gaps
- Does not detect privilege escalation events from non-Windows systems
- Does not detect privilege escalation that does not involve the monitored privileged groups
- Does not correlate events occurring more than 24 hours after account creation
- Does not correlate account and group events occurring on different computers
- Does not determine whether the privilege escalation was authorized or malicious
- Legitimate administrative or provisioning activity may trigger this detection

### Severity
Critical

## BruteForceDetector

### Purpose
Detect repeated failed authentication attempts against the same account.

### Detection Logic
- EventType = FailedAuthentication
- Same SourceIp
- Same TargetUser
- Same Computer
- >= 5 failures
- Within 5 minutes

### Required Telemetry
- Timestamp
- EventType
- SourceIp
- TargetUser
- Computer

### Finding Context
- Timestamp
- TargetUser
- SourceIp
- Count of failed attempts in defined time window

### Known Gaps
- Password spraying across many accounts
- Distributed attacks from multiple IP addresses
- Low-and-slow attacks outside the five-minute window
- Does not detect authentication attacks where attempts are distributed across multiple target computers

### Severity
High

## GroupMembershipChangeDetector

### Purpose
Detect Windows group membership additions and assign severity based on the sensitivity of the target group. Provides visibility into potential privilege escalation activity.

### Detection Logic
- EventId = 4728 or 4732
- Evaluates the target group
- Assigns severity based on whether the target group is privileged

### Required Telemetry
- EventId

### Finding Context
- Username
- TargetUser
- TargetGroup
- SourceIp
- Timestamp

### Known Gaps
- Does not detect privilege escalation events from non-Windows systems
- Does not determine whether the privilege escalation was authorized or malicious
- Legitimate administrative or provisioning activity may trigger this detection
- Does not detect privilege escalation that does not involve the monitored privileged groups

### Severity
- Domain / Enterprise Admins / Local Admins: High
- Other Privileged Groups: Medium
- Other Groups: Low

## PortScanDetector

### Purpose
Detect port scanning activity originating from a single source IP address against a single destination IP address. Triggers when four or more unique destination ports are observed within a one-minute window.

### Detection Logic
- Evaluates NetworkConnectionBlocked events grouped by SourceIp, DestinationIp, and Protocol
- Uses a sliding 1-minute window
- Counts unique destination port values within the window
- Triggers when 4 or more unique ports are observed

### Required Telemetry
- Timestamp
- EventType
- SourceIp
- DestinationIp
- DestinationPort
- Protocol

### Finding Context
- Timestamp
- SourceIp
- DestinationIp
- Count of unique destination ports scanned in the defined time window
- Computer

### Known Gaps
- Does not detect port scanning activity from multiple source IP addresses
- Does not detect port scanning activity targeting multiple destination IP addresses
- Does not detect port scanning activity that occurs outside the 1-minute window
- Does not detect low and slow port scanning activity that occurs over a longer period of time
- Currently validated using Linux UFW telemetry; equivalent Windows network-block telemetry has not been tested

### Severity
Medium