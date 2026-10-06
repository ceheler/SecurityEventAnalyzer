# SecurityEventAnalyzer

## Purpose

SecurityEventAnalyzer is a command-line security analysis application that processes normalized JSON security events through a set of detection rules and returns standardized security findings

The analyzer uses a shared SecurityEvent schema so telemetry from different platforms and normalization pipelines can be evaluated by the same detection engine 

Current validation includes Windows Security Event data, Linux SSH authentication telemetry, and Linux UFW network-block telemetry

## Features

- Parses normalized security-event JSON files
- Supports normalized telemetry from multiple operating systems and sources
- Validates input files and handles empty or malformed input
- Detects:
  - Brute-force authentication activity
  - Windows account creation
  - Windows group membership additions
  - Account creation followed by privileged-group membership
  - Network port scanning
- Assigns standardized severity levels to findings
- Uses a central DetectionEngine to execute registered rules
- Uses a common SecurityFinding model for detector output
- Supports cross-event correlation
- Includes xUnit unit and integration tests
- Processes mixed telemetry sources in a single event collection

For detailed rule logic, telemetry requirements, and known detection gaps, see
[Detection Coverage](docs/detection-coverage.md).

## Detection Rules

### Port Scan

Events with `EventType = NetworkConnectionBlocked` are grouped by source IP, destination IP, and protocol

Each group is analyzed using a sliding one-minute window. Four or more unique destination ports observed within the window produce a Medium-severity finding

The detector currently has been validated using normalized Linux UFW telemetry

Repeated connections to the same ports do not increase the distinct-port count

### Brute Force

Events with `EventType = FailedAuthentication` are grouped by target user, source IP, and computer

Each group is ordered chronologically and evaluated using a sliding five-minute window

Five or more failed authentication attempts within that window produce a High-severity finding

The detector operates on normalized authentication events rather than a platform-specific Event ID

It has been validated against both normalized Windows failed-logon events and Linux SSH failed-authentication events

### Account Creation

Windows Event ID 4720 events are filtered with LINQ
Each matching event produces a finding containing the relevant account, computer, source IP, and timestamp information

### Group Membership Change

Windows Event IDs `4728` and `4732` are filtered using LINQ to detect additions to security-enabled global and local groups

Severity is assigned based on the sensitivity of the target group:
- Local Administrators => High
- Domain Admins / Enterprise Admins => High
- Other groups containing "admin" => Medium
- Other group membership changes => Low

Local Administrators can also be identified using the well-known SID `S-1-5-32-544`

When Windows does not provide the member account name, the detector uses the member SID as a fallback identifier

### Account Privilege Correlation

Windows Event ID `4720` account-creation events are correlated with subsequent privileged group-membership changes using Event IDs `4728` and `4732`

The detector correlates the newly created account's `TargetSid` with the group-membership event's `MemberSid`. A correlation requires:
- The group-membership change to occur after account creation
- The change to occur within the configured 24-hour correlation window
- The events to occur on the same computer
- The target group to be recognized as privileged, including Local Administrators, Domain Admins, or Enterprise Admins

A matching account-creation and privileged-group sequence produces a Critical finding

The detector also searches for a subsequent successful logon (`4624`) by the elevated account. When a corresponding `4672` event is found using the same Logon ID, username, and computer, the finding is enriched to indicate that the account later established a logon session that was assigned special privileges

Event `4672` is optional enrichment and is not required for the base account-privilege correlation finding

## Architecture

### SecurityEvent

- Represents a normalized security event from supported telemetry sources
- `Timestamp` is required for time-based detection and correlation
- Other properties are nullable because different telemetry sources expose different fields
- Platform-specific identifiers such as `EventId` are optional
- Common fields such as `EventType`, `SourceIp`, `TargetUser`, `DestinationIp`, `DestinationPort`, and `Protocol` allow detectors to operate across normalized event sources where applicable

### SecurityFinding

- Represents a standardized detection result produced by a detector
- Allows different detectors to produce uniform data

### Severity

- Project-defined enum used to classify findings as Unknown, Critical, High, Medium, Low, or Informational

### IDetectionRule

- Defines the common contract implemented by all detection rules
- Allows new rules to be registered with the detection engine without modifying the engine's execution logic

### Individual Detectors

- Contain detection logic based on the rules mentioned above
- Future expandability due to the OOP design of the project

### DetectionEngine

- Receives a collection of `IDetectionRule` detectors through constructor injection
- Executes each registered rule against the imported events

### Program.cs

- Does input file validation and error handling of input
- Calls the detection engine and outputs readable output to the terminal

## Example Input

- A sample synthetic event file, `test_windows_security_events.json`, is included in the tests directory

## Example Output

```text
Analyzing E:\logs\test.json

Log event summary

===================

Processed 56 events


Brute Force Login Detection
7 failed logins detected within 5 min window.
===================
Severity: High
Timestamp: 8/26/2026 8:25:30 AM
User: administrator
Source IP: 10.10.40.55
Count: 7

Account Creation Detected
Account username: temp-admin created on computer DC01
===================
Severity: Informational
Timestamp: 8/26/2026 8:35:05 AM
User: jdoe
Target User: temp-admin
Source IP: 10.10.10.50
Computer: DC01

Account Creation Detected
Account username: corr-standard-user created on computer LAB-WS03
===================
Severity: Informational
Timestamp: 8/26/2026 10:30:00 AM
User: lab-admin
Target User: corr-standard-user
Computer: LAB-WS03

Account Creation Detected
Account username: corr-late-admin created on computer LAB-WS04
===================
Severity: Informational
Timestamp: 8/26/2026 11:00:00 AM
User: lab-admin
Target User: corr-late-admin
Computer: LAB-WS04

Account Creation Detected
Account username: corr-domain-admin created on computer LAB-DC02
===================
Severity: Informational
Timestamp: 8/26/2026 11:10:00 AM
User: domain-admin
Target User: corr-domain-admin
Computer: LAB-DC02

Account Creation Detected
Account username: corr-cross-host created on computer LAB-WS05
===================
Severity: Informational
Timestamp: 8/26/2026 11:30:00 AM
User: lab-admin
Target User: corr-cross-host
Computer: LAB-WS05

Global Group Membership Change Detected
Member: temp-admin was added to Domain Admins
===================
Severity: High
Timestamp: 8/26/2026 8:37:22 AM
User: jdoe
Target User: temp-admin
Target Group: Domain Admins
Source IP: 10.10.10.50

Local Group Membership Change Detected
Member: S-1-5-21-1111111111-2222222222-3333333333-1101 was added to Administrators
===================
Severity: High
Timestamp: 8/26/2026 10:05:00 AM
User: lab-admin
Target Group: Administrators

Local Group Membership Change Detected
Member: S-1-5-21-1111111111-2222222222-3333333333-1102 was added to Administrators
===================
Severity: High
Timestamp: 8/26/2026 10:25:00 AM
User: lab-admin
Target Group: Administrators

Local Group Membership Change Detected
Member: S-1-5-21-1111111111-2222222222-3333333333-1103 was added to Users
===================
Severity: Low
Timestamp: 8/26/2026 10:35:00 AM
User: lab-admin
Target Group: Users

Local Group Membership Change Detected
Member: S-1-5-21-1111111111-2222222222-3333333333-1104 was added to Administrators
===================
Severity: High
Timestamp: 8/27/2026 11:01:00 AM
User: lab-admin
Target Group: Administrators

Global Group Membership Change Detected
Member: S-1-5-21-4444444444-5555555555-6666666666-1201 was added to Domain Admins
===================
Severity: High
Timestamp: 8/26/2026 11:15:00 AM
User: domain-admin
Target Group: Domain Admins

Local Group Membership Change Detected
Member: S-1-5-21-1111111111-2222222222-3333333333-1105 was added to Administrators
===================
Severity: High
Timestamp: 8/26/2026 11:35:00 AM
User: lab-admin
Target Group: Administrators

AccountPrivilegeCorrelation
Account corr-local-admin was created and added to Administrators within 24 hours,
and a privileged session was observed at 8/26/2026 10:10:00 AM. See Logon ID 0xA100
===================
Severity: Critical
Timestamp: 8/26/2026 10:05:00 AM
User: lab-admin
Target User: corr-local-admin
Target Group: Administrators
Source IP: 192.0.2.50
Computer: LAB-WS01

AccountPrivilegeCorrelation
Account corr-base-admin was created and added to Administrators within 24 hours.
===================
Severity: Critical
Timestamp: 8/26/2026 10:25:00 AM
User: lab-admin
Target User: corr-base-admin
Target Group: Administrators
Computer: LAB-WS02

AccountPrivilegeCorrelation
Account corr-domain-admin was created and added to Domain Admins within 24 hours,
and a privileged session was observed at 8/26/2026 11:20:00 AM. See Logon ID 0xB200
===================
Severity: Critical
Timestamp: 8/26/2026 11:15:00 AM
User: domain-admin
Target User: corr-domain-admin
Target Group: Domain Admins
Source IP: 198.51.100.25
Computer: LAB-DC02
```

## How to Run

1. Build the project
2. Locate program's executable
3. Navigate to path of .exe 
4. Call the .exe and specify the JSON as the first command line argument

PS Example:`.\SecurityEventAnalyzer.Cli.exe C:\Logs\test_windows_security_events.json`

SDK-Style Example:`dotnet run --project .\src\SecurityEventAnalyzer.Cli -- C:\Logs\test_windows_security_events.json`

## Running Tests

1. Run tests inside Visual Studio by right-clicking the test project and selecting "Run tests"
2. Using a terminal, navigate to the solution or test project directory and run `dotnet test`

## Project Structure

### src folder

- Detection folder contains all detection rules, DetectionEngine and IDetectionRule
- Enums folder contains Severity.cs
- Models folder contains SecurityEvent and SecurityFinding objects

### tests folder

- Contains all xUnit unit tests
- Contains JSON file used for initial debugging

### docs folder
- Contains detection-coverage.md with detailed detection logic, telemetry requirements, and known gaps for each detection rule

## Testing

- Tests use the xUnit framework
- Individual detection rules are tested independently
- Positive tests verify expected finding properties and severity
- Negative tests verify that unrelated or insufficient telemetry does not generate findings
- Boundary conditions are tested for time windows and detection thresholds
- Port-scan tests verify distinct-port counting, destination isolation, repeated ports, and one-minute window behavior
- Account privilege correlation tests verify SID matching, host matching, privileged-group targeting, and the 24-hour correlation window
- DetectionEngine integration tests verify that multiple registered rules operate correctly against a mixed event collection
- Mixed normalized Windows, Linux SSH, and Linux UFW event data has also been validated through the executable

## Design Decisions

- Nullable fields are used where Windows Events may not include a corresponding field
- All detectors respond with SecurityFinding objects to ensure Program.cs is using the same object format for all output
- The IDetectionRule interface allows all detection rules to be executed by DetectionEngine without rule-specific engine logic
- DetectionEngine utilizes a constructor allowing user to specify what detection rules are in use at runtime
- OOP principles followed to prevent code congestion and allow easier readability
- Stable identifiers such as account and group SIDs are used for cross-event correlation when available instead of relying solely on display names
- Event `4672` is treated as enrichment rather than a standalone indication that privileges were exercised

## Future Improvements

- Configurable rule thresholds and severity mappings
- JSON/CSV output options
- Structured application logging
- Streaming support for large event files
- More efficient sliding-window correlation
- Additional detection rules, including:
  - 4648 — Logon attempted using explicit credentials
  - 4103/4104 — PowerShell module and script block logging
  - 1102 — Windows audit log cleared
- Create standalone 4672 — Special privileges assigned to a new logon detector

## Current Detection Scope / Limitations

- Account privilege correlation currently uses a 24-hour correlation window
- Privileged-group correlation currently recognizes:
  - Local Administrators
  - Domain Admins
  - Enterprise Admins
- Local Administrators is also identified using the well-known SID `S-1-5-32-544`
- Event `4672` is used as enrichment indicating that special privileges were assigned to a subsequent logon session; it does not prove those privileges were exercised
- Cross-platform authentication detection has been validated using normalized Windows and Linux SSH telemetry
- Port-scan detection has been validated using normalized Linux UFW telemetry
- Equivalent Windows network-block telemetry has not yet been validated for the port-scan detector
- The current analyzer processes imported event collections rather than live streaming telemetry

## Disclaimer


This project is intended for educational and security-lab use. It currently operates on synthetic or imported event data and is not intended to replace a production SIEM