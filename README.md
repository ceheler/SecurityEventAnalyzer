# SecurityEventAnalyzer

## Purpose
Project is designed to be run from the terminal.  The project accepts a JSON file containing Windows security-event data in the expected schema. It analyzes the entries and passes them through several detection algorithms and returns any detected security findings

## Features
- Parses Windows security event JSON file
- Validates the file and reports empty results and file errors
- Currently has detectors for brute force, account creation, and group membership
- Assigns severity enum value to all detections
- Uses a central detection engine to execute all registered rules
- All detection rules handle empty input
- Returns easy to digest results to the terminal
- Includes xUnit tests

## Detection Rules

### Brute Force
Windows Event ID 4625 events are filtered and grouped by username and source IP using LINQ
Each group is ordered chronologically and analyzed for five or more failed logons within an inclusive five-minute window
Events missing the username or source IP required for correlation are excluded from brute-force analysis

### Account Creation
Windows Event ID 4720 events are filtered with LINQ
Each matching event produces a finding containing the relevant account, computer, source IP, and timestamp information

### Privileged Group Membership
Windows Event ID 4728 events are filtered using LINQ
Severity is assigned based on a hierarchy 
- Domain/Enterprise Admin => High
- Other Admin Groups => Medium
- Other groups => Low

## Architecture

### Security Event
- Represents a parsed Windows security event
- `Timestamp` and `EventId` are required 
- Event-specific properties are nullable because different Windows Event IDs expose different fields

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
- Calls Detection engine and outputs readable output to the terminal

## Example Input
- A sample synthetic event file, `test_windows_security_events.json`, is included in the tests directory

## Example Output
```text
Analyzing C:\Users\cehel\source\repos\SecurityEventAnalyzer\tests\test_windows_security_events.json

Log event summary

===================

Processed 40 events


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

Privileged Group Membership Change Detected
Account username: temp-admin was added to Domain Admins
===================
Severity: High
Timestamp: 8/26/2026 8:37:22 AM
User: jdoe
Target User: temp-admin
Target Group: Domain Admins
Source IP: 10.10.10.50
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

## Testing
- All tests use xUnit framework
- Tests have lists generated expecting detection or no detection based on the rules
- In rules expecting detection the output is checked against what is expected
- In rules expecting no detection the output is checked against an empty response
- Multiple responses and null input are checked in all applicable detection rules
- Unrelated events are checked to ensure they do not produce false positive results
- DetectionEngine tested to ensure all individual rules work when the engine is called

## Design Decisions
- Nullable fields are used where Windows Events may not include a corresponding field
- All detectors respond with SecurityFinding objects to ensure Program.cs is using the same object format for all output
- IDetectionRule object ensures all rules will interface with DetectionEngine and not require hard coding
- DetectionEngine utilizes a constructor allowing user to specify what detection rules are in use at runtime
- OOP principles followed to prevent code congestion and allow easier readability

## Future Improvements
- Configurable rule thresholds and severity mappings
- JSON/CSV output options
- Structured application logging
- Streaming support for large event files
- More efficient sliding-window correlation
- Additional detection rules, including:
  - 4648 — Logon attempted using explicit credentials
  - 4672 — Special privileges assigned to a new logon
  - 4103/4104 — PowerShell module and script block logging
  - 1102 — Windows audit log cleared

## Disclaimer


This project is intended for educational and security-lab use. It currently operates on synthetic or imported event data and is not intended to replace a production SIEM.