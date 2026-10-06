using SecurityEventAnalyzer.Cli.Detection;
using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Tests;

public class DetectionEngineTests
{
    List<IDetectionRule> rules =
                [ new BruteForceDetector(),
                  new AccountCreationDetector(),
                  new GroupMembershipChangeDetector(),
                  new PortScanDetector(),
                  new AccountPrivilegeCorrelationDetector()
                ];
    [Fact]
    public void Detect_ReturnsFinding_NewAccountCreated()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventId = 4720, SourceIp = "10.10.10.1" , TargetUser = "John", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), Computer = "Computer1" }
            ];
        var detector = new DetectionEngine(rules);
        var findings = detector.Detect(testList);
        var finding = Assert.Single(findings);

        Assert.Equal("John", finding.TargetUser);
        Assert.Equal("10.10.10.1", finding.SourceIp);
        Assert.Equal(Severity.Informational, finding.Severity);
        Assert.Equal("Account Creation Detected", finding.RuleName);
        Assert.Equal(new DateTime(2026, 8, 31, 05, 00, 0), finding.Timestamp);
        Assert.Equal("Computer1", finding.Computer);
    }

    [Fact]
    public void Detect_ReturnsFinding_WhenFiveFailedLoginsOccurWithinFiveMinutes()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), },
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 0), },
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 30), },
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 45), },
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 03, 0), }
            ];
        var detector = new DetectionEngine(rules);
        var findings = detector.Detect(testList);
        var finding = Assert.Single(findings);

        Assert.Equal("Admin", finding.TargetUser);
        Assert.Equal("10.10.10.1", finding.SourceIp);
        Assert.Equal(5, finding.Count);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("Brute Force Login Detection", finding.RuleName);
    }

    [Fact]
    public void Detect_ReturnsFinding_WhenFiveFailedLoginsOccurWithinFiveMinutesAndAccountCreated()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), },
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 0), },
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 30), },
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 45), },
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 03, 0), },
            new SecurityEvent { EventId = 4720, SourceIp = "10.10.10.1" , TargetUser = "John", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), Computer = "Computer1" },
            ];
        var detector = new DetectionEngine(rules);
        var findings = detector.Detect(testList);
        Assert.Equal(2, findings.Count);
    }

    [Fact]
    public void Detect_ReturnsFinding_WhenGroupMembershipChanged()
    {
        List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4728, SourceIp = "10.10.10.1" , TargetUser = "hax0r", TargetGroup = "Domain Admins", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0) }
                ];
        var detector = new DetectionEngine(rules);
        var findings = detector.Detect(testList);
        var finding = Assert.Single(findings);

        Assert.Equal("hax0r", finding.TargetUser);
        Assert.Equal("10.10.10.1", finding.SourceIp);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Contains("Group Membership Change Detected", finding.RuleName);
        Assert.Equal(new DateTime(2026, 8, 31, 05, 00, 0), finding.Timestamp);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_WhenInputIsEmpty()
    {
        List<SecurityEvent> testList = new List<SecurityEvent>();
        var detector = new DetectionEngine(rules);
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ReturnsFinding_MixedEventsMultipleFindings()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), },
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 0), },
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 30), },
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 45), },
            new SecurityEvent { EventType = "FailedAuthentication", SourceIp = "10.10.10.1" , TargetUser = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 03, 0), },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 0), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 80 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 10), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 443 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 20), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 22 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 30), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 3389 },
            new SecurityEvent { EventType = "BenignNetworkConnection", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 40), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 22 },
            new SecurityEvent { EventId = 4720, SourceIp = "10.10.10.1" , TargetUser = "John", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), Computer = "Computer1" },
            new SecurityEvent { EventId = 4728, SourceIp = "10.10.10.1", TargetUser = "hax0r", TargetGroup = "Enterprise Admins", Timestamp = new DateTime(2026, 9, 1, 6, 0 ,0) }
            ];

        var detector = new DetectionEngine(rules);
        var findings = detector.Detect(testList);
        Assert.Equal(4, findings.Count);
        Assert.Contains(findings,
        f => f.RuleName == "Brute Force Login Detection");
        Assert.Contains(findings,
            f => f.RuleName == "Port Scan Detection");
        Assert.Contains(findings,
            f => f.RuleName == "Account Creation Detected");
        Assert.Contains(findings,
            f => f.RuleName.Contains("Group Membership Change Detected"));
    }
}
