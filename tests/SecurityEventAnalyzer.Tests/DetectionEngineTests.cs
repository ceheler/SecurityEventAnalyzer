using SecurityEventAnalyzer.Cli.Detection;
using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Tests;

public class DetectionEngineTests
{
    List<IDetectionRule> rules =
                [ new BruteForceDetector(),
                  new AccountCreationDetector(),
                  new PrivilegedGroupMembershipDetector()
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
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 30), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 45), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 03, 0), }
            ];
        var detector = new DetectionEngine(rules);
        var findings = detector.Detect(testList);
        var finding = Assert.Single(findings);

        Assert.Equal("Admin", finding.Username);
        Assert.Equal("10.10.10.1", finding.SourceIp);
        Assert.Equal(5, finding.Count);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("Brute Force Login Detection", finding.RuleName);
    }

    [Fact]
    public void Detect_ReturnsFinding_WhenFiveFailedLoginsOccurWithinFiveMinutesAndAccountCreated()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 30), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 45), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 03, 0), },
            new SecurityEvent { EventId = 4720, SourceIp = "10.10.10.1" , TargetUser = "John", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), Computer = "Computer1" }
            ];
        var detector = new DetectionEngine(rules);
        var findings = detector.Detect(testList);
        Assert.Equal(2, findings.Count);
    }

    [Fact]
    public void Detect_ReturnsFinding_WhenPrivilegedAccountCreated()
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
        Assert.Equal("Privileged Group Membership Change Detected", finding.RuleName);
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
}
