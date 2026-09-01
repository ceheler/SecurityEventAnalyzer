using SecurityEventAnalyzer.Cli;

namespace SecurityEventAnalyzer.Tests;

public class AccountCreationDetectorTests
{
    [Fact]
    public void Detect_ReturnsFinding_NewAccountCreated()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventId = 4720, SourceIp = "10.10.10.1" , TargetUser = "John", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), Computer = "Computer1" }
            ];
        var detector = new AccountCreationDetector();
        var findings = detector.Detect(testList);
        var finding = Assert.Single(findings);

        Assert.Equal("John", finding.Username);
        Assert.Equal("10.10.10.1", finding.SourceIp);
        Assert.Equal(Severity.Informational, finding.Severity);
        Assert.Equal("Account Creation Detected", finding.RuleName);
        Assert.Equal(new DateTime(2026, 8, 31, 05, 00, 0), finding.Timestamp);
        Assert.Equal("Computer1", finding.Computer);
    }

    [Fact]
    public void Detect_ReturnsFinding_MultipleAccountCreated()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventId = 4720, SourceIp = "10.10.10.1" , Username = "John", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), Computer = "Computer1" },
            new SecurityEvent { EventId = 4720, SourceIp = "10.10.10.1" , Username = "Tony", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), Computer = "Computer2" }
            ];
        var detector = new AccountCreationDetector();
        var findings = detector.Detect(testList);
        Assert.Equal(2, findings.Count);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_NoAccountCreated()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "John", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), Computer = "Computer1" },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Tony", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), Computer = "Computer2" }
            ];
        var detector = new AccountCreationDetector();
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_WhenInputIsEmpty()
    {
        List<SecurityEvent> testList = new List<SecurityEvent>();
        var detector = new AccountCreationDetector();
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }

}
