using SecurityEventAnalyzer.Cli;

namespace SecurityEventAnalyzer.Tests;

public class BruteForceDetectorTests
{
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
        var detector = new BruteForceDetector();
        var findings = detector.Detect(testList);
        var finding = Assert.Single(findings);

        Assert.Equal("Admin", finding.Username);
        Assert.Equal("10.10.10.1", finding.SourceIp);
        Assert.Equal(5, finding.Count);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("Brute Force Login Detection", finding.RuleName);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_WhenOnlyFourFailedLoginsOccur()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 30), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 45), }
            ];
        var detector = new BruteForceDetector();
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_WhenOnlyFiveFailedLoginsOccurOutsideFiveMinutes()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 02, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 03, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 06, 0), }
            ];
        var detector = new BruteForceDetector();
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ReturnsFinding_WhenExactlyFiveFailedLoginsOccurInsideFiveMinutes()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 02, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 03, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 05, 0), }
            ];
        var detector = new BruteForceDetector();
        var findings = detector.Detect(testList);
        var finding = Assert.Single(findings);

        Assert.Equal("Admin", finding.Username);
        Assert.Equal("10.10.10.1", finding.SourceIp);
        Assert.Equal(5, finding.Count);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("Brute Force Login Detection", finding.RuleName);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_WhenFiveFailedLoginsOccurInsideFiveMinutesDifferentIps()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.1.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.1.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 02, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.10" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 03, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 04, 0), }
            ];
        var detector = new BruteForceDetector();
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_WhenFiveFailedLoginsOccurInsideFiveMinutesDifferentUsers()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Bob", Timestamp = new DateTime(2026, 8, 31, 05, 01, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 02, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Joe", Timestamp = new DateTime(2026, 8, 31, 05, 03, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 04, 0), }
            ];
        var detector = new BruteForceDetector();
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_WhenInputIsEmpty()
    {
        List<SecurityEvent> testList = new List<SecurityEvent>();
        var detector = new BruteForceDetector();
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ReturnsFinding_WhenTwoGroupedEventrsFiveFailedLoginsOccurWithinFiveMinutes()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 30), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 01, 45), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Admin", Timestamp = new DateTime(2026, 8, 31, 05, 03, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Adam", Timestamp = new DateTime(2026, 8, 31, 05, 10, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Adam", Timestamp = new DateTime(2026, 8, 31, 05, 11, 0), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Adam", Timestamp = new DateTime(2026, 8, 31, 05, 11, 30), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Adam", Timestamp = new DateTime(2026, 8, 31, 05, 11, 45), },
            new SecurityEvent { EventId = 4625, SourceIp = "10.10.10.1" , Username = "Adam", Timestamp = new DateTime(2026, 8, 31, 05, 13, 0), }
            ];
        var detector = new BruteForceDetector();
        var findings = detector.Detect(testList);
        Assert.Equal(2, findings.Count);
    }
}