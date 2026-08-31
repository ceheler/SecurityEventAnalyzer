using SecurityEventAnalyzer.Cli;

namespace SecurityEventAnalyxer.Tests;

public class Tests
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
        var findings = BruteForceDetector.Detect(testList);
        Assert.Single(findings);

        
    }
}