using SecurityEventAnalyzer.Cli.Detection;
using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Tests;

public class PortScanDetectorTests
{
    [Fact]
    public void Detect_ReturnsNoFinding_WhenLessThanFourDistinctDestinationPortsOccurWithinOneMinute()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 0), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 80 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 10), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 443 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 20), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 22 }
        ];

        var detector = new PortScanDetector();
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ReturnsFinding_WhenFourDistinctDestinationPortsOccurWithinOneMinute()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 0), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 80 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 10), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 443 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 20), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 22 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 30), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 3389 }
        ];

        var detector = new PortScanDetector();
        var findings = detector.Detect(testList);
        var finding = Assert.Single(findings);
        Assert.Equal("Port Scan Detection", finding.RuleName);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("192.168.1.100", finding.SourceIp);
        Assert.Equal("192.168.1.1", finding.DestinationIp);
        Assert.Equal(4, finding.Count);
        Assert.Equal(new DateTime(2026, 10, 06, 05, 00, 0), finding.Timestamp);
    }

    [Fact]
    public void Detect_ReturnsFinding_WhenFiveDistinctDestinationPortsOccurWithinOneMinute()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 0), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 80 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 10), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 443 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 20), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 22 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 30), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 3389 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 40), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 53 }
        ];

        var detector = new PortScanDetector();
        var findings = detector.Detect(testList);
        var finding = Assert.Single(findings);
        Assert.Equal("Port Scan Detection", finding.RuleName);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("192.168.1.100", finding.SourceIp);
        Assert.Equal("192.168.1.1", finding.DestinationIp);
        Assert.Equal(5, finding.Count);
        Assert.Equal(new DateTime(2026, 10, 06, 05, 00, 0), finding.Timestamp);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_WhenMoreThanFourDistinctDestinationPortsRepeat()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 0), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 80 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 10), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 443 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 20), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 80 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 30), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 443 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 40), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 80 }
        ];

        var detector = new PortScanDetector();
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_SameSourceDifferentDestination()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 0), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 80 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 10), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.2", DestinationPort = 443 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 20), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.3", DestinationPort = 22 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 30), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.4", DestinationPort = 3389 }
        ];

        var detector = new PortScanDetector();
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_WhenInputIsEmpty()
    {
        List<SecurityEvent> testList = new List<SecurityEvent>();
        var detector = new PortScanDetector();
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_WhenOutsideOneMinuteWindow()
    {
        List<SecurityEvent> testList = [
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 00), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 80 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 10), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 443 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 00, 20), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 22 },
            new SecurityEvent { EventType = "NetworkConnectionBlocked", Protocol="TCP", Timestamp = new DateTime(2026, 10, 06, 05, 01, 01), SourceIp = "192.168.1.100", DestinationIp = "192.168.1.1", DestinationPort = 3389 }
        ];

        var detector = new PortScanDetector();
        var findings = detector.Detect(testList);
        Assert.Empty(findings);
    }
}