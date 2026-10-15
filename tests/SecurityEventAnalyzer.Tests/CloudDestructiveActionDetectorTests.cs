using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;
using SecurityEventAnalyzer.Cli.Detection;

namespace SecurityEventAnalyzer.Tests;

public class CloudDestructiveActionDetectorTests
{
    [Fact]
    public void Detect_ReturnsFinding_TerminateInstancesEvent()
    {
        List<SecurityEvent> testList =
        [
            new SecurityEvent
            {
                Username = "terraform",
                EventType = "CloudApiCall",
                SourceIp = "10.10.10.1",
                Action = "TerminateInstances",
                ResourceId = "i-0123456789abcdef0",
                Timestamp = new DateTime(2026, 8, 31, 5, 0, 0)
            }
        ];

        var detector = new CloudDestructiveActionDetector();
        var findings = detector.Detect(testList);
        var finding = Assert.Single(findings);

        Assert.Equal("terraform", finding.Username);
        Assert.Equal("10.10.10.1", finding.SourceIp);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("Cloud Destructive Action Detected", finding.RuleName);
        Assert.Equal(new DateTime(2026, 8, 31, 5, 0, 0), finding.Timestamp);
        Assert.Contains("TerminateInstances", finding.Description);
        Assert.Contains("i-0123456789abcdef0", finding.Description);
    }

    [Fact]
    public void Detect_ReturnsFinding_DeleteVpcEvent()
    {
        List<SecurityEvent> testList =
        [
            new SecurityEvent
            {
                Username = "admin",
                EventType = "CloudApiCall",
                SourceIp = "10.10.10.1",
                Action = "DeleteVpc",
                ResourceId = "vpc-0abc123def456",
                Timestamp = new DateTime(2026, 8, 31, 6, 30, 0)
            }
        ];

        var detector = new CloudDestructiveActionDetector();
        var findings = detector.Detect(testList);
        var finding = Assert.Single(findings);

        Assert.Equal("admin", finding.Username);
        Assert.Equal("10.10.10.1", finding.SourceIp);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("Cloud Destructive Action Detected", finding.RuleName);
        Assert.Equal(new DateTime(2026, 8, 31, 6, 30, 0), finding.Timestamp);
        Assert.Contains("DeleteVpc", finding.Description);
        Assert.Contains("vpc-0abc123def456", finding.Description);

    }

    [Fact]
    public void Detect_ReturnsNoFinding_RunInstancesEvent()
    {
        List<SecurityEvent> testList =
        [
            new SecurityEvent
            {
                Username = "terraform",
                EventType = "CloudApiCall",
                SourceIp = "10.10.10.1",
                Action = "RunInstances",
                ResourceId = "i-0123456789abcdef0",
                Timestamp = new DateTime(2026, 8, 31, 7, 0, 0)
            }
        ];

        var detector = new CloudDestructiveActionDetector();
        var findings = detector.Detect(testList);

        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ReturnsFinding_TerminateInstances_MissingResourceId()
    {
        List<SecurityEvent> testList =
        [
            new SecurityEvent
            {
                Username = "terraform",
                EventType = "CloudApiCall",
                SourceIp = "10.10.10.1",
                Action = "TerminateInstances",
                ResourceId = null,
                Timestamp = new DateTime(2026, 8, 31, 7, 0, 0)
            }
        ];

        var detector = new CloudDestructiveActionDetector();
        var findings = detector.Detect(testList);
        var finding = Assert.Single(findings);

        Assert.Equal("terraform", finding.Username);
        Assert.Equal("10.10.10.1", finding.SourceIp);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("Cloud Destructive Action Detected", finding.RuleName);
        Assert.Equal(new DateTime(2026, 8, 31, 7, 0, 0), finding.Timestamp);
        Assert.Contains("TerminateInstances", finding.Description);
        Assert.Contains("Unknown Resource", finding.Description);
    }

    [Fact]
    public void Detect_ReturnsNoFinding_TerminateInstances_WrongEventType()
    {
        List<SecurityEvent> testList =
        [
            new SecurityEvent
            {
                Username = "terraform",
                EventType = "Authentication",
                SourceIp = "10.10.10.1",
                Action = "TerminateInstances",
                ResourceId = "i-0123456789abcdef0",
                Timestamp = new DateTime(2026, 8, 31, 9, 0, 0)
            }
        ];

        var detector = new CloudDestructiveActionDetector();
        var findings = detector.Detect(testList);

        Assert.Empty(findings);
    }
}