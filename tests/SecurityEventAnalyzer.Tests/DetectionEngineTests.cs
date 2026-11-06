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

    private class TestAuthenticationRule : IAuthenticationDetectionRule
    {
        public bool WasCalled { get; private set; } = false;

        public List<AuthenticationCorrelation>? ReceivedCorrelations
        {
            get;
            private set;
        }

        public List<SecurityFinding> FindingsToReturn { get; set; } = [];

        public List<SecurityFinding> Detect(
            List<AuthenticationCorrelation> correlations)
        {
            WasCalled = true;
            ReceivedCorrelations = correlations;

            return FindingsToReturn;
        }
    }

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

    [Fact]
    public void Detect_WithAuthenticationCorrelations_ExecutesAuthenticationRules()
    {
        var testRule = new TestAuthenticationRule();

        var timestamp = new DateTime(
            2026, 10, 20, 09, 21, 10, DateTimeKind.Utc);

        var kerberosEvent = new SecurityEvent
        {
            EventId = 4769,
            StatusCode = "0x0",
            Timestamp = timestamp,
            Username = "svc_healthmon",
            SourceIp = "10.20.14.37",
            ServicePrincipalName = "cifs/APP02"
        };

        var correlation = new AuthenticationCorrelation
        {
            Timestamp = timestamp,
            Username = "svc_healthmon",
            SourceIp = "10.20.14.37",
            DestinationHost = "APP02",
            LogonType = null,
            AuthOutcome = AuthenticationOutcome.Unknown,
            SupportingEvents = new List<SecurityEvent>
            {
                kerberosEvent
            }
        };

        var correlations = new List<AuthenticationCorrelation>
        {
            correlation
        };

        var engine = new DetectionEngine(
            new List<IDetectionRule>(),
            new List<IAuthenticationDetectionRule>
            {
                testRule
            });

        var findings = engine.Detect(
            new List<SecurityEvent>(),
            correlations);

        Assert.True(testRule.WasCalled);
        Assert.Same(correlations, testRule.ReceivedCorrelations);
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithBothRuleTypes_CombinesFindings()
    {
        var testRule = new TestAuthenticationRule();

        var timestamp = new DateTime(
            2026, 10, 20, 09, 21, 10, DateTimeKind.Utc);

        var testFinding = new SecurityFinding
        {
            RuleName = "Test Authentication Finding",
            Description = "Authentication detection test",
            Timestamp = timestamp,
            Severity = Severity.Informational
        };

        testRule.FindingsToReturn = new List<SecurityFinding> { testFinding };

        var kerberosEvent = new SecurityEvent
        {
            EventId = 4769,
            StatusCode = "0x0",
            Timestamp = timestamp,
            Username = "svc_healthmon",
            SourceIp = "10.20.14.37",
            ServicePrincipalName = "cifs/APP02"
        };

        var correlation = new AuthenticationCorrelation
        {
            Timestamp = timestamp,
            Username = "svc_healthmon",
            SourceIp = "10.20.14.37",
            DestinationHost = "APP02",
            LogonType = null,
            AuthOutcome = AuthenticationOutcome.Unknown,
            SupportingEvents = new List<SecurityEvent>
            {
                kerberosEvent
            }
        };

        var correlations = new List<AuthenticationCorrelation>
        {
            correlation
        };

        var accountCreationEvent = new List<SecurityEvent>
        {
            new SecurityEvent
            {
                EventId = 4720,
                SourceIp = "10.20.14.37",
                TargetUser = "newuser",
                Timestamp = timestamp,
                Computer = "Computer1"
            }
        };

        var engine = new DetectionEngine(
            new List<IDetectionRule>
            {
                new AccountCreationDetector()
            },
            new List<IAuthenticationDetectionRule>
            {
                testRule
            });

        var findings = engine.Detect(
            accountCreationEvent,
            correlations);

        Assert.True(testRule.WasCalled);
        Assert.Same(correlations, testRule.ReceivedCorrelations);
        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.RuleName == "Account Creation Detected");
        Assert.Contains(findings, f => f.RuleName == "Test Authentication Finding");

    }
}
