using SecurityEventAnalyzer.Cli.Detection;
using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Tests;

public class SuccessfulAuthenticationAfterFailuresDetectorTests
{
    [Fact]
    public void Detect_ThreeFailuresFollowedBySuccess_ReturnsFinding()
    {
        var timestamp = new DateTime(2026, 10, 20, 09, 18, 00, DateTimeKind.Utc);

        var kerberosEvent = new SecurityEvent
        {
            EventId = 4769,
            StatusCode = "0x0",
            Timestamp = timestamp,
            Username = "Administrator",
            SourceIp = "10.20.14.37",
            ServicePrincipalName = "cifs/APP02"
        };

        List<AuthenticationCorrelation> testEvents = [
                new AuthenticationCorrelation {
                    Timestamp = timestamp,
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Failed,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                },
                new AuthenticationCorrelation {
                    Timestamp = timestamp.AddMinutes(1),
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Failed,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                },
                new AuthenticationCorrelation {
                    Timestamp = timestamp.AddMinutes(2),
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Failed,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                },
                new AuthenticationCorrelation {
                    Timestamp = timestamp.AddMinutes(3),
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Successful,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                }
            ];

        var detector = new SuccessfulAuthenticationAfterFailuresDetector();
        var findings = detector.Detect(testEvents);

        Assert.Single(findings);
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Theory]
    [InlineData(240, true)]  // 4 minutes
    [InlineData(300, true)]  // Exactly 5 minutes
    [InlineData(301, false)] // 5 minutes and 1 second
    [InlineData(360, false)] // 6 minutes
    public void Detect_FailureWindowBoundary_ReturnsExpectedResult(
        int secondsBeforeSuccess,
        bool expectedFinding)
    {
        var successTime = new DateTime(
            2026, 10, 20, 09, 21, 00, DateTimeKind.Utc);

        var correlations = new List<AuthenticationCorrelation>
        {
            new AuthenticationCorrelation
            {
                Timestamp = successTime.AddSeconds(-secondsBeforeSuccess),
                Username = "Administrator",
                SourceIp = "10.20.14.37",
                DestinationHost = "APP02",
                AuthOutcome = AuthenticationOutcome.Failed,
                SupportingEvents = []
            },
            new AuthenticationCorrelation
            {
                Timestamp = successTime.AddMinutes(-2),
                Username = "Administrator",
                SourceIp = "10.20.14.37",
                DestinationHost = "APP02",
                AuthOutcome = AuthenticationOutcome.Failed,
                SupportingEvents = []
            },
            new AuthenticationCorrelation
            {
                Timestamp = successTime.AddMinutes(-1),
                Username = "Administrator",
                SourceIp = "10.20.14.37",
                DestinationHost = "APP02",
                AuthOutcome = AuthenticationOutcome.Failed,
                SupportingEvents = []
            },
            new AuthenticationCorrelation
            {
                Timestamp = successTime,
                Username = "Administrator",
                SourceIp = "10.20.14.37",
                DestinationHost = "APP02",
                AuthOutcome = AuthenticationOutcome.Successful,
                SupportingEvents = []
            }
        };

        var detector = new SuccessfulAuthenticationAfterFailuresDetector();
        var findings = detector.Detect(correlations);

        if (expectedFinding)
        {
            var finding = Assert.Single(findings);
            Assert.Equal(Severity.High, finding.Severity);
        }
        else
        {
            Assert.Empty(findings);
        }
    }

    [Theory]
    [InlineData("Username")]
    [InlineData("SourceIp")]
    [InlineData("DestinationHost")]
    public void Detect_MismatchedGroupIdentifier_ReturnsNoFinding(
        string identifierToChange)
    {
        var timestamp = new DateTime(2026, 10, 20, 09, 18, 00, DateTimeKind.Utc);
        var identifierValue = identifierToChange switch
        {
            "Username" => "DifferentUser",
            "SourceIp" => "10.20.14.38",
            "DestinationHost" => "APP03",
            _ => ""
        };
        

        var kerberosEvent = new SecurityEvent
        {
            EventId = 4769,
            StatusCode = "0x0",
            Timestamp = timestamp,
            Username = "Administrator",
            SourceIp = "10.20.14.37",
            ServicePrincipalName = "cifs/APP02"
        };

        List<AuthenticationCorrelation> testEvents = [
                new AuthenticationCorrelation {
                    Timestamp = timestamp,
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Failed,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                },
                new AuthenticationCorrelation {
                    Timestamp = timestamp.AddMinutes(1),
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Failed,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                },
                new AuthenticationCorrelation {
                    Timestamp = timestamp.AddMinutes(2),
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Failed,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                },
                new AuthenticationCorrelation {
                    Timestamp = timestamp.AddMinutes(3),
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Successful,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                }
            ];

            var targetIdentifier = testEvents[0];

            switch (identifierToChange)
            {
                case "Username":
                    targetIdentifier.Username = identifierValue;
                    break;
                case "SourceIp":
                    targetIdentifier.SourceIp = identifierValue;
                    break;
                case "DestinationHost":
                    targetIdentifier.DestinationHost = identifierValue;
                    break;
            }

        var detector = new SuccessfulAuthenticationAfterFailuresDetector();
        var findings = detector.Detect(testEvents);

        Assert.Empty(findings);
    }

    [Theory]
    [InlineData("Username")]
    [InlineData("DestinationHost")]
    public void Detect_CaseInsensitiveIdentifiers_ReturnsFinding(
        string identifierToModify)
    {
        var timestamp = new DateTime(2026, 10, 20, 09, 18, 00, DateTimeKind.Utc);
        var identifierValue = identifierToModify switch
        {
            "Username" => "ADMINISTRATOR",
            "DestinationHost" => "app02",
            _ => ""
        };
        

        var kerberosEvent = new SecurityEvent
        {
            EventId = 4769,
            StatusCode = "0x0",
            Timestamp = timestamp,
            Username = "Administrator",
            SourceIp = "10.20.14.37",
            ServicePrincipalName = "cifs/APP02"
        };

        List<AuthenticationCorrelation> testEvents = [
                new AuthenticationCorrelation {
                    Timestamp = timestamp,
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Failed,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                },
                new AuthenticationCorrelation {
                    Timestamp = timestamp.AddMinutes(1),
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Failed,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                },
                new AuthenticationCorrelation {
                    Timestamp = timestamp.AddMinutes(2),
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Failed,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                },
                new AuthenticationCorrelation {
                    Timestamp = timestamp.AddMinutes(3),
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Successful,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                }
            ];

        var targetIdentifier = testEvents[0];

            switch (identifierToModify)
            {
                case "Username":
                    targetIdentifier.Username = identifierValue;
                    break;
                case "DestinationHost":
                    targetIdentifier.DestinationHost = identifierValue;
                    break;
            }

        var detector = new SuccessfulAuthenticationAfterFailuresDetector();
        var findings = detector.Detect(testEvents);

        Assert.Single(findings);
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Theory]
    [InlineData(AuthenticationOutcome.Unknown)]
    [InlineData(AuthenticationOutcome.Ambiguous)]
    public void Detect_UncertainAuthenticationOutcome_ReturnsNoFinding(
        AuthenticationOutcome uncertainOutcome)
    {
        var timestamp = new DateTime(2026, 10, 20, 09, 18, 00, DateTimeKind.Utc);

        var kerberosEvent = new SecurityEvent
        {
            EventId = 4769,
            StatusCode = "0x0",
            Timestamp = timestamp,
            Username = "Administrator",
            SourceIp = "10.20.14.37",
            ServicePrincipalName = "cifs/APP02"
        };

        List<AuthenticationCorrelation> testEvents = [
                new AuthenticationCorrelation {
                    Timestamp = timestamp,
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Failed,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                },
                new AuthenticationCorrelation {
                    Timestamp = timestamp.AddMinutes(1),
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Failed,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                },
                new AuthenticationCorrelation {
                    Timestamp = timestamp.AddMinutes(2),
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Failed,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                },
                new AuthenticationCorrelation {
                    Timestamp = timestamp.AddMinutes(3),
                    Username = "Administrator",
                    SourceIp = "10.20.14.37",
                    DestinationHost = "APP02",
                    LogonType = null,
                    AuthOutcome = AuthenticationOutcome.Successful,
                    SupportingEvents = new List<SecurityEvent>
                    {
                        kerberosEvent
                    }
                }
            ];

        var targetIdentifier = testEvents[0];

        targetIdentifier.AuthOutcome = uncertainOutcome;

        var detector = new SuccessfulAuthenticationAfterFailuresDetector();
        var findings = detector.Detect(testEvents);
        
        Assert.Empty(findings);
    }
}