using SecurityEventAnalyzer.Cli.Correlation;
using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Tests
{
    public class AuthenticationCorrelationTests
    {
        [Fact]
        public void Correlate_KerberosTicketAndFailedLogon_ReturnsFailedAuthentication()
        {
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x0",
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc), 
                    Computer = "DC01", 
                    Username = "svc_healthmon", 
                    SourceIp = "10.20.14.37", 
                    ServicePrincipalName = "cifs/APP02"
                    },
                new SecurityEvent {
                    EventId = 4625,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 15, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "SVC_HEALTHMON",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                }];
        
            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Single(results);
            Assert.Equal(testEvents[0].Timestamp, results[0].Timestamp);
            Assert.Equal("svc_healthmon", results[0].Username);
            Assert.Equal("10.20.14.37", results[0].SourceIp);
            Assert.Equal("APP02", results[0].DestinationHost);
            Assert.Equal(3, results[0].LogonType);
            Assert.Equal(AuthenticationOutcome.Failed, results[0].AuthOutcome);
            Assert.Equal(2, results[0].SupportingEvents.Count);
            Assert.Same(testEvents[0], results[0].SupportingEvents[0]);
            Assert.Same(testEvents[1], results[0].SupportingEvents[1]);
        }

        [Fact]
        public void Correlate_DifferentDestination_ReturnsUnknown()
        {
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x0",
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc), 
                    Computer = "DC01", 
                    Username = "svc_healthmon", 
                    SourceIp = "10.20.14.37", 
                    ServicePrincipalName = "cifs/APP02"
                    },
                new SecurityEvent {
                    EventId = 4625,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 15, DateTimeKind.Utc),
                    Computer = "APP03",
                    Username = "SVC_HEALTHMON",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                }];
        
            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Single(results);
            Assert.Equal(AuthenticationOutcome.Unknown, results[0].AuthOutcome);
            Assert.Equal(testEvents[0].Timestamp, results[0].Timestamp);
            Assert.Equal(testEvents[0].Username, results[0].Username);
            Assert.Equal(testEvents[0].SourceIp, results[0].SourceIp);
            Assert.Equal("APP02", results[0].DestinationHost);
            Assert.Null(results[0].LogonType);
            Assert.Single(results[0].SupportingEvents);
            Assert.Same(testEvents[0], results[0].SupportingEvents[0]);
        }

        [Fact]
        public void Correlate_KerberosTicketAndSuccessfulLogon_ReturnsSuccessfulAuthentication()
        {
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x0",
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc), 
                    Computer = "DC01", 
                    Username = "svc_healthmon", 
                    SourceIp = "10.20.14.37", 
                    ServicePrincipalName = "cifs/APP02"
                    },
                new SecurityEvent {
                    EventId = 4624,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 15, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "SVC_HEALTHMON",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                }];
        
            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Single(results);
            Assert.Equal(testEvents[0].Timestamp, results[0].Timestamp);
            Assert.Equal("svc_healthmon", results[0].Username);
            Assert.Equal("10.20.14.37", results[0].SourceIp);
            Assert.Equal("APP02", results[0].DestinationHost);
            Assert.Equal(3, results[0].LogonType);
            Assert.Equal(AuthenticationOutcome.Successful, results[0].AuthOutcome);
            Assert.Equal(2, results[0].SupportingEvents.Count);
            Assert.Same(testEvents[0], results[0].SupportingEvents[0]);
            Assert.Same(testEvents[1], results[0].SupportingEvents[1]);
        }

        [Fact]
        public void Correlate_WrongLogonType_ReturnsUnknown()
        {
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x0",
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc), 
                    Computer = "DC01", 
                    Username = "svc_healthmon", 
                    SourceIp = "10.20.14.37", 
                    ServicePrincipalName = "cifs/APP02"
                    },
                new SecurityEvent {
                    EventId = 4624,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 15, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "SVC_HEALTHMON",
                    SourceIp = "10.20.14.37",
                    LogonType = 2
                }];
        
            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);
        
            Assert.Single(results);
            Assert.Equal(AuthenticationOutcome.Unknown, results[0].AuthOutcome);
            Assert.Equal(testEvents[0].Timestamp, results[0].Timestamp);
            Assert.Equal(testEvents[0].Username, results[0].Username);
            Assert.Equal(testEvents[0].SourceIp, results[0].SourceIp);
            Assert.Equal("APP02", results[0].DestinationHost);
            Assert.Null(results[0].LogonType);
            Assert.Single(results[0].SupportingEvents);
            Assert.Same(testEvents[0], results[0].SupportingEvents[0]);
        }

        [Fact]
        public void Correlate_KerberosTicketWithoutDestinationLogon_ReturnsUnknown()
        {
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x0",
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc), 
                    Computer = "DC01", 
                    Username = "svc_healthmon", 
                    SourceIp = "10.20.14.37", 
                    ServicePrincipalName = "cifs/APP02"
                    }];
        
            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Single(results);
            Assert.Equal("svc_healthmon", results[0].Username);
            Assert.Equal("10.20.14.37", results[0].SourceIp);
            Assert.Equal("APP02", results[0].DestinationHost);
            Assert.Null(results[0].LogonType);
            Assert.Equal(AuthenticationOutcome.Unknown, results[0].AuthOutcome);
            Assert.Single(results[0].SupportingEvents);
            Assert.Same(testEvents[0], results[0].SupportingEvents[0]);
        }

        [Fact]
        public void Correlate_MultipleMatchingLogons_ReturnsAmbiguous()
        {
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x0",
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc), 
                    Computer = "DC01", 
                    Username = "svc_healthmon", 
                    SourceIp = "10.20.14.37", 
                    ServicePrincipalName = "cifs/APP02"
                    },
                new SecurityEvent {
                    EventId = 4625,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 15, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                },
                new SecurityEvent {
                    EventId = 4624,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 17, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                }];

            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Single(results);
            Assert.Equal(AuthenticationOutcome.Ambiguous, results[0].AuthOutcome);
            Assert.Equal(3, results[0].SupportingEvents.Count);
            Assert.Equal("APP02", results[0].DestinationHost);
            Assert.Same(testEvents[0], results[0].SupportingEvents[0]);
            Assert.Same(testEvents[1], results[0].SupportingEvents[1]);
            Assert.Same(testEvents[2], results[0].SupportingEvents[2]);
        }

        [Fact]
        public void Correlate_MultipleFailedLogons_ReturnsAmbiguous()
        {
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc), 
                    Computer = "DC01", 
                    Username = "svc_healthmon",
                    StatusCode = "0x0",
                    SourceIp = "10.20.14.37",
                    ServicePrincipalName = "cifs/APP02"
                    },
                new SecurityEvent {
                    EventId = 4625,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 15, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                },
                new SecurityEvent {
                    EventId = 4625,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 17, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                }];

            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Single(results);
            Assert.Equal(AuthenticationOutcome.Ambiguous, results[0].AuthOutcome);
            Assert.Equal(3, results[0].SupportingEvents.Count);
            Assert.Equal(3, results[0].LogonType);
            Assert.Equal("APP02", results[0].DestinationHost);
            Assert.Same(testEvents[0], results[0].SupportingEvents[0]);
            Assert.Same(testEvents[1], results[0].SupportingEvents[1]);
            Assert.Same(testEvents[2], results[0].SupportingEvents[2]);
        }

        [Fact]
        public void Correlate_FailedKerberosTicketRequest_DoesNotGenerateCorrelation()
        {
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x20",
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc), 
                    Computer = "DC01", 
                    Username = "svc_healthmon", 
                    SourceIp = "10.20.14.37", 
                    ServicePrincipalName = "cifs/APP02"
                    },
                new SecurityEvent {
                    EventId = 4624,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 15, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                }];
            
            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Empty(results);
        }

        [Fact]
        public void Correlate_CompetingKerberosTickets_ReturnsAmbiguous()
        {
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x0",
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc),
                    Computer = "DC01",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    ServicePrincipalName = "cifs/APP02"
                },
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x0",
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 12, DateTimeKind.Utc),
                    Computer = "DC01",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    ServicePrincipalName = "cifs/APP02"
                },
                new SecurityEvent {
                    EventId = 4624,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 15, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                }
            ];

            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Equal(2, results.Count);
            Assert.Equal(AuthenticationOutcome.Ambiguous, results[0].AuthOutcome);
            Assert.Equal(AuthenticationOutcome.Ambiguous, results[1].AuthOutcome);
            Assert.Equal(2, results[0].SupportingEvents.Count);
            Assert.Equal(2, results[1].SupportingEvents.Count);
            Assert.Same(testEvents[0], results[0].SupportingEvents[0]);
            Assert.Same(testEvents[2], results[0].SupportingEvents[1]);
            Assert.Same(testEvents[1], results[1].SupportingEvents[0]);
            Assert.Same(testEvents[2], results[1].SupportingEvents[1]);
            Assert.Equal("APP02", results[0].DestinationHost);
            Assert.Equal("APP02", results[1].DestinationHost);
        }

        [Fact]
        public void Correlate_IndependentKerberosTickets_PreservesOutcomes()
        {
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x0",
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc),
                    Computer = "DC01",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    ServicePrincipalName = "cifs/APP02"
                },
                new SecurityEvent {
                    EventId = 4624,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 15, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                },
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x0",
                    Timestamp = new DateTime(2026, 10, 20, 09, 22, 10, DateTimeKind.Utc),
                    Computer = "DC01",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    ServicePrincipalName = "cifs/APP02"
                },
                new SecurityEvent {
                    EventId = 4625,
                    Timestamp = new DateTime(2026, 10, 20, 09, 22, 15, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                }
            ];

            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Equal(2, results.Count);
            Assert.Equal(AuthenticationOutcome.Successful, results[0].AuthOutcome);
            Assert.Equal(AuthenticationOutcome.Failed, results[1].AuthOutcome);
            Assert.Equal(2, results[0].SupportingEvents.Count);
            Assert.Equal(2, results[1].SupportingEvents.Count);
            Assert.Same(testEvents[0], results[0].SupportingEvents[0]);
            Assert.Same(testEvents[1], results[0].SupportingEvents[1]);
            Assert.Same(testEvents[2], results[1].SupportingEvents[0]);
            Assert.Same(testEvents[3], results[1].SupportingEvents[1]);
        }

        [Theory]
        [InlineData(0, 1, AuthenticationOutcome.Failed)]
        [InlineData(20, 1, AuthenticationOutcome.Failed)]
        [InlineData(21, 1, AuthenticationOutcome.Unknown)]
        [InlineData(-1, 1, AuthenticationOutcome.Unknown)]
        public void Correlate_TimeDifference_RespectsWindow(int secondsDifference, int expectedCount, AuthenticationOutcome expectedOutcome)
        {
            DateTime kerberosTimestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc);
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769, 
                    Timestamp = kerberosTimestamp,
                    StatusCode = "0x0", 
                    Computer = "DC01", 
                    Username = "svc_healthmon", 
                    SourceIp = "10.20.14.37", 
                    ServicePrincipalName = "cifs/APP02"
                    },
                new SecurityEvent {
                    EventId = 4625,
                    Timestamp = kerberosTimestamp.AddSeconds(secondsDifference),
                    Computer = "APP02",
                    Username = "SVC_HEALTHMON",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                }];

            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Equal(expectedCount, results.Count);
            Assert.Equal(expectedOutcome, results[0].AuthOutcome);
        }

        [Theory]
        [InlineData(null, null, "10.20.14.37", "10.20.14.37", 0)]
        [InlineData("", "", "10.20.14.37", "10.20.14.37", 0)]
        [InlineData(" ", " ", "10.20.14.37", "10.20.14.37", 0)]
        [InlineData("svc_healthmon", "svc_healthmon", null, null, 0)]
        [InlineData("svc_healthmon", "svc_healthmon", "", "", 0)]
        [InlineData("svc_healthmon", "svc_healthmon", "10.20.14.37", "10.20.14.37", 1)]
        public void Correlate_ValidatesRequiredIdentifiers(
            string? kerberosUsername,
            string? logonUsername,
            string? kerberosSourceIp,
            string? logonSourceIp,
            int expectedCount)
        {
            DateTime kerberosTimestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc);
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x0",
                    Timestamp = kerberosTimestamp, 
                    Computer = "DC01", 
                    Username = kerberosUsername, 
                    SourceIp = kerberosSourceIp, 
                    ServicePrincipalName = "cifs/APP02"
                    },
                new SecurityEvent {
                    EventId = 4625,
                    Timestamp = kerberosTimestamp.AddSeconds(10),
                    Computer = "APP02",
                    Username = logonUsername,
                    SourceIp = logonSourceIp,
                    LogonType = 3
                }];

            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Equal(expectedCount, results.Count);
        }

        [Theory]
        [InlineData(null, 0)]
        [InlineData("", 0)]
        [InlineData("APP02", 0)]
        [InlineData("cifs/", 0)]
        [InlineData("/APP02", 0)]
        [InlineData("cifs/APP02/extra", 0)]
        [InlineData("cifs/APP02", 1)]
        public void Correlate_InvalidServicePrincipalName_HandlesGracefully(
            string? servicePrincipalName,
            int expectedCount)
        {
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = "0x0",
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc), 
                    Computer = "DC01", 
                    Username = "svc_healthmon", 
                    SourceIp = "10.20.14.37", 
                    ServicePrincipalName = servicePrincipalName
                    },
                new SecurityEvent {
                    EventId = 4625,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 15, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "SVC_HEALTHMON",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                }];

            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Equal(expectedCount, results.Count);
        }

        [Theory]
        [InlineData("0x0", 1)]
        [InlineData("0x00", 1)]
        [InlineData("0x00000000", 1)]
        [InlineData("0X0", 1)]
        [InlineData("0x20", 0)]
        [InlineData("0x6", 0)]
        [InlineData(null, 0)]
        [InlineData("", 0)]
        [InlineData("invalid", 0)]
        public void Correlate_KerberosStatusCode_ValidatesTicketResult(string? statusCode, int expectedCount)
        {
            List<SecurityEvent> testEvents = [
                new SecurityEvent {
                    EventId = 4769,
                    StatusCode = statusCode,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 10, DateTimeKind.Utc), 
                    Computer = "DC01", 
                    Username = "svc_healthmon", 
                    SourceIp = "10.20.14.37", 
                    ServicePrincipalName = "cifs/APP02"
                    },
                new SecurityEvent {
                    EventId = 4624,
                    Timestamp = new DateTime(2026, 10, 20, 09, 21, 15, DateTimeKind.Utc),
                    Computer = "APP02",
                    Username = "svc_healthmon",
                    SourceIp = "10.20.14.37",
                    LogonType = 3
                }];
            
            var correlator = new AuthenticationCorrelator();
            var results = correlator.Correlate(testEvents);

            Assert.Equal(expectedCount, results.Count);
        }
    }
}