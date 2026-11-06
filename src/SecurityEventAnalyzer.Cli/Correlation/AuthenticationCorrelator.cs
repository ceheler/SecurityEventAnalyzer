using SecurityEventAnalyzer.Cli.Models;
using System.Globalization;

namespace SecurityEventAnalyzer.Cli.Correlation
{
    public class AuthenticationCorrelator
    {
        public List<AuthenticationCorrelation> Correlate (List<SecurityEvent> events)
        {
            var correlations = new List<AuthenticationCorrelation>();
            var kerberosEvents = events.Where(x => x.EventId == 4769);
            var failedRemoteLogons = events.Where(x => x.EventId == 4625 && x.LogonType == 3);
            var successfulRemoteLogons = events.Where(x => x.EventId == 4624 && x.LogonType == 3);
            var logons = failedRemoteLogons.Concat(successfulRemoteLogons).OrderBy(x => x.Timestamp).ToList();

            foreach(var kerberosEvent in kerberosEvents)
            {
                var supportingEvents = new List<SecurityEvent> { kerberosEvent };
                string destinationPrincipal = kerberosEvent.ServicePrincipalName ?? "";
                string[] destinationHostSplit = destinationPrincipal.Split('/');
                if (destinationHostSplit.Length != 2 ||
                    string.IsNullOrWhiteSpace(kerberosEvent.Username)||
                    string.IsNullOrWhiteSpace(kerberosEvent.SourceIp) ||
                    string.IsNullOrWhiteSpace(destinationHostSplit[0])||
                    string.IsNullOrWhiteSpace(destinationHostSplit[1])
                    )
                {
                    continue;
                }
                
                string status = kerberosEvent.StatusCode ?? "";
                if (string.IsNullOrWhiteSpace(status) ||
                    status.StartsWith("0x", StringComparison.OrdinalIgnoreCase) == false)
                {
                    continue;
                }
                string hexValue = status.Substring(2);
                if (!int.TryParse(hexValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int statusCode) || statusCode != 0)
                {
                    continue;
                }


                string destinationHost = destinationHostSplit[1];
                foreach(var entry in logons)
                {
                    TimeSpan timeDifference = entry.Timestamp - kerberosEvent.Timestamp;

                    if (string.IsNullOrWhiteSpace(entry.Username)||
                        string.IsNullOrWhiteSpace(entry.SourceIp) ||
                        string.IsNullOrWhiteSpace(entry.Computer)
                        )
                        {
                            continue;
                        }

                    if (string.Equals(kerberosEvent.Username, entry.Username, StringComparison.OrdinalIgnoreCase)
                        && kerberosEvent.SourceIp == entry.SourceIp
                        && string.Equals(destinationHost, entry.Computer, StringComparison.OrdinalIgnoreCase)
                        && timeDifference >= TimeSpan.Zero
                        && timeDifference <= TimeSpan.FromSeconds(20))
                    {
                        supportingEvents.Add(entry);
                    }
                    
                }

                var correlation = GenerateCorrelation(supportingEvents);
                correlations.Add(correlation);
            }

        for (int i = 0; i < (correlations.Count - 1); i++)
            {
                for (int j = i + 1; j < correlations.Count; j++)
                {
                    var correlationA = correlations[i];
                    var correlationB = correlations[j];

                    bool sharedLogon = correlationA.SupportingEvents.Skip(1).Any(e1 => correlationB.SupportingEvents.Skip(1).Any(e2 => ReferenceEquals(e1, e2)));

                    if (sharedLogon)
                    {
                        correlationA.AuthOutcome = AuthenticationOutcome.Ambiguous;
                        correlationB.AuthOutcome = AuthenticationOutcome.Ambiguous;
                    }
                }
            }

        return correlations;
        }

    private AuthenticationCorrelation GenerateCorrelation (List<SecurityEvent> securityEvents)
    {
            if (securityEvents == null || securityEvents.Count == 0)
            {
                throw new ArgumentException("Security events list cannot be null or empty.", nameof(securityEvents));
            }

            var destinationHostSplit = securityEvents[0].ServicePrincipalName?.Split('/');
            var destinationHost = destinationHostSplit?.Length == 2 ? destinationHostSplit[1] : null;
            var authentication = AuthenticationOutcome.Ambiguous;
            
            if (securityEvents.Count == 1)
            {
                authentication = AuthenticationOutcome.Unknown;
            }
            else if (securityEvents.Count == 2)
            {
                if (securityEvents[1].EventId == 4624)
                {
                    authentication = AuthenticationOutcome.Successful;
                }
                else if (securityEvents[1].EventId == 4625)
                {
                    authentication = AuthenticationOutcome.Failed;
                }
            }

            var correlation = new AuthenticationCorrelation
                {
                    Timestamp = securityEvents[0].Timestamp,
                    Username = securityEvents[0].Username,
                    SourceIp = securityEvents[0].SourceIp,
                    DestinationHost = destinationHost,
                    LogonType = securityEvents.Count > 1 ? securityEvents[1].LogonType : null,
                    AuthOutcome = authentication,
                    SupportingEvents = securityEvents
                };
            
            return correlation;
        }
    }
}