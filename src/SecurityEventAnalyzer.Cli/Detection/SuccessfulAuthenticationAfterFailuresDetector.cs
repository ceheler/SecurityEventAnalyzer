using SecurityEventAnalyzer.Cli.Models;
using SecurityEventAnalyzer.Cli.Enums;

namespace SecurityEventAnalyzer.Cli.Detection
{
    public class SuccessfulAuthenticationAfterFailuresDetector : IAuthenticationDetectionRule
    {
        public List<SecurityFinding> Detect(List<AuthenticationCorrelation> correlations)
        {
            List<SecurityFinding> findings = [];
            var validCorrelations = correlations
            .Where(c => 
                (c.AuthOutcome == AuthenticationOutcome.Failed ||
                c.AuthOutcome == AuthenticationOutcome.Successful) &&
                !string.IsNullOrWhiteSpace(c.Username) &&
                !string.IsNullOrWhiteSpace(c.SourceIp) &&
                !string.IsNullOrWhiteSpace(c.DestinationHost))
            .ToList();

            var groups = validCorrelations
                .GroupBy(c => new
                {
                    Username = c.Username!.ToUpperInvariant(),
                    SourceIp = c.SourceIp,
                    DestinationHost = c.DestinationHost!.ToUpperInvariant()
                });

            foreach (var group in groups)
            {
                var failedAttempts = group.Where(c => c.AuthOutcome == AuthenticationOutcome.Failed).OrderBy(c => c.Timestamp).ToList();
                var successfulAttempts = group.Where(c => c.AuthOutcome == AuthenticationOutcome.Successful).OrderBy(c => c.Timestamp).ToList();

                foreach (var successfulAttempt in successfulAttempts)
                {
                    var windowStart = successfulAttempt.Timestamp.AddMinutes(-5);
                    var precedingFailures = failedAttempts
                        .Where(f => f.Timestamp < successfulAttempt.Timestamp && f.Timestamp >= windowStart)
                        .ToList();

                    if (precedingFailures.Count >= 3)
                    {
                        findings.Add(new SecurityFinding
                        {
                            RuleName = "Successful Authentication After Multiple Failures",
                            Description = $"User '{successfulAttempt.Username}' from IP '{successfulAttempt.SourceIp}' successfully authenticated to '{successfulAttempt.DestinationHost}' after {precedingFailures.Count} failed attempts within 5 minutes.",
                            Timestamp = successfulAttempt.Timestamp,
                            SourceIp = successfulAttempt.SourceIp,
                            TargetUser = successfulAttempt.Username,
                            Severity = Severity.High
                        });

                    }
                }
            }

            return findings;
        }
    }
}