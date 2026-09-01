using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Cli.Detection
{
    public class AccountCreationDetector : IDetectionRule
    {
        public List<SecurityFinding> Detect(List<SecurityEvent> importedEvents)
        {
            if (importedEvents.Count == 0)
            {
                return [];
            }
            var detections = new List<SecurityFinding>();
            var accountCreationList = importedEvents.Where(e => e.EventId == 4720);
            foreach (var accounts in accountCreationList)
            {
                detections.Add(new SecurityFinding
                {
                    RuleName = "Account Creation Detected",
                    Username = accounts.Username,
                    TargetUser = accounts.TargetUser,
                    Computer = accounts.Computer,
                    SourceIp = accounts.SourceIp,
                    Description = $"Account username: {accounts.TargetUser} created on computer {accounts.Computer}",
                    Severity = Severity.Informational,
                    Timestamp = accounts.Timestamp
                });
            }
            return detections;
        }
    }
}