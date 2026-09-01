using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Cli.Detection
{
    public class PrivilegedGroupMembershipDetector : IDetectionRule
    {
        public List<SecurityFinding> Detect(List<SecurityEvent> importedEvents) 
        {
            if (importedEvents.Count == 0)
            {
                return [];
            }
            var detections = new List<SecurityFinding>();
            var privilegedGroupMembershipEvents = importedEvents.Where(e => e.EventId == 4728);
            foreach (var securityEvent in privilegedGroupMembershipEvents)
            {
                Severity severity;
                StringComparison comp = StringComparison.OrdinalIgnoreCase;
                var targetGroup = securityEvent.TargetGroup;
                if (!string.IsNullOrWhiteSpace(targetGroup))
                {
                    if (targetGroup.Contains("Domain Admins", comp) || targetGroup.Contains("Enterprise Admins", comp))
                    {
                        severity = Severity.High;
                    }
                    else if (targetGroup.Contains("admin", comp))
                    {
                        severity = Severity.Medium;
                    }
                    else
                    {
                        severity = Severity.Low;
                    }
                }
                else 
                {
                    severity = Severity.Low;
                }
                detections.Add(new SecurityFinding
                {
                    RuleName = "Privileged Group Membership Change Detected",
                    Username = securityEvent.Username,
                    TargetUser = securityEvent.TargetUser,
                    TargetGroup = securityEvent.TargetGroup,
                    SourceIp = securityEvent.SourceIp,
                    Description = $"Account username: {securityEvent.TargetUser} was added to {securityEvent.TargetGroup}",
                    Timestamp = securityEvent.Timestamp,
                    Severity = severity
                });
                
            }
            return detections;
        }
    }
}
