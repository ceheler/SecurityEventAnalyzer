using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Cli.Detection
{
    public class GroupMembershipChangeDetector : IDetectionRule
    {
        public List<SecurityFinding> Detect(List<SecurityEvent> importedEvents) 
        {
            if (importedEvents.Count == 0)
            {
                return [];
            }
            var detections = new List<SecurityFinding>();
            var groupMembershipChangedEvents = importedEvents.Where(e => e.EventId == 4728 || e.EventId == 4732);
            foreach (var securityEvent in groupMembershipChangedEvents)
            {
                string scope = "Local";
                if (securityEvent.EventId == 4728)
                {
                    scope = "Global";
                }
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
                if (!string.IsNullOrWhiteSpace(securityEvent.TargetSid))
                {
                    if (string.Equals(securityEvent.TargetSid, "S-1-5-32-544", StringComparison.OrdinalIgnoreCase))
                    {
                        severity = Severity.High;
                    }
                }
                

                var memberIdentity =
                        !string.IsNullOrWhiteSpace(securityEvent.TargetUser)
                        ? securityEvent.TargetUser
                        : !string.IsNullOrWhiteSpace(securityEvent.MemberSid)
                            ? securityEvent.MemberSid
                            : "Unknown";

                detections.Add(new SecurityFinding
                {
                    RuleName = $"{scope} Group Membership Change Detected",
                    Username = securityEvent.Username,
                    TargetUser = securityEvent.TargetUser,
                    TargetGroup = securityEvent.TargetGroup,
                    SourceIp = securityEvent.SourceIp,
                    Timestamp = securityEvent.Timestamp,
                    Severity = severity,
                    Description = $"Member: {memberIdentity} was added to {securityEvent.TargetGroup}"
                });
                
            }
            return detections;
        }
    }
}
