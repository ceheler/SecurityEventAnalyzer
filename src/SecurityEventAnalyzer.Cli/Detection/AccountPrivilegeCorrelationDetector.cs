using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Cli.Detection
{
    public class AccountPrivilegeCorrelationDetector : IDetectionRule 
    {
        public List<SecurityFinding> Detect(List<SecurityEvent> importedEvents)
        {
            if (importedEvents.Count == 0)
            {
                return [];
            }
            TimeSpan correlationWindow = TimeSpan.FromHours(24);
            var detections = new List<SecurityFinding>();
            var accountCreations = importedEvents.Where(e => e.EventId == 4720);
            var successfulLogons = importedEvents.Where(e => e.EventId == 4624);
            var privilegedLogons = importedEvents.Where(e => e.EventId == 4672);
            var groupChanges = importedEvents.Where(e => e.EventId == 4728 || e.EventId == 4732);
            var groupChangesByMemberSid = groupChanges.Where(e => !string.IsNullOrEmpty(e.MemberSid)).ToLookup(e => e.MemberSid!, StringComparer.OrdinalIgnoreCase);
            foreach (var accountCreation in accountCreations)
            {

                StringComparison comp = StringComparison.OrdinalIgnoreCase;

                if (string.IsNullOrWhiteSpace(accountCreation.TargetSid))
                {
                    continue;
                }

                var relatedGroupChanges = groupChangesByMemberSid[accountCreation.TargetSid];
                var computer = accountCreation.Computer;

                foreach (var groupChange in relatedGroupChanges)
                {
                    var creationTimestamp = accountCreation.Timestamp;
                    var findingTimestamp = groupChange.Timestamp;
                    SecurityEvent? matchedPrivilegedLogin = null;
                    string description = "";

                    if (groupChange.Timestamp >= creationTimestamp 
                        && groupChange.Timestamp <= creationTimestamp + correlationWindow
                        && string.Equals(accountCreation.Computer, groupChange.Computer, comp))
                    {
                        bool isPrivilegedGroup = string.Equals(groupChange.TargetGroup, "Domain Admins", comp)
                            || string.Equals(groupChange.TargetGroup, "Enterprise Admins", comp)
                            || string.Equals(groupChange.TargetGroup, "Administrators", comp)
                            || string.Equals(groupChange.TargetSid, "S-1-5-32-544", comp);
                        
                        if (!isPrivilegedGroup)
                        {
                            continue;
                        }

                        var privilegedLogins = successfulLogons.Where(e => string.Equals(e.TargetUser, accountCreation.TargetUser, comp) 
                        && string.Equals(e.Computer, computer, comp) 
                        && e.Timestamp >= groupChange.Timestamp
                        && e.Timestamp <= groupChange.Timestamp + correlationWindow);

                        foreach (var login in privilegedLogins) 
                        {
                            var privilegesAssignedToLogin = privilegedLogons.Where(e => 
                            string.Equals(e.Username, login.TargetUser, comp) 
                            && string.Equals(e.Computer, computer, comp)
                            && string.Equals(e.LogonId, login.LogonId, comp)
                            && e.Timestamp >= login.Timestamp);

                            if (privilegesAssignedToLogin.Any())
                            {
                                matchedPrivilegedLogin = login;
                                break;
                            }

                        }

                        if (matchedPrivilegedLogin != null) 
                        {
                            description = $"Account {accountCreation.TargetUser} was created and added to {groupChange.TargetGroup} within 24 hours,\n" +
                                $"and a privileged session was observed at {matchedPrivilegedLogin.Timestamp}. See LogonID {matchedPrivilegedLogin.LogonId}";
                        }
                        else
                        {
                            description = $"Account {accountCreation.TargetUser} was created and added to {groupChange.TargetGroup} within 24 hours.";
                        }


                        var finding = new SecurityFinding
                        {
                            RuleName = "AccountPrivilegeCorrelation",
                            Timestamp = findingTimestamp,
                            Description = description,
                            Username = accountCreation.Username,
                            SourceIp = matchedPrivilegedLogin?.SourceIp ?? accountCreation.SourceIp,
                            Computer = computer,
                            TargetUser = accountCreation.TargetUser,
                            TargetGroup = groupChange.TargetGroup,
                            Severity = Severity.Critical
                        };
                        detections.Add(finding);
                    }
                }
            }
            return detections;
        }
    }
}
