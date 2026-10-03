using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;
using System;
using System.Collections.Generic;

namespace SecurityEventAnalyzer.Cli.Detection
{
    public class BruteForceDetector : IDetectionRule
    {
        public List<SecurityFinding> Detect(List<SecurityEvent> importedEvents)
        {
            if (importedEvents.Count == 0)
            {
                return [];
            }
            var detections = new List<SecurityFinding>();
            var failedLogins = importedEvents.Where(e => string.Equals(e.EventType, "FailedAuthentication", 
                StringComparison.OrdinalIgnoreCase) 
                && e.SourceIp is not null 
                && e.TargetUser is not null
                );
            var suspLogins = failedLogins.GroupBy(e => new
            {
                e.TargetUser,
                e.SourceIp,
                e.Computer
            }).ToArray();
            foreach (var logins in suspLogins)
            {
                var orderedLogins = logins.OrderBy(e => e.Timestamp).ToArray();
                int eventGroupCount = orderedLogins.Length;
                if (eventGroupCount >= 5)
                {
                    for (int i = 0; i < eventGroupCount; i++)
                    {
                        DateTime start = orderedLogins[i].Timestamp;
                        DateTime end = start.AddMinutes(5);
                        int eventsInWindow = 0;
                        for (int j = i; j < eventGroupCount; j++)
                        {
                            if (orderedLogins[j].Timestamp <= end)
                            {
                                eventsInWindow++;
                            }
                            else
                            {
                                break;
                            }
                        }
                        if (eventsInWindow >= 5)
                        {
                            detections.Add(new SecurityFinding 
                            {
                                RuleName = "Brute Force Login Detection",
                                Timestamp = start,
                                Description = $"{eventsInWindow} failed logins detected within 5 min window.",
                                TargetUser = logins.Key.TargetUser,
                                SourceIp = logins.Key.SourceIp,
                                Count = eventsInWindow,
                                Severity = Severity.High
                            });
                            break;
                        }
                    }
                }
            }
            return detections;
        }
    }
}