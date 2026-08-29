using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityEventAnalyzer.Cli
{
    public class BruteForceDetector
    {
        public static List<SecurityFinding> DetectionEngine(List<SecurityEvent> importedEvents)
        {
            var failedLogins = importedEvents.Where(e => e.EventId == 4625);
            var suspLogins = failedLogins.GroupBy(e => new
            {
                e.Username,
                e.SourceIp
            }).ToArray();
            foreach (var logins in suspLogins)
            {
                var orderedLogins = logins.OrderBy(e => e.Timestamp).ToArray();
                int eventGroupCount = orderedLogins.Count();
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
                            
                            break;
                        }
                    }
                }
            }
            return null;
        }
    }
}
