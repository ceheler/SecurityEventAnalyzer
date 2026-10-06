using System;
using System.Collections.Generic;
using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Cli.Detection
{
    public class PortScanDetector : IDetectionRule
    {
        public List<SecurityFinding> Detect(List<SecurityEvent> importedEvents)
        {
            if (importedEvents.Count == 0)
            {
                return new List<SecurityFinding>();
            }
            var detections = new List<SecurityFinding>();
            var blockedConnections = importedEvents.FindAll(e => string.Equals(e.EventType, "NetworkConnectionBlocked", StringComparison.OrdinalIgnoreCase)
            && e.SourceIp is not null
            && e.DestinationPort is not null
            && e.DestinationIp is not null
            && e.Protocol is not null
            );

            var groupedBlockedConnections = blockedConnections.GroupBy(e => new
            {
                e.SourceIp,
                e.DestinationIp,
                e.Protocol
            });

            foreach (var portScanEvent in groupedBlockedConnections)
            {
                var orderedEvents = portScanEvent.OrderBy(e => e.Timestamp).ToArray();

                if (orderedEvents.Length >= 4)
                {
                    for (int i = 0; i < orderedEvents.Length; i++)
                    {
                        DateTime start = orderedEvents[i].Timestamp;
                        DateTime end = start.AddMinutes(1);
                        var distinctPortList = new HashSet<int>();
                        for (int j = i; j < orderedEvents.Length; j++)
                        {
                            if (orderedEvents[j].Timestamp <= end)
                            {
                                distinctPortList.Add(orderedEvents[j].DestinationPort.Value);
                            }
                            else
                            {
                                break;
                            }
                        }

                        if (distinctPortList.Count >= 4)
                        {
                            detections.Add(new SecurityFinding
                            {
                                RuleName = "Port Scan Detection",
                                Timestamp = start,
                                Description = $"{distinctPortList.Count} distinct blocked destination ports detected within a 1 minute window.",
                                SourceIp = portScanEvent.Key.SourceIp,
                                DestinationIp = portScanEvent.Key.DestinationIp,
                                Count = distinctPortList.Count,
                                Computer = orderedEvents[i].Computer,
                                Severity = Severity.Medium
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
