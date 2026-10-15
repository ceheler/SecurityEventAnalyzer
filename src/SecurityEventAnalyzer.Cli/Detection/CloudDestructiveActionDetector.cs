using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Cli.Detection
{
    public class CloudDestructiveActionDetector : IDetectionRule
    {
        public List<SecurityFinding> Detect(List<SecurityEvent> importedEvents)
        {
            if (importedEvents.Count == 0)
            {
                return [];
            }

            var detections = new List<SecurityFinding>();

            var cloudTrailEvents = importedEvents.Where(e => e.EventType == "CloudApiCall");
            var detectionEvents = cloudTrailEvents.Where(e => e.Action == "TerminateInstances" ||
                e.Action == "DeleteVpc");

            foreach(var detection in detectionEvents)
            {
                var username = detection.Username ?? "Unknown Principal";
                var resource = detection.ResourceId ?? "Unknown Resource";
                
                detections.Add(new SecurityFinding
                {
                    RuleName = "Cloud Destructive Action Detected",
                    Username = detection.Username,
                    SourceIp = detection.SourceIp,
                    Timestamp = detection.Timestamp,
                    Severity = Severity.Medium,
                    Description = $"Cloud action {detection.Action} performed by {username} against {resource}"
                });
 
            }

            return detections;
        }
    }
}