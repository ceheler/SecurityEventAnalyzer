using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Cli.Detection
{
    public class DetectionEngine
    {
        private readonly List<IDetectionRule> ruleList = new List<IDetectionRule>();
        public DetectionEngine(List<IDetectionRule> rules) { ruleList = rules; }

        public List<SecurityFinding> Detect(List<SecurityEvent> importedEvents) 
        {
            if (importedEvents == null) { return new List<SecurityFinding>(); }
            
            List<SecurityFinding> findings = [];
            foreach (var rule in ruleList)
            {
                var detection = rule.Detect(importedEvents);
                findings.AddRange(detection);
                
            }
            return findings;
        }
    }
}