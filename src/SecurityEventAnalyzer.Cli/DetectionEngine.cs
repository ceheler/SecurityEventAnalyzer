using System;
using System.Collections.Generic;

namespace SecurityEventAnalyzer.Cli
{
    public class DetectionEngine
    {
        public List<SecurityFinding> Detect(List<SecurityEvent> importedEvents) 
        {
            if (importedEvents == null) { return new List<SecurityFinding>(); }
            List<IDetectionRule> ruleList = [new BruteForceDetector(), new AccountCreationDetector()];
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