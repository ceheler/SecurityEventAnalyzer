using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Cli.Detection
{
    public class DetectionEngine
    {
        private readonly List<IDetectionRule> ruleList = new List<IDetectionRule>();
        private readonly List<IAuthenticationDetectionRule> authenticationRuleList;
        public DetectionEngine(List<IDetectionRule> rules, List<IAuthenticationDetectionRule>? authenticationRules = null) 
        { 
            ruleList = rules; 
            authenticationRuleList = authenticationRules ?? new List<IAuthenticationDetectionRule>();
        }

        public List<SecurityFinding> Detect(List<SecurityEvent> importedEvents, List<AuthenticationCorrelation>? authenticationCorrelations = null) 
        {
            if (importedEvents == null) { return new List<SecurityFinding>(); }
            
            List<SecurityFinding> findings = [];
            foreach (var rule in ruleList)
            {
                var detection = rule.Detect(importedEvents);
                findings.AddRange(detection);
                
            }
            if (authenticationCorrelations?.Count > 0)
            {
                foreach (var authRule in authenticationRuleList)
                {
                    var authDetection = authRule.Detect(authenticationCorrelations);
                    findings.AddRange(authDetection);
                }
            }
            return findings;
        }
    }
}