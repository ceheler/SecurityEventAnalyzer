using System;

namespace SecurityEventAnalyzer.Cli
{
    public class SecurityFinding
    {
        public string RuleName { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string Description { get; set; } = string.Empty;
        public string? Username { get; set; }
        public string? SourceIp { get; set; }
        public int? Count { get; set; }
        public string? Computer { get; set; }
        public string? TargetUser { get; set; }
        public Severity Severity { get; set; }
    }
}