using SecurityEventAnalyzer.Cli.Enums;

namespace SecurityEventAnalyzer.Cli.Models
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
        public string? TargetGroup { get; set; }
        public Severity Severity { get; set; }

        public IEnumerable<string> GetFindingDetails()
        {
            if (!string.IsNullOrWhiteSpace(Username))
                yield return $"User: {Username}";

            if (!string.IsNullOrWhiteSpace(TargetUser))
                yield return $"Target User: {TargetUser}";

            if (!string.IsNullOrWhiteSpace(TargetGroup))
                yield return $"Target Group: {TargetGroup}";

            if (!string.IsNullOrWhiteSpace(SourceIp))
                yield return $"Source IP: {SourceIp}";

            if (!string.IsNullOrWhiteSpace(Computer))
                yield return $"Computer: {Computer}";

            if (Count.HasValue)
                yield return $"Count: {Count}";
        }
    }


}