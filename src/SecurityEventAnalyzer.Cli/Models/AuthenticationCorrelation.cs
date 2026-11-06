namespace SecurityEventAnalyzer.Cli.Models
{
    public class AuthenticationCorrelation
    {
        public required DateTime Timestamp { get; set; }
        public required IReadOnlyList<SecurityEvent> SupportingEvents { get; set; }
        public string? Username { get; set; }
        public string? SourceHost { get; set; }
        public string? SourceIp { get; set; }
        public string? DestinationHost { get; set; }
        public string? DestinationIp { get; set; }
        public int? LogonType { get; set; }
        public required AuthenticationOutcome AuthOutcome { get; set; }
        
    }

    public enum AuthenticationOutcome
    {
        Unknown = 0,
        Successful,
        Failed,
        Ambiguous
    }
}