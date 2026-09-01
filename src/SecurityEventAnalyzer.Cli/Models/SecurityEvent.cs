namespace SecurityEventAnalyzer.Cli.Models
{
    public class SecurityEvent
    {
        public required DateTime Timestamp { get; set; }
        public required int EventId { get; set; }
        public string? Computer { get; set; }
        public string? Username { get; set; }
        public string? SourceIp { get; set; }
        public string? EventType { get; set; }
        public string? Level { get; set; }
        public string? Message { get; set; }
        public string? TargetUser { get; set; }
        public string? TargetGroup { get; set; }
    }
}
