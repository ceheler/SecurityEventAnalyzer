namespace SecurityEventAnalyzer.Cli.Models
{
    public class SecurityEvent
    {
        public required DateTime Timestamp { get; set; }
        public int? EventId { get; set; }
        public string? Computer { get; set; }
        public string? Username { get; set; }
        public string? SourceIp { get; set; }
        public int? SourcePort { get; set; }
        public string? EventType { get; set; }
        public string? Level { get; set; }
        public string? Message { get; set; }
        public string? TargetUser { get; set; }
        public string? TargetGroup { get; set; }
        public string? TargetDomainName { get; set; }
        public string? MemberSid { get; set; }
        public string? TargetSid { get; set; }
        public string? LogonId { get; set; }
        public string? Service { get; set; }
        public string? AccountValidity { get; set; }
        public string? Protocol { get; set; }
    }
}
