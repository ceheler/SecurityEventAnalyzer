using System;

namespace SecurityEventAnalyzer.Cli
{
    public class SecurityEvent
    {
        public DateTime Timestamp { get; set; }
        public int EventId { get; set; }
        public string Computer { get; set; }
        public string Username { get; set; }
        public string SourceIp { get; set; }
        public string EventType { get; set; }
        public string Level { get; set; }
        public string Message { get; set; }
        public string? TargetUser { get; set; }
    }
}
