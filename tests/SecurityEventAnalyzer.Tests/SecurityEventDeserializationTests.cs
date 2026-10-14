using SecurityEventAnalyzer.Cli.Models;
using System.Text.Json;

public class SecurityEventDeserializationTests
{
    [Fact]
    public void DeserializeSecurityEvent_ValidCloudEvent_PopulatesCloudFields()
    {
        string json = """
        [
          {
            "Timestamp": "2026-10-13T21:59:31Z",
            "Service": "CloudTrail",
            "EventType": "CloudApiCall",
            "Action": "RunInstances",
            "Username": "TerraformExecutionRole",
            "SourceIp": "192.0.2.10",
            "ResourceType": "AWS::EC2::Instance",
            "ResourceId": "i-0123456789abcdef0"
          }
        ]
        """;

        SecurityEvent[] events = JsonSerializer.Deserialize<SecurityEvent[]>(json) ?? Array.Empty<SecurityEvent>();

        Assert.Single(events);
        Assert.Equal("RunInstances", events[0].Action);
        Assert.Equal("AWS::EC2::Instance", events[0].ResourceType);
        Assert.Equal("i-0123456789abcdef0", events[0].ResourceId);
    }
}