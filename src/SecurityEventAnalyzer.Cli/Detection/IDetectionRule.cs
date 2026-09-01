using SecurityEventAnalyzer.Cli.Models;


namespace SecurityEventAnalyzer.Cli.Detection
{
    public interface IDetectionRule
    {
        List<SecurityFinding> Detect(List<SecurityEvent> events);
    }
}
