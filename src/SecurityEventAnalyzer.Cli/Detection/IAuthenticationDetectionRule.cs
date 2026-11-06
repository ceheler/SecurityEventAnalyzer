using SecurityEventAnalyzer.Cli.Models;


namespace SecurityEventAnalyzer.Cli.Detection
{
    public interface IAuthenticationDetectionRule
    {
        List<SecurityFinding> Detect(List<AuthenticationCorrelation> correlations);
    }
}