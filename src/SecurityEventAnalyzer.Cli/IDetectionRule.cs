using System;
using System.Collections.Generic;


namespace SecurityEventAnalyzer.Cli
{
    public interface IDetectionRule
    {
        List<SecurityFinding> Detect(List<SecurityEvent> events);
    }
}
