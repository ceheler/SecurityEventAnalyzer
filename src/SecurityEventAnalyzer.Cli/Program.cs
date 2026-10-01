using SecurityEventAnalyzer.Cli.Detection;
using SecurityEventAnalyzer.Cli.Models;
using System.Text.Json;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Error: No command argument specified.");
            Console.WriteLine("Usage: SecurityEventAnalyzer <path-to-log>");
            return;
        }
            string inputFile = args[0];

        if (!File.Exists(inputFile))
        {
            Console.WriteLine($"Error: Specified log file '{inputFile}' does not exist.");
            return;
        }

        try
        {
            string content = File.ReadAllText(inputFile);
            List<IDetectionRule> rules =
                [ new BruteForceDetector(),
                  new AccountCreationDetector(),
                  new GroupMembershipChangeDetector(),
                  new AccountPrivilegeCorrelationDetector()
                ];
            var detector = new DetectionEngine(rules);
            Console.WriteLine("\nAnalyzing " + args[0]);
            if (string.IsNullOrWhiteSpace(content))
            {
                Console.WriteLine("Error: Log file returned null or empty. Check log file.");
                return;
            }


            using JsonDocument doc = JsonDocument.Parse(content);

            var fifthEvent = doc.RootElement[4];
            var eventId = fifthEvent.GetProperty("EventId");

            Console.WriteLine("\n--- DEBUG ---");
            Console.WriteLine(fifthEvent.GetRawText());
            Console.WriteLine($"ValueKind: {eventId.ValueKind}");
            Console.WriteLine($"Raw EventId: {eventId.GetRawText()}");
            Console.WriteLine($"TryGetInt32: {eventId.TryGetInt32(out int parsedId)}");
            Console.WriteLine($"Parsed ID: {parsedId}");
            Console.WriteLine($"SecurityEvent.EventId runtime type: " +
                $"{typeof(SecurityEvent).GetProperty(nameof(SecurityEvent.EventId))?.PropertyType}");
            Console.WriteLine($"Loaded model assembly: {typeof(SecurityEvent).Assembly.Location}");
            Console.WriteLine("-------------\n");


            SecurityEvent[] events = JsonSerializer.Deserialize<SecurityEvent[]>(content) ?? Array.Empty<SecurityEvent>();

            if (events.Length == 0)
            {
                Console.WriteLine("Events array contained no usable events");
                return;
            }

            Console.WriteLine("\nLog event summary \n");
            Console.WriteLine("=================== \n");
            Console.WriteLine("Processed " + events.Length + " events\n");
            var findings = detector.Detect(events.ToList());
            if (findings.Count is 0)
            {
                Console.WriteLine("\n No Security findings Detected \n");
            }
            else 
            {
                foreach (var finding in findings)
                {
                    Console.WriteLine($"\n{finding.RuleName}");
                    Console.WriteLine(finding.Description);
                    Console.WriteLine("===================");
                    Console.WriteLine($"Severity: {finding.Severity}");
                    Console.WriteLine($"Timestamp: {finding.Timestamp}");

                    foreach (var detail in finding.GetFindingDetails())
                    {
                        Console.WriteLine(detail);
                    }
                }
            }
        }
        catch (Exception ex) 
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}