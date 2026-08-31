using SecurityEventAnalyzer.Cli;
using System;
using System.IO;
using System.Linq;
using System.Text.Json;

class Program
{
    static void Main(string[] args)
    {
        // Display usage instructions if proper command line arguments are not passed.
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
            Console.WriteLine("\nAnalyzing " + args[0]);
            if (string.IsNullOrWhiteSpace(content))
            {
                Console.WriteLine("Error: Log file returned null or empty. Check log file.");
                return;
            }
            
            SecurityEvent[] events = JsonSerializer.Deserialize<SecurityEvent[]>(content) ?? Array.Empty<SecurityEvent>();

            if (events.Length == 0)
            {
                Console.WriteLine("Events array contained no usable events");
                return;
            }

            Console.WriteLine("\nLog event summary \n");
            Console.WriteLine("------------------ \n");
            Console.WriteLine("Processed " + events.Length + " events\n");
            
            var findings = BruteForceDetector.Detect(events.ToList());

            foreach (var finding in findings)
            {
                Console.WriteLine(finding.RuleName);
                Console.WriteLine(finding.Description);
                Console.WriteLine("===================");
                Console.WriteLine($"Severity: {finding.Severity}");
                Console.WriteLine($"User: {finding.Username} \nSource Ip: {finding.SourceIp} \nCount: {finding.Count} \nTimestamp: {finding.Timestamp}\n\n");
            }
        }

        catch (Exception ex) 
        {
            Console.WriteLine($"Input file error: {ex.Message}");
        }
    }
}