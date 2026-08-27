using System;
using System.IO;
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
            Console.WriteLine("Events by ID\n");
            Console.WriteLine("------------------\n");

            var eventGroups = events.GroupBy(e => e.EventId).OrderByDescending(e => e.Key);

            foreach (var secEvent in eventGroups)
            {
                Console.WriteLine($"{secEvent.Key} : {secEvent.Count()}");
            }
            
            
        }

        catch (Exception ex) 
        {
            Console.WriteLine($"Input file error: {ex.Message}");
        }
    }
}

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
}