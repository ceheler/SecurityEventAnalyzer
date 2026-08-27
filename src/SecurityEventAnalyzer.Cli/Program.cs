using System;
using System.IO;
using System.Text.Json;

class Program
{
    static void Main(string[] args)
    {
        // Provide user with help if no command line argument is passed to the program
        if (args.Length == 0)
        {
            Console.WriteLine("Error: No command argument specified.");
            Console.WriteLine("Usage: SecurityEventAnalyzer <path-to-log>");
            return;
            // TODO: Validate path, encompas in try catch for error handling
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
            Console.WriteLine("File provided");
            if (string.IsNullOrWhiteSpace(content))
            {
                Console.WriteLine("Error: Log file returned null or empty. Check log file.");
                return;
            }
            
            SecurityEvent[] events = JsonSerializer.Deserialize<SecurityEvent[]>(content) ?? Array.Empty<SecurityEvent>();
            Console.WriteLine("Processed " + events.Length + " events");

            for (int i = 0; i < events.Length; i++)
            {
                //Event itterative loop for logic
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