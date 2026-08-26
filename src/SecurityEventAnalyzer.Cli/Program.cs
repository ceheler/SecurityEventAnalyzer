using System;
using System.Diagnostics.Tracing;
using System.IO;
using System.Text.Json;

class Program
{
    static void Main(string[] args)
    {
        // Provide user with help if no comand line argument is passed to the program
        if (args.Length == 0)
        {
            Console.WriteLine("Error: No command argument specified.");
            Console.WriteLine("Usage: SecurityEventAnalyzer <path-to-log>");
            return;
            // TODO: Validate path, encompas in try catch for error handling
        }
            string inputFile = args[0];

            if (System.IO.File.Exists(inputFile))
            {
                string content = System.IO.File.ReadAllText(inputFile);
                Console.WriteLine("File provided");
                Events[] events = JsonSerializer.Deserialize<Events[]>(content);
                Console.WriteLine("Processed " + events.Length + " events");
            }
        }
}

public class Events
{
    public DateTime timestamp { get; set; }
    public string EventID { get; set; }
    public string Computer { get; set; }
    public string Username { get; set; }
    public string SourceIP { get; set; }
    public string EventType { get; set; }
    public string Level { get; set; }
    public string Message { get; set; }
}