using DnsHttpCheckerLib;

class Program
{
    static async Task Main()
    {
        var checker = new DnsHttpChecker("all.api.radio-browser.info");
        var results = await checker.CheckAllAsync();

        foreach (var r in results)
        {
            Console.WriteLine($"{r.Url} (PTR={r.Ptr})");

            if (!string.IsNullOrEmpty(r.Error))
            {
                Console.WriteLine($"  ERROR: {r.Error}");
            }
            else
            {
                Console.WriteLine($"  Status: {r.StatusLine}  Time: {r.TimeMs}ms");
            }
        }

        var fastest_result = await checker.GetFastestServerAsync();

        if (fastest_result != null)
        {
            Console.WriteLine($"\nFastest working server: {fastest_result.Url} (PTR={fastest_result.Ptr})");
            Console.WriteLine($"  Status: {fastest_result.StatusLine}  Time: {fastest_result.TimeMs}ms");
        }
        else
        {
            Console.WriteLine("\nNo working servers found.");
        }

    }
}