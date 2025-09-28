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
    }
}