# Usage Guide

Here’s a quick example of how to use the `DnsHttpChecker` class:

```csharp
using DnsHttpCheckerLib;

var checker = new DnsHttpChecker();
var results = await checker.CheckAsync("all.api.radio-browser.info");

foreach (var result in results)
{
    Console.WriteLine($"{result.Url} -> {result.StatusLine}");
}
