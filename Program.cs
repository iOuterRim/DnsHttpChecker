// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");

var checker = new DnsHttpChecker("all.api.radio-browser.info");
await checker.RunAsync();