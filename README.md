# DnsHttpChecker

A small C# library and helper tool to perform DNS lookups, reverse DNS resolution, and HTTPS availability checks for resolved servers.

## Features
- 🔎 Resolve domain names to IPv4 and IPv6 addresses  
- 🔄 Perform reverse DNS lookups (PTR records)  
- 🌐 Check HTTPS availability of resolved servers (with proper SNI/Host headers)  
- 📖 XML-documented API, with published reference via DocFX  

## Installation
Clone the repository and build using the .NET SDK (≥ 8.0):

```bash
git clone https://github.com/iOuterRim/DnsHttpChecker.git
cd DnsHttpChecker
dotnet build
```
## Usage example

```bash
using DnsHttpCheckerLib;

var checker = new DnsHttpChecker();
var results = await checker.ResolveAndCheckAsync("all.api.radio-browser.info");

foreach (var result in results)
{
    Console.WriteLine($"{result.IP} -> {result.Status}");
}
```
## Documentation

📚 Full API reference and usage guides are available here:
👉 https://iOuterRim.github.io/DnsHttpChecker/

## Project Structure

```bash
/src/DnsHttpChecker       → Library (DnsHttpCheckerLib)
/tests/DnsHttpCheckerTest → Example & test project
```
## Contributing

Pull requests are welcome! Please open an issue to discuss major changes first.
Make sure to update/add documentation if you add features.




