# DnsHttpChecker Documentation

Welcome to the documentation for **DnsHttpCheckerLib** — a C# helper library for
performing DNS lookups and HTTP availability checks.

---

## 📖 Getting Started

The library helps you:

- Resolve a domain to IPv4 and IPv6 addresses.
- Perform reverse DNS lookups (PTR).
- Test HTTP/HTTPS endpoints directly against resolved IPs.
- Capture errors, status lines, and full request URLs.

---

## 📚 Documentation

- [API Reference](api/index.md)  
  Detailed API documentation for the `DnsHttpCheckerLib` namespace.

- [Articles](articles/intro.md)  
  Guides, examples, and background information.

---

## 🚀 Example Usage

```csharp
using DnsHttpCheckerLib;

var checker = new DnsHttpChecker();
var results = await checker.CheckDomainAsync("all.api.radio-browser.info");

foreach (var result in results)
{
    Console.WriteLine($"{result.IP} -> {result.StatusLine} ({result.Error})");
}
