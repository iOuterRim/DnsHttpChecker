using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;

public class DnsHttpChecker
{
    private readonly string _domain;
    private readonly int _timeoutMs;

    public DnsHttpChecker(string domain, int timeoutMs = 5000)
    {
        _domain = domain;
        _timeoutMs = timeoutMs;
    }

    public async Task RunAsync()
    {
        Console.WriteLine($"Resolving {_domain} ...");
        var addresses = await Dns.GetHostAddressesAsync(_domain);

        foreach (var ip in addresses)
        {
            string url = ip.AddressFamily == AddressFamily.InterNetworkV6
                ? $"https://[{ip}]"
                : $"https://{ip}";

            string ptr = "(no PTR)";
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(ip);
                ptr = hostEntry.HostName;
            }
            catch { }

            Console.WriteLine($"\nChecking {url} (Host={_domain}, PTR={ptr})");

            try
            {
                var sw = Stopwatch.StartNew();
                string status = await CheckServerAsync(ip, _domain, 443);
                sw.Stop();
                Console.WriteLine($"  -> {status} ({sw.ElapsedMilliseconds} ms)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  -> ERROR: {ex.Message}");
            }
        }
    }

    private async Task<string> CheckServerAsync(IPAddress ip, string domain, int port)
    {
        using var client = new TcpClient(ip.AddressFamily);
        var connectTask = client.ConnectAsync(ip, port);
        if (await Task.WhenAny(connectTask, Task.Delay(_timeoutMs)) != connectTask)
            throw new TimeoutException("Connection timed out");

        using var ssl = new SslStream(client.GetStream(), false,
            (sender, cert, chain, errors) =>
            {
                if (errors == SslPolicyErrors.None) return true;
                throw new Exception($"SSL validation failed: {errors}");
            });

        // Use domain for SNI + cert validation
        await ssl.AuthenticateAsClientAsync(domain);

        string request = $"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n";
        byte[] reqBytes = Encoding.ASCII.GetBytes(request);
        await ssl.WriteAsync(reqBytes, 0, reqBytes.Length);

        byte[] buffer = new byte[4096];
        int read = await ssl.ReadAsync(buffer, 0, buffer.Length);
        string response = Encoding.ASCII.GetString(buffer, 0, read);

        string firstLine = response.Split("\r\n")[0];
        return firstLine;
    }
}
