using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Generic;

public class DnsHttpChecker
{
    public class Result
    {
        public IPAddress IP { get; set; }
        public string Url { get; set; } = "";
        public string Ptr { get; set; } = "";
        public string StatusLine { get; set; } = "";
        public string StatusCode { get; set; } = "";
        public long TimeMs { get; set; }
        public string Error { get; set; } = "";
    }

    private readonly string _domain;
    private readonly int _timeoutMs;

    public DnsHttpChecker(string domain, int timeoutMs = 5000)
    {
        _domain = domain;
        _timeoutMs = timeoutMs;
    }

    public async Task<List<Result>> CheckAllAsync()
    {
        var results = new List<Result>();

        IPAddress[] addresses = await Dns.GetHostAddressesAsync(_domain);
        foreach (var ip in addresses)
        {
            var result = await CheckSingleAsync(ip);
            results.Add(result);
        }

        return results;
    }

    private async Task<Result> CheckSingleAsync(IPAddress ip)
    {
        var res = new Result { IP = ip };

        // Proper URL representation
        res.Url = ip.AddressFamily == AddressFamily.InterNetworkV6
            ? $"https://[{ip}]"
            : $"https://{ip}";

        // PTR (reverse DNS)
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip);
            res.Ptr = entry.HostName;
        }
        catch
        {
            res.Ptr = "(no PTR)";
        }

        try
        {
            var sw = Stopwatch.StartNew();
            string statusLine = await CheckServerAsync(ip, _domain, 443);
            sw.Stop();

            res.TimeMs = sw.ElapsedMilliseconds;
            res.StatusLine = statusLine;

            var parts = statusLine.Split(' ');
            if (parts.Length >= 2 && parts[0].StartsWith("HTTP/"))
                res.StatusCode = parts[1];
        }
        catch (Exception ex)
        {
            res.Error = ex.Message;
        }

        return res;
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

        await ssl.AuthenticateAsClientAsync(domain);

        string request = $"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n";
        byte[] reqBytes = Encoding.ASCII.GetBytes(request);
        await ssl.WriteAsync(reqBytes, 0, reqBytes.Length);

        byte[] buffer = new byte[4096];
        int read = await ssl.ReadAsync(buffer, 0, buffer.Length);
        if (read == 0) return "(no response)";

        string response = Encoding.ASCII.GetString(buffer, 0, read);
        return response.Split("\r\n")[0];
    }
}
