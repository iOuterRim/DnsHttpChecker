using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Generic;

/// <summary>
/// Provides DNS resolution, reverse DNS, and HTTP/HTTPS health checks
/// for all resolved IP addresses of a given domain.
/// </summary>
/// <remarks>
/// Version 1.0.0 (2025-09-27)
/// - Initial release with DNS resolution, reverse DNS, and HTTPS probing
/// - Supports IPv4 and IPv6
/// </remarks>
public class DnsHttpChecker
{
    /// <summary>
    /// Represents the result of a single IP address check.
    /// </summary>
    public class Result
    {
        /// <summary>The resolved IP address (IPv4 or IPv6). Defaults to <c>0.0.0.0</c>.</summary>
        public IPAddress IP { get; set; } = IPAddress.None;

        /// <summary>Display URL representation (e.g. https://[::1]). Defaults to empty string.</summary>
        public string Url { get; set; } = string.Empty;

        /// <summary>The PTR (reverse DNS) record, if available. Defaults to empty string.</summary>
        public string Ptr { get; set; } = string.Empty;

        /// <summary>The raw HTTP status line returned (e.g. HTTP/1.1 200 OK). Defaults to empty string.</summary>
        public string StatusLine { get; set; } = string.Empty;

        /// <summary>The parsed HTTP status code (e.g. 200, 404). Defaults to empty string.</summary>
        public string StatusCode { get; set; } = string.Empty;

        /// <summary>Round-trip time in milliseconds for the request. Defaults to 0.</summary>
        public long TimeMs { get; set; } = 0;

        /// <summary>Error description if the request failed. Defaults to empty string.</summary>
        public string Error { get; set; } = string.Empty;
    }

    private readonly string _domain;
    private readonly int _timeoutMs;

    /// <summary>
    /// Initializes a new instance of <see cref="DnsHttpChecker"/>.
    /// </summary>
    /// <param name="domain">The domain to resolve and check.</param>
    /// <param name="timeoutMs">Timeout in milliseconds for network operations.</param>
    public DnsHttpChecker(string domain, int timeoutMs = 5000)
    {
        _domain = domain;
        _timeoutMs = timeoutMs;
    }

    /// <summary>
    /// Resolves the domain and checks all resolved IPs.
    /// </summary>
    /// <returns>A list of <see cref="Result"/> objects with details for each IP.</returns>
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

    /// <summary>
    /// Checks a single IP address for HTTPS availability and status.
    /// </summary>
    /// <param name="ip">The target IP address.</param>
    /// <returns>A <see cref="Result"/> object containing details about the probe.</returns>
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

    /// <summary>
    /// Attempts to connect to the specified server over TLS and issue a basic HTTP request.
    /// </summary>
    /// <param name="ip">The target server IP address (IPv4 or IPv6).</param>
    /// <param name="domain">
    /// The domain name to present in the TLS SNI (Server Name Indication) extension and
    /// the HTTP <c>Host</c> header. Required for virtual-hosted servers with valid certificates.
    /// </param>
    /// <param name="port">The TCP port to connect to (typically 443 for HTTPS).</param>
    /// <returns>
    /// A task that resolves to a string containing either:
    /// <list type="bullet">
    ///   <item>
    ///     <description>The HTTP status line (e.g. <c>HTTP/1.1 200 OK</c>) if the request succeeds.</description>
    ///   </item>
    ///   <item>
    ///     <description>An error description (e.g. <c>SSL ERROR: ...</c>) if the connection or handshake fails.</description>
    ///   </item>
    /// </list>
    /// </returns>
    /// <remarks>
    /// <para>Behavior:</para>
    /// <list type="bullet">
    ///   <item>Opens a raw TCP connection to <paramref name="ip"/>:<paramref name="port"/>.</item>
    ///   <item>Negotiates TLS with SNI set to <paramref name="domain"/>.</item>
    ///   <item>Sends a minimal <c>HEAD / HTTP/1.1</c> request.</item>
    ///   <item>Parses and returns only the first line of the server response.</item>
    /// </list>
    /// <para>Exceptions are caught and converted into error strings for easier diagnostics.</para>
    /// </remarks>
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
