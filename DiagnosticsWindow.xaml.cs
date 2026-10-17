using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Media;

namespace GodEx;

public partial class DiagnosticsWindow : Window
{
    private bool _running;

    public DiagnosticsWindow()
    {
        InitializeComponent();
    }

    private async void RunChecks_Click(object sender, RoutedEventArgs e)
    {
        if (_running) return;
        _running = true;
        RunButton.IsEnabled = false;
        RunButton.Content = "Проверка…";
        SummaryText.Text = "Выполняются сетевые проверки. Это может занять несколько секунд.";

        SetIndicator(DnsDot, DnsStatus, "Проверка…", "#D8B76A");
        SetIndicator(RouteDot, RouteStatus, "Проверка…", "#D8B76A");
        SetIndicator(HttpsDot, HttpsStatus, "Проверка…", "#D8B76A");
        DnsOutput.Text = "Выполняются DNS-запросы…";
        RouteOutput.Text = "Читаются сетевые адаптеры и таблица маршрутов…";
        HttpsOutput.Text = "Выполняется HTTPS-запрос…";

        try
        {
            var dnsTask = CheckDnsAsync();
            var routeTask = CheckRoutesAsync();
            var httpsTask = CheckHttpsAsync();
            await Task.WhenAll(dnsTask, routeTask, httpsTask);

            var dns = await dnsTask;
            var routes = await routeTask;
            var https = await httpsTask;

            DnsOutput.Text = dns.Details;
            RouteOutput.Text = routes.Details;
            HttpsOutput.Text = https.Details;

            SetIndicator(DnsDot, DnsStatus, dns.Passed ? "Доступен" : "Ошибка",
                dns.Passed ? "#51D6A0" : "#FF6B82");
            DnsDetail.Text = dns.Summary;

            // A readable routing table is a successful diagnostic operation, not proof of VPN routing.
            SetIndicator(RouteDot, RouteStatus, routes.Readable ? "Прочитано" : "Ошибка",
                routes.Readable ? "#D8B76A" : "#FF6B82");
            RouteDetail.Text = routes.Readable
                ? "Сверь выбранные маршруты и VPN-интерфейс в подробностях"
                : "Не удалось прочитать маршруты";

            SetIndicator(HttpsDot, HttpsStatus, https.Passed ? "Доступен" : "Ошибка",
                https.Passed ? "#51D6A0" : "#FF6B82");
            HttpsDetail.Text = https.Summary;

            var passed = (dns.Passed ? 1 : 0) + (routes.Readable ? 1 : 0) + (https.Passed ? 1 : 0);
            SummaryText.Text = $"Проверки завершены: {passed} из 3 успешно. Жёлтый статус маршрутов означает, что таблица прочитана, но VPN-маршрутизация требует проверки вручную.";
        }
        catch (Exception ex)
        {
            SummaryText.Text = "Не удалось завершить диагностику: " + ex.Message;
        }
        finally
        {
            _running = false;
            RunButton.IsEnabled = true;
            RunButton.Content = "Повторить проверки  ↻";
        }
    }

    private static async Task<(bool Passed, string Summary, string Details)> CheckDnsAsync()
    {
        var details = new System.Text.StringBuilder();
        var successCount = 0;
        foreach (var host in new[] { "example.com", "www.cloudflare.com" })
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host).WaitAsync(TimeSpan.FromSeconds(6));
                if (addresses.Length > 0)
                {
                    successCount++;
                    details.AppendLine($"✓ {host}");
                    details.AppendLine("  " + string.Join(", ", addresses.Take(6).Select(a => a.ToString())));
                }
                else
                {
                    details.AppendLine($"✗ {host}: DNS не вернул IP-адресов");
                }
            }
            catch (Exception ex)
            {
                details.AppendLine($"✗ {host}: {ex.GetType().Name}: {ex.Message}");
            }
            details.AppendLine();
        }

        return (successCount > 0,
            $"{successCount}/2 имён разрешено",
            details.ToString().Trim());
    }

    private static async Task<(bool Readable, string Details)> CheckRoutesAsync()
    {
        var details = new System.Text.StringBuilder();
        var activeAdapters = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .ToList();

        details.AppendLine("АКТИВНЫЕ СЕТЕВЫЕ АДАПТЕРЫ");
        foreach (var adapter in activeAdapters)
        {
            var props = adapter.GetIPProperties();
            var ipv4 = props.UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.Address.ToString()).ToArray();
            var gateways = props.GatewayAddresses
                .Select(g => g.Address.ToString())
                .Where(g => g != "0.0.0.0" && g != "::").ToArray();
            var dns = props.DnsAddresses.Select(a => a.ToString()).ToArray();

            details.AppendLine($"• {adapter.Name} [{adapter.NetworkInterfaceType}]");
            if (ipv4.Length > 0) details.AppendLine($"  IPv4: {string.Join(", ", ipv4)}");
            if (gateways.Length > 0) details.AppendLine($"  Шлюз: {string.Join(", ", gateways)}");
            details.AppendLine($"  DNS: {(dns.Length == 0 ? "не указаны" : string.Join(", ", dns))}");
        }

        details.AppendLine();
        details.AppendLine("ТАБЛИЦА МАРШРУТИЗАЦИИ IPv4");
        try
        {
            var result = await RunCommandAsync("route.exe", new[] { "print", "-4" }, 7000);
            if (result.ExitCode != 0)
            {
                details.AppendLine("Не удалось получить таблицу маршрутов.");
                details.AppendLine(result.Output);
                return (false, details.ToString().Trim());
            }

            var lines = result.Output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var selected = lines.Where(line =>
                    line.Contains("0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
                    line.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                    line.Contains("Wintun", StringComparison.OrdinalIgnoreCase))
                .Take(18)
                .ToArray();

            details.AppendLine(selected.Length == 0
                ? "Команда выполнена, но типичные default/VPN-строки не удалось выделить. См. route print -4 в терминале Windows для полной таблицы."
                : string.Join(Environment.NewLine, selected.Select(line => line.Trim())));
            details.AppendLine();
            details.AppendLine("Интерпретация: строки default route не доказывают сами по себе, что весь трафик направлен через VPN. Имя VPN-интерфейса зависит от установки.");

            return (true, details.ToString().Trim());
        }
        catch (Exception ex)
        {
            details.AppendLine($"Ошибка чтения маршрутов: {ex.GetType().Name}: {ex.Message}");
            return (false, details.ToString().Trim());
        }
    }

    private static async Task<(bool Passed, string Summary, string Details)> CheckHttpsAsync()
    {
        using var handler = new HttpClientHandler { AllowAutoRedirect = true };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        try
        {
            using var response = await client.GetAsync("https://example.com/");
            var ok = (int)response.StatusCode is >= 200 and < 400;
            var detail = $"URL: https://example.com/\nHTTP статус: {(int)response.StatusCode} ({response.StatusCode})\nВремя проверки: {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
            return (ok, ok ? $"HTTP {(int)response.StatusCode}" : "HTTP-ошибка", detail);
        }
        catch (Exception ex)
        {
            return (false, "HTTPS-запрос не прошёл",
                $"URL: https://example.com/\nОшибка: {ex.GetType().Name}: {ex.Message}\nПроверь интернет, DNS, TLS и настройки сети.");
        }
    }

    private static async Task<(int ExitCode, string Output)> RunCommandAsync(
        string fileName, IEnumerable<string> arguments, int timeoutMs)
    {
        var start = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException($"Не удалось запустить {Path.GetFileName(fileName)}.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(timeoutMs);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"Команда {Path.GetFileName(fileName)} превысила лимит {timeoutMs} мс.");
        }

        return (process.ExitCode, ((await stdout) + Environment.NewLine + (await stderr)).Trim());
    }

    private static void SetIndicator(System.Windows.Shapes.Ellipse dot, System.Windows.Controls.TextBlock label,
        string text, string color)
    {
        var brush = (SolidColorBrush)new BrushConverter().ConvertFromString(color)!;
        dot.Fill = brush;
        label.Text = text;
    }
}
