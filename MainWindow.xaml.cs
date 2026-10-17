using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Windows;
using Microsoft.Win32;

namespace GodEx;

public partial class MainWindow : Window
{
    private string? _configPath;
    private bool _connected;
    private bool _busy;

    public MainWindow() => InitializeComponent();

    private void ImportConfig_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Выбери конфигурацию WireGuard",
            Filter = "WireGuard config (*.conf)|*.conf|Все файлы (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false
        };

        if (dialog.ShowDialog(this) != true)
            return;

        try
        {
            var config = File.ReadAllText(dialog.FileName);
            ValidateWireGuardConfig(config, dialog.FileName);
            _configPath = dialog.FileName;
            _connected = false;
            var tunnelName = Path.GetFileNameWithoutExtension(_configPath);
            ConfigText.Text = $"Конфигурация: {Path.GetFileName(_configPath)}";
            ServerText.Text = tunnelName;
            StatusText.Text = "Конфигурация проверена. Можно подключаться.";
            ConnectButton.Content = "Подключить VPN  →";
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Не удалось импортировать конфигурацию",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void Connect_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        if (_configPath is null)
        {
            MessageBox.Show(
                "Сначала импортируй .conf-файл WireGuard от своего VPN-провайдера или со своего сервера. GodEx не содержит выдуманных серверов и не создаёт ключи за тебя.",
                "Нужна конфигурация WireGuard",
                MessageBoxButton.OK, MessageBoxImage.Information);
            ImportConfig_Click(sender, e);
            return;
        }

        var wireGuard = FindWireGuard();
        if (wireGuard is null)
        {
            var result = MessageBox.Show(
                "Не найден WireGuard for Windows. Установить официальный клиент? После установки вернись в GodEx и нажми подключение ещё раз.",
                "WireGuard не установлен",
                MessageBoxButton.YesNo, MessageBoxImage.Information);
            if (result == MessageBoxResult.Yes)
                Process.Start(new ProcessStartInfo("https://www.wireguard.com/install/") { UseShellExecute = true });
            return;
        }

        var tunnelName = Path.GetFileNameWithoutExtension(_configPath);
        if (!Regex.IsMatch(tunnelName, @"^[A-Za-z0-9_=+.-]{1,32}$"))
        {
            MessageBox.Show(
                "Переименуй файл конфигурации: используй только латинские буквы, цифры, точку, дефис или подчёркивание; максимум 32 символа.",
                "Недопустимое имя туннеля", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _busy = true;
        ConnectButton.IsEnabled = false;
        try
        {
            StatusText.Text = _connected ? "Отключение WireGuard…" : "Запуск WireGuard…";
            var args = _connected
                ? new[] { "/uninstalltunnelservice", tunnelName }
                : new[] { "/installtunnelservice", _configPath };

            var start = new ProcessStartInfo
            {
                FileName = wireGuard,
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Path.GetDirectoryName(wireGuard) ?? AppContext.BaseDirectory
            };
            start.Arguments = _connected
                ? $"/uninstalltunnelservice \"{tunnelName}\""
                : $"/installtunnelservice \"{_configPath}\"";

            using var process = Process.Start(start);
            if (process is null)
                throw new InvalidOperationException("Windows не смог запустить WireGuard.");

            await process.WaitForExitAsync();
            if (process.ExitCode != 0)
                throw new InvalidOperationException($"WireGuard завершился с кодом {process.ExitCode}. Проверь конфигурацию и наличие такого туннеля.");

            _connected = !_connected;
            StatusText.Text = _connected
                ? "Команда запуска выполнена. Проверяй доступность сервера."
                : "Команда отключения выполнена.";
            ConnectButton.Content = _connected ? "Отключить VPN  ■" : "Подключить VPN  →";
            ConfigText.Text = _connected
                ? $"WireGuard: запущен туннель {tunnelName}. Само по себе это ещё не подтверждает доступ к Codex."
                : $"Конфигурация: {Path.GetFileName(_configPath)}";
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            StatusText.Text = "Операция отменена в запросе Windows UAC.";
        }
        catch (Exception ex)
        {
            StatusText.Text = "Не удалось выполнить команду WireGuard.";
            MessageBox.Show(ex.Message, "GodEx — ошибка VPN", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _busy = false;
            ConnectButton.IsEnabled = true;
        }
    }

    private static string? FindWireGuard()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wireguard.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "WireGuard", "wireguard.exe")
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    private static void ValidateWireGuardConfig(string text, string path)
    {
        if (new FileInfo(path).Length > 128 * 1024)
            throw new InvalidDataException("Файл конфигурации неожиданно большой (более 128 КБ).");

        bool Has(string pattern) => Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline);
        if (!Has(@"^\s*\[Interface\]\s*$") ||
            !Has(@"^\s*PrivateKey\s*=\s*\S+\s*$") ||
            !Has(@"^\s*\[Peer\]\s*$") ||
            !Has(@"^\s*PublicKey\s*=\s*\S+\s*$") ||
            !Has(@"^\s*Endpoint\s*=\s*\S+\s*$") ||
            !Has(@"^\s*AllowedIPs\s*=\s*\S+\s*$"))
        {
            throw new InvalidDataException(
                "Файл не похож на полноценную конфигурацию WireGuard. Нужны секции [Interface] и [Peer], а также PrivateKey, PublicKey, Endpoint и AllowedIPs. Секретный ключ никому не отправляй.");
        }
    }

    private void Servers_Click(object sender, RoutedEventArgs e) => ImportConfig_Click(sender, e);

    private async void Diagnostics_Click(object sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            MessageBox.Show("Дождись завершения текущей операции.", "Диагностика GodEx",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var wg = FindWireGuard();
        var config = _configPath is null ? null : Path.GetFileNameWithoutExtension(_configPath);
        var report = new System.Text.StringBuilder();
        report.AppendLine("GODEX — ДИАГНОСТИКА VPN");
        report.AppendLine($"Время: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        report.AppendLine();

        if (wg is null)
        {
            report.AppendLine("✗ WireGuard for Windows: не найден");
            report.AppendLine("Установи официальный клиент: https://www.wireguard.com/install/");
            report.AppendLine("Проверка туннеля невозможна.");
            MessageBox.Show(report.ToString(), "Диагностика GodEx",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        report.AppendLine("✓ WireGuard for Windows: найден");
        report.AppendLine($"Исполняемый файл: {wg}");
        if (config is null)
        {
            report.AppendLine("✗ Конфигурация: не импортирована");
            report.AppendLine("Импортируй .conf, затем повтори диагностику.");
            MessageBox.Show(report.ToString(), "Диагностика GodEx",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        report.AppendLine($"Конфигурация: {config}");
        report.AppendLine();

        try
        {
            var serviceName = "WireGuardTunnel$" + config;
            var service = await RunDiagnosticCommandAsync("sc.exe", new[] { "query", serviceName }, 5000);
            var serviceRunning = service.ExitCode == 0 &&
                System.Text.RegularExpressions.Regex.IsMatch(
                    service.Output, @"STATE\s*:\s*4\s+RUNNING",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            report.AppendLine(serviceRunning
                ? "✓ Служба туннеля: RUNNING"
                : "✗ Служба туннеля: не подтверждена как RUNNING");
            if (!string.IsNullOrWhiteSpace(service.Output))
                report.AppendLine(service.Output.Trim());

            report.AppendLine();
            report.AppendLine("=== СЕТЬ, DNS И МАРШРУТЫ ===");
            await AppendNetworkDiagnosticsAsync(report, config);
            
            var wgExe = Path.Combine(Path.GetDirectoryName(wg) ?? "", "wg.exe");
            if (!File.Exists(wgExe))
            {
                report.AppendLine();
                report.AppendLine("⚠ wg.exe не найден рядом с WireGuard. Проверка handshake недоступна.");
            }
            else
            {
                var handshakes = await RunDiagnosticCommandAsync(wgExe,
                    new[] { "show", config, "latest-handshakes" }, 5000);
                report.AppendLine();
                if (handshakes.ExitCode != 0)
                {
                    report.AppendLine("✗ Не удалось получить latest-handshakes.");
                    if (!string.IsNullOrWhiteSpace(handshakes.Output))
                        report.AppendLine(handshakes.Output.Trim());
                }
                else
                {
                    var timestamps = new List<long>();
                    foreach (var line in handshakes.Output.Split(new[] { '\r', '\n' },
                                 StringSplitOptions.RemoveEmptyEntries))
                    {
                        var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2 && long.TryParse(parts[^1], out var timestamp))
                            timestamps.Add(timestamp);
                    }

                    var latest = timestamps.Where(t => t > 0).DefaultIfEmpty(0).Max();
                    if (latest == 0)
                    {
                        report.AppendLine("✗ WireGuard handshake: пока не подтверждён");
                        report.AppendLine("Возможные причины: сервер недоступен, неверные ключи/Endpoint или ещё не было обмена.");
                    }
                    else
                    {
                        var age = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - latest;
                        report.AppendLine($"✓ Последний handshake: {DateTimeOffset.FromUnixTimeSeconds(latest).ToLocalTime():yyyy-MM-dd HH:mm:ss}");
                        report.AppendLine(age <= 180
                            ? $"✓ Handshake свежий ({Math.Max(0, age)} сек. назад)"
                            : $"⚠ Последний handshake был {Math.Max(0, age)} сек. назад; он может быть устаревшим.");
                    }

                    var transfer = await RunDiagnosticCommandAsync(wgExe,
                        new[] { "show", config, "transfer" }, 5000);
                    if (transfer.ExitCode == 0)
                    {
                        long rx = 0, tx = 0;
                        foreach (var line in transfer.Output.Split(new[] { '\r', '\n' },
                                     StringSplitOptions.RemoveEmptyEntries))
                        {
                            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 3 &&
                                long.TryParse(parts[^2], out var received) &&
                                long.TryParse(parts[^1], out var sent))
                            {
                                rx += received;
                                tx += sent;
                            }
                        }
                        report.AppendLine($"Трафик peer-ов: принято {FormatBytes(rx)}, отправлено {FormatBytes(tx)}");
                        report.AppendLine("Примечание: счётчики могут быть нулевыми, если трафик ещё не проходил.");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            report.AppendLine();
            report.AppendLine("✗ Ошибка диагностики: " + ex.Message);
        }

        report.AppendLine();
        report.AppendLine("Важно: состояние службы и handshake не гарантируют доступность Codex или правильную маршрутизацию всего трафика.");
        MessageBox.Show(report.ToString(), "Диагностика GodEx",
            MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private static async Task AppendNetworkDiagnosticsAsync(System.Text.StringBuilder report, string tunnelName)
    {
        try
        {
            var adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .ToList();

            report.AppendLine("Активные сетевые адаптеры:");
            foreach (var adapter in adapters)
            {
                var props = adapter.GetIPProperties();
                var ipv4 = props.UnicastAddresses
                    .Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(a => a.Address.ToString()).ToArray();
                var dns = props.DnsAddresses.Select(a => a.ToString()).ToArray();
                var gateways = props.GatewayAddresses
                    .Select(g => g.Address.ToString())
                    .Where(g => g != "0.0.0.0" && g != "::").ToArray();

                report.AppendLine($"• {adapter.Name} [{adapter.NetworkInterfaceType}] — {adapter.OperationalStatus}");
                if (ipv4.Length > 0) report.AppendLine($"  IPv4: {string.Join(", ", ipv4)}");
                if (gateways.Length > 0) report.AppendLine($"  Шлюз: {string.Join(", ", gateways)}");
                report.AppendLine($"  DNS: {(dns.Length == 0 ? "не указаны" : string.Join(", ", dns))}");
            }

            var tunnelAdapters = adapters.Where(a =>
                    a.Name.Contains(tunnelName, StringComparison.OrdinalIgnoreCase) ||
                    a.Description.Contains(tunnelName, StringComparison.OrdinalIgnoreCase) ||
                    a.Name.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                    a.Description.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                    a.Description.Contains("Wintun", StringComparison.OrdinalIgnoreCase))
                .ToList();

            report.AppendLine();
            if (tunnelAdapters.Count == 0)
            {
                report.AppendLine("⚠ Адаптер, похожий на VPN-туннель, не найден среди активных интерфейсов.");
                report.AppendLine("Это не доказывает, что VPN не работает: название интерфейса зависит от установки WireGuard.");
            }
            else
            {
                report.AppendLine("✓ Найдены активные адаптеры, похожие на VPN:");
                foreach (var adapter in tunnelAdapters)
                    report.AppendLine($"  {adapter.Name} — {adapter.Description}");
            }

            report.AppendLine();
            var routeResult = await RunDiagnosticCommandAsync("route.exe", new[] { "print", "-4" }, 5000);
            if (routeResult.ExitCode == 0)
            {
                report.AppendLine("IPv4 таблица маршрутизации (фрагмент):");
                var routeLines = routeResult.Output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                var interesting = routeLines.Where(line =>
                    line.Contains("0.0.0.0") ||
                    tunnelAdapters.Any(a => line.Contains(a.Name, StringComparison.OrdinalIgnoreCase)) ||
                    line.Contains(tunnelName, StringComparison.OrdinalIgnoreCase))
                    .Take(16).ToArray();
                report.AppendLine(interesting.Length == 0
                    ? "  Не удалось выделить default/VPN-маршруты автоматически; полная таблица не показана."
                    : string.Join(Environment.NewLine, interesting.Select(line => "  " + line.Trim())));
                report.AppendLine("Маршруты показываются как диагностика; наличие default route само по себе не доказывает, что весь трафик идёт через VPN.");
            }
            else
            {
                report.AppendLine("✗ Не удалось прочитать IPv4 таблицу маршрутизации.");
                if (!string.IsNullOrWhiteSpace(routeResult.Output))
                    report.AppendLine(routeResult.Output);
            }

            report.AppendLine();
            report.AppendLine("DNS-проверка:");
            foreach (var host in new[] { "example.com", "www.cloudflare.com" })
            {
                try
                {
                    var addresses = await Dns.GetHostAddressesAsync(host).WaitAsync(TimeSpan.FromSeconds(5));
                    report.AppendLine(addresses.Length > 0
                        ? $"✓ {host}: разрешён в {string.Join(", ", addresses.Take(4).Select(a => a.ToString()))}"
                        : $"✗ {host}: DNS не вернул адресов");
                }
                catch (Exception ex)
                {
                    report.AppendLine($"✗ {host}: {ex.GetType().Name} — {ex.Message}");
                }
            }

            report.AppendLine();
            report.AppendLine("HTTPS-проверка доступности:");
            using var handler = new HttpClientHandler { AllowAutoRedirect = true };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(7) };
            try
            {
                using var response = await client.GetAsync("https://example.com/");
                report.AppendLine($"✓ https://example.com/ ответил HTTP {(int)response.StatusCode} ({response.StatusCode})");
            }
            catch (Exception ex)
            {
                report.AppendLine($"✗ HTTPS-запрос не прошёл: {ex.GetType().Name} — {ex.Message}");
            }

            report.AppendLine("Проверки используют системные DNS и маршруты Windows. Чтобы доказать, что запросы прошли именно через VPN, сопоставь маршрут к целевому адресу с интерфейсом туннеля и повтори тест с отключённым туннелем для сравнения.");
        }
        catch (Exception ex)
        {
            report.AppendLine("✗ Ошибка сетевой диагностики: " + ex.Message);
        }
    }

    private static async Task<(int ExitCode, string Output)> RunDiagnosticCommandAsync(
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

        var output = (await stdout) + Environment.NewLine + (await stderr);
        return (process.ExitCode, output.Trim());
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double value = Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return $"{value:0.##} {units[unit]}";
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(
            "GodEx использует официальный WireGuard for Windows и конфигурацию, которую ты выберешь. Файл остаётся в исходном месте и не отправляется в GitHub. Автозапуск и автоматическая проверка туннеля будут отдельным следующим шагом.",
            "Настройки GodEx", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
