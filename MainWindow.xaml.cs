using System.ComponentModel;
using System.Diagnostics;
using System.IO;
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
            foreach (var arg in args) start.ArgumentList.Add(arg);

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

    private void Diagnostics_Click(object sender, RoutedEventArgs e)
    {
        var wg = FindWireGuard();
        var config = _configPath is null ? "не выбрана" : Path.GetFileName(_configPath);
        MessageBox.Show(
            $"WireGuard for Windows: {(wg is null ? "не найден" : "найден")}\nКонфигурация: {config}\nСостояние, известное приложению: {(_connected ? "команда запуска выполнена" : "не подключено")}\n\nЭто не проверка внешнего IP и не гарантия доступности Codex.",
            "Диагностика GodEx", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(
            "GodEx использует официальный WireGuard for Windows и конфигурацию, которую ты выберешь. Файл остаётся в исходном месте и не отправляется в GitHub. Автозапуск и автоматическая проверка туннеля будут отдельным следующим шагом.",
            "Настройки GodEx", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
