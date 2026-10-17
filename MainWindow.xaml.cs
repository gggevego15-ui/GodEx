using System.Windows;
using System.Windows.Controls;

namespace GodEx;

public partial class MainWindow : Window
{
    private bool _requested;
    public MainWindow() => InitializeComponent();

    private void Connect_Click(object sender, RoutedEventArgs e)
    {
        _requested = !_requested;
        StatusText.Text = _requested
            ? "Подключение недоступно: VPN-сервер не настроен"
            : "Не подключено";
        ConnectButton.Content = _requested ? "Проверить позже  →" : "Подключить VPN  →";
        MessageBox.Show(
            "Интерфейс GodEx готовится. Для реального VPN-подключения нужно настроить протокол и рабочий сервер. Сейчас трафик через VPN не проходит.",
            "GodEx — подключение",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void Servers_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show("Список серверов появится после настройки VPN-инфраструктуры. Серверы и пинг не подделываются.", "Серверы GodEx", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void Diagnostics_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show("Статус: приложение запущено. VPN-туннель: не настроен. Защищённое соединение: неактивно.", "Диагностика GodEx", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show("Настройки автоподключения и запуска Windows будут добавлены после интеграции VPN-клиента.", "Настройки GodEx", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
