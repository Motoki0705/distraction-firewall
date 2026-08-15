using System.Windows;
using DistractionFirewall.App.Services;
using DistractionFirewall.App.ViewModels;

namespace DistractionFirewall.App;

public partial class MainWindow : Window, IDisposable
{
    private readonly MainViewModel _viewModel;

    public MainWindow()
    {
        InitializeComponent();
        _viewModel = new MainViewModel(new ActivationClient());
        DataContext = _viewModel;
        Loaded += OnLoaded;
        Closed += OnClosed;
    }

    private async void OnLoaded(object sender, RoutedEventArgs eventArgs) =>
        await _viewModel.InitializeAsync().ConfigureAwait(true);

    private void OnClosed(object? sender, EventArgs eventArgs)
    {
        Dispose();
    }

    public void Dispose()
    {
        Loaded -= OnLoaded;
        Closed -= OnClosed;
        _viewModel.Dispose();
        GC.SuppressFinalize(this);
    }

    private void Close_Click(object sender, RoutedEventArgs eventArgs) => Close();
}
