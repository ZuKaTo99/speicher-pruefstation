using Avalonia.Controls;
using SpeicherPrüfstation.Desktop.ViewModels;

namespace SpeicherPrüfstation.Desktop.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Closing += OnWindowClosing;
    }

    private void OnWindowClosing(object? sender, WindowClosingEventArgs eventArgs)
    {
        if (DataContext is MainViewModel viewModel && !viewModel.RequestWindowClose())
            eventArgs.Cancel = true;
    }
}