using CommunityToolkit.Mvvm.ComponentModel;

namespace SpeicherPrüfstation.Desktop.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    [ObservableProperty]
    public partial string Greeting { get; set; } = "Linux Speicher-Prüfstation";
}