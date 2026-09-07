using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SpeicherPrüfstation.Desktop.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    [ObservableProperty]
    public partial string Greeting { get; set; } =
        "Linux Speicher-Prüfstation";

    [ObservableProperty]
    public partial string StatusMessage { get; set; } =
        "Bereit.";

    [RelayCommand]
    private void TestStatus()
    {
        StatusMessage =
            "Die Verbindung zwischen Oberfläche und C# funktioniert.";
    }
}