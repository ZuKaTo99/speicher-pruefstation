using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SpeicherPrüfstation.Desktop.Models;
using SpeicherPrüfstation.Desktop.Services;

namespace SpeicherPrüfstation.Desktop.ViewModels;


public partial class MainViewModel : ViewModelBase
{
    private readonly IStorageDeviceService _storageDeviceService;

    public MainViewModel()
        : this(new LinuxStorageDeviceService())
    {
    }

    public MainViewModel(
        IStorageDeviceService storageDeviceService)
    {
        _storageDeviceService = storageDeviceService
            ?? throw new ArgumentNullException(
                nameof(storageDeviceService));
    }

    public ObservableCollection<StorageDeviceViewModel> StorageDevices
    {
        get;
    } = [];

    [ObservableProperty]
    public partial StorageDeviceViewModel? SelectedDevice
    {
        get;
        set;
    }

    [ObservableProperty]
    public partial bool IsRefreshingDevices { get; set; }

    [ObservableProperty]
    public partial string Greeting { get; set; } =
        "Linux Speicher-Prüfstation";

    [ObservableProperty]
    public partial string StatusMessage { get; set; } =
        "Bereit.";

    [RelayCommand]
    private async Task RefreshDevicesAsync(
        CancellationToken cancellationToken)
    {
        IsRefreshingDevices = true;
        StatusMessage = "USB-Speichergeräte werden gesucht …";

        try
        {
            IReadOnlyList<StorageDevice> devices =
                await _storageDeviceService
                    .GetUsbStorageDevicesAsync(cancellationToken);

            SelectedDevice = null;
            StorageDevices.Clear();

            foreach (StorageDevice device in devices)
            {
                StorageDevices.Add(
                    new StorageDeviceViewModel(device));
            }

            SelectedDevice = StorageDevices.Count > 0
                ? StorageDevices[0]
                : null;

            StatusMessage = StorageDevices.Count switch
            {
                0 => "Kein externes USB-Speichergerät erkannt.",
                1 => "1 externes USB-Speichergerät erkannt.",
                _ => $"{StorageDevices.Count} externe USB-Speichergeräte erkannt."
            };
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Die Gerätesuche wurde abgebrochen.";
        }
        catch (Exception exception)
        {
            StatusMessage =
                $"Fehler bei der Geräteerkennung: {exception.Message}";
        }
        finally
        {
            IsRefreshingDevices = false;
        }
    }
}
