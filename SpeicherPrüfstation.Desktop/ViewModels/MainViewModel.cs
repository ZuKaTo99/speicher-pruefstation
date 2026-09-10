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
    private readonly IStorageDeviceService
        _storageDeviceService;

    private readonly ISmartHealthService
        _smartHealthService;

    public MainViewModel()
        : this(
            new LinuxStorageDeviceService(),
            new LinuxSmartHealthService())
    {
    }

    public MainViewModel(
        IStorageDeviceService storageDeviceService)
        : this(
            storageDeviceService,
            new LinuxSmartHealthService())
    {
    }

    public MainViewModel(
        IStorageDeviceService storageDeviceService,
        ISmartHealthService smartHealthService)
    {
        _storageDeviceService = storageDeviceService
            ?? throw new ArgumentNullException(
                nameof(storageDeviceService));

        _smartHealthService = smartHealthService
            ?? throw new ArgumentNullException(
                nameof(smartHealthService));
    }

    public ObservableCollection<StorageDeviceViewModel>
        StorageDevices
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
    public partial SmartHealthResultViewModel? SmartHealth
    {
        get;
        set;
    }

    [ObservableProperty]
    public partial bool IsRefreshingDevices
    {
        get;
        set;
    }

    [ObservableProperty]
    public partial bool IsCheckingSmartHealth
    {
        get;
        set;
    }

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
        SmartHealth = null;

        StatusMessage =
            "USB-Speichergeräte werden gesucht …";

        try
        {
            IReadOnlyList<StorageDevice> devices =
                await _storageDeviceService
                    .GetUsbStorageDevicesAsync(
                        cancellationToken);

            SelectedDevice = null;
            StorageDevices.Clear();

            foreach (StorageDevice device in devices)
            {
                StorageDevices.Add(
                    new StorageDeviceViewModel(device));
            }

            SelectedDevice =
                StorageDevices.Count > 0
                    ? StorageDevices[0]
                    : null;

            StatusMessage =
                StorageDevices.Count switch
                {
                    0 =>
                        "Kein externes USB-Speichergerät erkannt.",
                    1 =>
                        "1 externes USB-Speichergerät erkannt.",
                    _ =>
                        $"{StorageDevices.Count} externe "
                        + "USB-Speichergeräte erkannt."
                };
        }
        catch (OperationCanceledException)
        {
            StatusMessage =
                "Die Gerätesuche wurde abgebrochen.";
        }
        catch (Exception exception)
        {
            StatusMessage =
                $"Fehler bei der Geräteerkennung: "
                + exception.Message;
        }
        finally
        {
            IsRefreshingDevices = false;
        }
    }

    [RelayCommand(
        CanExecute = nameof(CanCheckSmartHealth))]
    private async Task CheckSmartHealthAsync(
        CancellationToken cancellationToken)
    {
        StorageDeviceViewModel? selectedDevice =
            SelectedDevice;

        if (selectedDevice is null)
        {
            StatusMessage =
                "Bitte zuerst ein USB-Speichergerät auswählen.";

            return;
        }

        IsCheckingSmartHealth = true;
        SmartHealth = null;

        StatusMessage =
            $"SMART-Hardwarestatus für "
            + $"{selectedDevice.DevicePath} wird geprüft …";

        try
        {
            SmartHealthResult result =
                await _smartHealthService
                    .CheckHealthAsync(
                        selectedDevice.DevicePath,
                        cancellationToken);

            if (!ReferenceEquals(
                    selectedDevice,
                    SelectedDevice))
            {
                StatusMessage =
                    "Die Geräteauswahl wurde während "
                    + "der Prüfung geändert.";

                return;
            }

            SmartHealth =
                new SmartHealthResultViewModel(result);

            StatusMessage =
                result.State switch
                {
                    SmartHealthState.Passed =>
                        "SMART-Prüfung bestanden.",
                    SmartHealthState.Warning =>
                        "SMART meldet einen möglichen "
                        + "Hardwarefehler.",
                    SmartHealthState.Unavailable =>
                        "Für dieses Gerät ist kein eindeutiger "
                        + "SMART-Status verfügbar.",
                    _ =>
                        "Die SMART-Prüfung ist fehlgeschlagen."
                };
        }
        catch (OperationCanceledException)
        {
            StatusMessage =
                "Die SMART-Prüfung wurde abgebrochen.";
        }
        catch (UnauthorizedAccessException exception)
        {
            StatusMessage = exception.Message;
        }
        catch (Exception exception)
        {
            StatusMessage =
                $"Fehler bei der SMART-Prüfung: "
                + exception.Message;
        }
        finally
        {
            IsCheckingSmartHealth = false;
        }
    }

    private bool CanCheckSmartHealth()
    {
        return SelectedDevice is not null
               && !IsCheckingSmartHealth;
    }

    partial void OnSelectedDeviceChanged(
        StorageDeviceViewModel? value)
    {
        SmartHealth = null;

        CheckSmartHealthCommand
            .NotifyCanExecuteChanged();
    }

    partial void OnIsCheckingSmartHealthChanged(
        bool value)
    {
        CheckSmartHealthCommand
            .NotifyCanExecuteChanged();
    }
}
