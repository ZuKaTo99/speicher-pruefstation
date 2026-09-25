using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
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

    private readonly IVirusScanService _virusScanService;
    private readonly IQuarantineService _quarantineService;
    private long _scanGeneration;
    private long _quarantineGeneration;
    private VirusScanResult? _lastVirusScanResult;
    private StorageDevice? _lastVirusScanDevice;

    private readonly Dictionary<string, QuarantineItemResult>
        _quarantinedItems =
            new(StringComparer.Ordinal);

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
        : this(
            storageDeviceService,
            smartHealthService,
            new LinuxVirusScanService(
                storageDeviceService),
            new LinuxQuarantineService(
                storageDeviceService))
    {
    }

    public MainViewModel(
        IStorageDeviceService storageDeviceService,
        ISmartHealthService smartHealthService,
        IVirusScanService virusScanService)
        : this(
            storageDeviceService,
            smartHealthService,
            virusScanService,
            new LinuxQuarantineService(
                storageDeviceService))
    {
    }

    public MainViewModel(
        IStorageDeviceService storageDeviceService,
        ISmartHealthService smartHealthService,
        IVirusScanService virusScanService,
        IQuarantineService quarantineService)
    {
        _storageDeviceService =
            storageDeviceService
            ?? throw new ArgumentNullException(
                nameof(storageDeviceService));

        _smartHealthService =
            smartHealthService
            ?? throw new ArgumentNullException(
                nameof(smartHealthService));

        _virusScanService =
            virusScanService
            ?? throw new ArgumentNullException(
                nameof(virusScanService));

        _quarantineService =
            quarantineService
            ?? throw new ArgumentNullException(
                nameof(quarantineService));
    }

    public ObservableCollection<StorageDeviceViewModel>
        StorageDevices
    {
        get;
    } = [];

    [ObservableProperty]
    public partial StorageDeviceViewModel?
        SelectedDevice
    {
        get;
        set;
    }

    [ObservableProperty]
    public partial SmartHealthResultViewModel?
        SmartHealth
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
    public partial string Greeting
    {
        get;
        set;
    } = "Linux Speicher-Prüfstation";

    [ObservableProperty]
    public partial string StatusMessage
    {
        get;
        set;
    } = "Bereit.";

    [ObservableProperty]
    public partial bool IsScanning
    {
        get;
        set;
    }

    [ObservableProperty]
    public partial bool IsCleaningUp
    {
        get;
        set;
    }

    [ObservableProperty]
    public partial bool IsQuarantining
    {
        get;
        set;
    }

    [ObservableProperty]
    public partial bool HasPendingCleanup
    {
        get;
        set;
    }

    [ObservableProperty]
    public partial long ScannedFileCount
    {
        get;
        set;
    }

    [ObservableProperty]
    public partial long VirusFindingCount
    {
        get;
        set;
    }

    [ObservableProperty]
    public partial long VirusErrorCount
    {
        get;
        set;
    }

    [ObservableProperty]
    public partial long VirusWarningCount
    {
        get;
        set;
    }

    [ObservableProperty]
    public partial string VirusScanStateText
    {
        get;
        set;
    } = "Noch nicht gestartet";

    [ObservableProperty]
    public partial string VirusScanSummary
    {
        get;
        set;
    } =
        "Zuerst ein USB-Gerät auswählen "
        + "und den Virenscan starten.";

    [ObservableProperty]
    public partial string VirusFindingsText
    {
        get;
        set;
    } = "Noch kein Scanergebnis.";

    [ObservableProperty]
    public partial string VirusMessagesText
    {
        get;
        set;
    } = "Noch keine Meldungen.";

    [ObservableProperty]
    public partial string QuarantineStatus
    {
        get;
        set;
    } =
        "Noch keine Funddatei in Quarantäne gesichert.";

    public bool IsBusy =>
        IsRefreshingDevices
        || IsCheckingSmartHealth
        || IsScanning
        || IsCleaningUp
        || IsQuarantining;

    public bool CanSelectDevice =>
        !IsBusy
        && !HasPendingCleanup;

    public bool IsVirusWorkActive =>
        IsScanning
        || IsCleaningUp
        || IsQuarantining;

    public bool HasQuarantinableFindings =>
        RemainingFindings().Count > 0;

    [RelayCommand(
        CanExecute = nameof(CanRefreshDevices))]
    private async Task RefreshDevicesAsync(
        CancellationToken cancellationToken)
    {
        if (!CanRefreshDevices())
        {
            return;
        }

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
                    new StorageDeviceViewModel(
                        device));
            }

            SelectedDevice =
                StorageDevices.Count > 0
                    ? StorageDevices[0]
                    : null;

            StatusMessage =
                StorageDevices.Count switch
                {
                    0 =>
                        "Kein externes "
                        + "USB-Speichergerät erkannt.",

                    1 =>
                        "1 externes "
                        + "USB-Speichergerät erkannt.",

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
                "Fehler bei der Geräteerkennung: "
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
        if (!CanCheckSmartHealth())
        {
            return;
        }

        StorageDeviceViewModel? selectedDevice =
            SelectedDevice;

        if (selectedDevice is null)
        {
            StatusMessage =
                "Bitte zuerst ein "
                + "USB-Speichergerät auswählen.";

            return;
        }

        IsCheckingSmartHealth = true;
        SmartHealth = null;

        StatusMessage =
            "SMART-Hardwarestatus für "
            + $"{selectedDevice.DevicePath} "
            + "wird geprüft …";

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
                new SmartHealthResultViewModel(
                    result);

            StatusMessage =
                result.State switch
                {
                    SmartHealthState.Passed =>
                        "SMART-Prüfung bestanden.",

                    SmartHealthState.Warning =>
                        "SMART meldet einen möglichen "
                        + "Hardwarefehler.",

                    SmartHealthState.Unavailable =>
                        "Für dieses Gerät ist kein "
                        + "eindeutiger SMART-Status "
                        + "verfügbar.",

                    _ =>
                        "Die SMART-Prüfung "
                        + "ist fehlgeschlagen."
                };
        }
        catch (OperationCanceledException)
        {
            StatusMessage =
                "Die SMART-Prüfung wurde abgebrochen.";
        }
        catch (UnauthorizedAccessException exception)
        {
            StatusMessage =
                exception.Message;
        }
        catch (Exception exception)
        {
            StatusMessage =
                "Fehler bei der SMART-Prüfung: "
                + exception.Message;
        }
        finally
        {
            IsCheckingSmartHealth = false;
        }
    }

    [RelayCommand(
        CanExecute = nameof(CanStartVirusScan),
        IncludeCancelCommand = true)]
    private async Task StartVirusScanAsync(
        CancellationToken cancellationToken)
    {
        if (!CanStartVirusScan()
            || SelectedDevice
            is not { } selectedDevice)
        {
            return;
        }

        ClearVirusResult();

        long generation =
            ++_scanGeneration;

        IsScanning = true;
        VirusScanStateText = "Scan läuft";

        var progress =
            new Progress<VirusScanProgress>(
                value =>
                {
                    if (!IsScanning
                        || generation
                        != _scanGeneration)
                    {
                        return;
                    }

                    StatusMessage =
                        value.Status;

                    VirusScanSummary =
                        value.Status;

                    ScannedFileCount =
                        value.ScannedFiles;

                    VirusFindingCount =
                        value.Findings;

                    VirusErrorCount =
                        value.Errors;

                    VirusWarningCount =
                        value.Warnings;
                });

        try
        {
            VirusScanResult result =
                await _virusScanService.ScanAsync(
                    selectedDevice.Device,
                    progress,
                    cancellationToken);

            // Bereits eingereihte Fortschrittsmeldungen
            // dürfen das Ergebnis nicht überschreiben.
            _scanGeneration++;

            VirusScanStateText =
                result.State switch
                {
                    VirusScanState.NoFindings =>
                        "Keine Funde",

                    VirusScanState.Findings =>
                        "Funde vorhanden",

                    VirusScanState.Incomplete =>
                        "Scan unvollständig",

                    VirusScanState.Canceled =>
                        "Scan abgebrochen",

                    _ =>
                        "Scan fehlgeschlagen"
                };

            VirusScanSummary =
                result.Summary;

            StatusMessage =
                result.Summary;

            ScannedFileCount =
                result.ScannedFiles;

            VirusFindingCount =
                result.Findings.Count;

            VirusErrorCount =
                result.ErrorCount;

            VirusWarningCount =
                result.Warnings.Count;

            VirusFindingsText =
                result.Findings.Count == 0
                    ? "Keine Schadsoftware-Funde "
                      + "gemeldet. Scanstatus beachten."
                    : string.Join(
                        "\n\n",
                        result.Findings.Select(
                            finding =>
                                finding.FilePath
                                + "\nSignatur: "
                                + finding.Signature));

            string[] messages =
                result.Errors
                    .Select(value =>
                        "Fehler: " + value)
                    .Concat(
                        result.Warnings.Select(
                            value =>
                                "Warnung: " + value))
                    .ToArray();

            VirusMessagesText =
                messages.Length == 0
                    ? "Keine Warnungen oder "
                      + "Fehler gemeldet."
                    : string.Join(
                        "\n\n",
                        messages);

            _lastVirusScanResult =
                result;

            _lastVirusScanDevice =
                selectedDevice.Device;

            _quarantinedItems.Clear();

            QuarantineStatus =
                result.Findings.Count == 0
                    ? "Für dieses Scanergebnis sind "
                      + "keine Funddateien zu sichern."
                    : $"{FormatFindingCount(
                        result.Findings.Count)} "
                      + "können verschlüsselt in die "
                      + "lokale Quarantäne "
                      + "gesichert werden.";

            OnPropertyChanged(
                nameof(HasQuarantinableFindings));
        }
        catch (OperationCanceledException)
        {
            VirusScanStateText =
                "Scan abgebrochen";

            VirusScanSummary =
                "Der Scan wurde abgebrochen; "
                + "es liegt kein vollständiges "
                + "Ergebnis vor.";

            StatusMessage =
                VirusScanSummary;
        }
        catch (Exception exception)
        {
            VirusScanStateText =
                "Scan fehlgeschlagen";

            VirusScanSummary =
                "Der Virenscan konnte nicht "
                + "abgeschlossen werden.";

            VirusMessagesText =
                exception.Message;

            VirusErrorCount++;

            StatusMessage =
                VirusScanSummary;
        }
        finally
        {
            _scanGeneration++;
            UpdatePendingCleanup();
            IsScanning = false;
        }
    }

    [RelayCommand(
        CanExecute = nameof(CanQuarantineFindings),
        IncludeCancelCommand = true)]
    private async Task QuarantineFindingsAsync(
        CancellationToken cancellationToken)
    {
        if (!CanQuarantineFindings()
            || SelectedDevice
            is not { } selectedDevice)
        {
            return;
        }

        IReadOnlyList<VirusFinding> findings =
            RemainingFindings();

        if (findings.Count == 0)
        {
            return;
        }

        IsQuarantining = true;

        long generation =
            ++_quarantineGeneration;

        QuarantineStatus =
            $"{FormatFindingCount(findings.Count)} "
            + "werden vorbereitet …";

        StatusMessage =
            QuarantineStatus;

        var progress =
            new Progress<string>(
                message =>
                {
                    if (!IsQuarantining
                        || generation
                        != _quarantineGeneration)
                    {
                        return;
                    }

                    QuarantineStatus =
                        message;

                    StatusMessage =
                        message;
                });

        try
        {
            QuarantineResult result =
                await _quarantineService
                    .QuarantineAsync(
                        selectedDevice.Device,
                        findings,
                        progress,
                        cancellationToken);

            _quarantineGeneration++;

            foreach (QuarantineItemResult item
                     in result.Items)
            {
                _quarantinedItems[
                    item.OriginalFilePath] = item;
            }

            var statusParts =
                new List<string>();

            if (result.Items.Count > 0)
            {
                statusParts.Add(
                    $"{FormatFindingCount(
                        result.Items.Count)} "
                    + "wurden verschlüsselt gesichert.");

                statusParts.Add(
                    "Quarantäneordner: "
                    + result.DirectoryPath);

                statusParts.Add(
                    "Die Originaldateien auf dem "
                    + "USB-Gerät wurden nicht verändert.");
            }
            else
            {
                statusParts.Add(
                    "Es konnte keine Funddatei "
                    + "in Quarantäne gesichert werden.");
            }

            if (result.Errors.Count > 0)
            {
                statusParts.Add(
                    "Fehler:\n"
                    + string.Join(
                        "\n",
                        result.Errors));
            }

            if (result.Warnings.Count > 0)
            {
                statusParts.Add(
                    "Warnungen:\n"
                    + string.Join(
                        "\n",
                        result.Warnings));
            }

            QuarantineStatus =
                string.Join(
                    "\n\n",
                    statusParts);

            if (result.WasCanceled)
            {
                StatusMessage =
                    "Die Quarantäneoperation "
                    + "wurde abgebrochen.";
            }
            else if (result.Errors.Count > 0)
            {
                StatusMessage =
                    "Die Quarantäneoperation wurde "
                    + "mit Fehlern beendet.";
            }
            else if (result.Items.Count == 1)
            {
                StatusMessage =
                    "Eine Funddatei wurde "
                    + "in Quarantäne gesichert.";
            }
            else
            {
                StatusMessage =
                    $"{result.Items.Count} "
                    + "Funddateien wurden "
                    + "in Quarantäne gesichert.";
            }

            OnPropertyChanged(
                nameof(HasQuarantinableFindings));
        }
        catch (OperationCanceledException)
        {
            QuarantineStatus =
                "Die Quarantäneoperation wurde "
                + "abgebrochen. Bereits vollständig "
                + "gesicherte Einträge bleiben erhalten.";

            StatusMessage =
                QuarantineStatus;
        }
        catch (Exception exception)
        {
            QuarantineStatus =
                "Die Quarantäneoperation "
                + "ist fehlgeschlagen:\n"
                + exception.Message;

            StatusMessage =
                "Die Quarantäneoperation "
                + "ist fehlgeschlagen.";
        }
        finally
        {
            _quarantineGeneration++;
            UpdatePendingCleanup();
            IsQuarantining = false;
        }
    }

    [RelayCommand(
        CanExecute = nameof(CanRetryCleanup))]
    private async Task RetryCleanupAsync()
    {
        if (!CanRetryCleanup())
        {
            return;
        }

        IsCleaningUp = true;

        StatusMessage =
            "Ausstehendes Aushängen "
            + "wird erneut geprüft …";

        try
        {
            var messages =
                new List<string>();

            if (_virusScanService.HasPendingMounts)
            {
                VirusScanCleanupResult scanCleanup =
                    await _virusScanService
                        .RetryCleanupAsync();

                messages.AddRange(
                    scanCleanup.Messages);
            }

            if (_quarantineService.HasPendingMounts)
            {
                VirusScanCleanupResult
                    quarantineCleanup =
                        await _quarantineService
                            .RetryCleanupAsync();

                messages.AddRange(
                    quarantineCleanup.Messages);
            }

            UpdatePendingCleanup();

            string message =
                HasPendingCleanup
                    ? "Das Aushängen ist weiterhin "
                      + "nicht bestätigt. "
                      + "Meldungen beachten."
                    : "Das Aushängen ist jetzt "
                      + "bestätigt. Das bisherige "
                      + "Scanergebnis bleibt unverändert.";

            VirusScanSummary =
                message;

            StatusMessage =
                message;

            VirusMessagesText +=
                "\n\nNachkontrolle: "
                + message;

            if (messages.Count > 0)
            {
                VirusMessagesText +=
                    "\n"
                    + string.Join(
                        "\n",
                        messages);
            }
        }
        catch (Exception exception)
        {
            StatusMessage =
                "Das Aushängen konnte "
                + "nicht bestätigt werden.";

            VirusMessagesText +=
                "\n\nNachkontrolle: "
                + exception.Message;
        }
        finally
        {
            UpdatePendingCleanup();
            IsCleaningUp = false;
        }
    }

    public bool RequestWindowClose()
    {
        if (IsScanning)
        {
            StartVirusScanCommand.Cancel();

            StatusMessage =
                "Abbruch angefordert. Bitte das "
                + "Aufräumen abwarten und das Fenster "
                + "danach erneut schließen.";

            return false;
        }

        if (IsQuarantining)
        {
            QuarantineFindingsCommand.Cancel();

            StatusMessage =
                "Abbruch angefordert. Bitte das "
                + "Aufräumen abwarten und das Fenster "
                + "danach erneut schließen.";

            return false;
        }

        if (IsCleaningUp || HasPendingCleanup)
        {
            StatusMessage =
                "Vor dem Schließen muss das Aushängen "
                + "bestätigt sein. Bitte die Meldungen "
                + "zum Virenscan beachten.";

            return false;
        }

        return true;
    }

    private void ClearVirusResult()
    {
        ScannedFileCount = 0;
        VirusFindingCount = 0;
        VirusErrorCount = 0;
        VirusWarningCount = 0;

        VirusScanStateText =
            "Noch nicht gestartet";

        VirusScanSummary =
            "Zuerst ein USB-Gerät auswählen "
            + "und den Virenscan starten.";

        VirusFindingsText =
            "Noch kein Scanergebnis.";

        VirusMessagesText =
            "Noch keine Meldungen.";

        QuarantineStatus =
            "Noch keine Funddatei "
            + "in Quarantäne gesichert.";

        _lastVirusScanResult = null;
        _lastVirusScanDevice = null;
        _quarantinedItems.Clear();

        OnPropertyChanged(
            nameof(HasQuarantinableFindings));
    }

    private bool CanRefreshDevices()
    {
        return CanSelectDevice;
    }

    private bool CanStartVirusScan()
    {
        return CanSelectDevice
               && SelectedDevice is not null;
    }

    private bool CanRetryCleanup()
    {
        return !IsBusy
               && HasPendingCleanup;
    }

    private bool CanQuarantineFindings()
    {
        return CanSelectDevice
               && SelectedDevice
               is { } selected
               && _lastVirusScanDevice
               is not null
               && ReferenceEquals(
                   selected.Device,
                   _lastVirusScanDevice)
               && RemainingFindings().Count > 0;
    }

    private IReadOnlyList<VirusFinding>
        RemainingFindings()
    {
        return _lastVirusScanResult
                   ?.Findings
                   .Where(finding =>
                       !_quarantinedItems
                           .ContainsKey(
                               finding.FilePath))
                   .ToArray()
               ?? [];
    }

    private void UpdatePendingCleanup()
    {
        HasPendingCleanup =
            _virusScanService.HasPendingMounts
            || _quarantineService.HasPendingMounts;
    }

    private static string FormatFindingCount(
        int count)
    {
        return count == 1
            ? "1 Funddatei"
            : $"{count} Funddateien";
    }

    private bool CanCheckSmartHealth()
    {
        return SelectedDevice is not null
               && CanSelectDevice;
    }

    partial void OnSelectedDeviceChanged(
        StorageDeviceViewModel? value)
    {
        SmartHealth = null;

        if (!IsVirusWorkActive
            && !HasPendingCleanup)
        {
            ClearVirusResult();
        }

        UpdateAvailability();
    }

    partial void OnIsCheckingSmartHealthChanged(
        bool value)
    {
        UpdateAvailability();
    }

    partial void OnIsRefreshingDevicesChanged(
        bool value)
    {
        UpdateAvailability();
    }

    partial void OnIsScanningChanged(
        bool value)
    {
        UpdateAvailability();
    }

    partial void OnIsCleaningUpChanged(
        bool value)
    {
        UpdateAvailability();
    }

    partial void OnIsQuarantiningChanged(
        bool value)
    {
        UpdateAvailability();
    }

    partial void OnHasPendingCleanupChanged(
        bool value)
    {
        UpdateAvailability();
    }

    private void UpdateAvailability()
    {
        OnPropertyChanged(
            nameof(IsBusy));

        OnPropertyChanged(
            nameof(CanSelectDevice));

        OnPropertyChanged(
            nameof(IsVirusWorkActive));

        RefreshDevicesCommand
            .NotifyCanExecuteChanged();

        CheckSmartHealthCommand
            .NotifyCanExecuteChanged();

        StartVirusScanCommand
            .NotifyCanExecuteChanged();

        QuarantineFindingsCommand
            .NotifyCanExecuteChanged();

        RetryCleanupCommand
            .NotifyCanExecuteChanged();
    }
}
