using System;
using System.Collections.Generic;
using SpeicherPrüfstation.Desktop.Formatting;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.ViewModels;

public sealed class StorageDeviceViewModel
{
    public StorageDeviceViewModel(
        StorageDevice device)
    {
        Device = device
            ?? throw new ArgumentNullException(
                nameof(device));

        DisplayName = CreateDisplayName(device);

        var volumes =
            new List<StorageVolumeViewModel>();

        foreach (StorageVolume volume in device.Volumes)
        {
            volumes.Add(
                new StorageVolumeViewModel(volume));
        }

        Volumes = volumes.ToArray();
    }

    public StorageDevice Device { get; }

    public string DisplayName { get; }

    public string DevicePath =>
        Device.DevicePath;

    public string SizeText =>
        ByteSizeFormatter.Format(Device.SizeBytes);

    public string TransportText =>
        string.IsNullOrWhiteSpace(Device.Transport)
            ? "Nicht erkannt"
            : Device.Transport.Trim().ToUpperInvariant();

    public string AccessText =>
        Device.IsReadOnly
            ? "Schreibgeschützt"
            : "Beschreibbar";

    public IReadOnlyList<StorageVolumeViewModel> Volumes
    {
        get;
    }

    public string VolumeCountText =>
        Volumes.Count switch
        {
            0 => "Keine Partitionen erkannt",
            1 => "1 Partition erkannt",
            _ => $"{Volumes.Count} Partitionen erkannt"
        };

    private static string CreateDisplayName(
        StorageDevice device)
    {
        var parts = new List<string>();

        if (!string.IsNullOrWhiteSpace(device.Vendor))
        {
            parts.Add(device.Vendor.Trim());
        }

        if (!string.IsNullOrWhiteSpace(device.Model))
        {
            parts.Add(device.Model.Trim());
        }

        return parts.Count == 0
            ? "Unbekanntes USB-Speichergerät"
            : string.Join(" ", parts);
    }
}
