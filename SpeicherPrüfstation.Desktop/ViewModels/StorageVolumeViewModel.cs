using System;
using SpeicherPrüfstation.Desktop.Formatting;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.ViewModels;

public sealed class StorageVolumeViewModel
{
    public StorageVolumeViewModel(
        StorageVolume volume)
    {
        Volume = volume
                 ?? throw new ArgumentNullException(
                     nameof(volume));
    }

    public StorageVolume Volume { get; }

    public string Name => Volume.Name;

    public string DevicePath => Volume.DevicePath;

    public string SizeText =>
        ByteSizeFormatter.Format(Volume.SizeBytes);

    public string FileSystemText =>
        GetTextOrFallback(
            Volume.FileSystem,
            "Nicht erkannt");

    public string LabelText =>
        GetTextOrFallback(
            Volume.Label,
            "Ohne Bezeichnung");

    public string AccessText =>
        Volume.IsReadOnly
            ? "Schreibgeschützt"
            : "Beschreibbar";

    public string MountPointText =>
        Volume.IsMounted
            ? string.Join(", ", Volume.MountPoints)
            : "Nicht eingehängt";

    private static string GetTextOrFallback(
        string? value,
        string fallback)
    {
        return string.IsNullOrWhiteSpace(value)
            ? fallback
            : value.Trim();
    }
}
