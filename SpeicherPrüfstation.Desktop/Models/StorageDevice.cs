using System.Collections.Generic;

namespace SpeicherPrüfstation.Desktop.Models;

public sealed record StorageDevice
{
    public required string Name { get; init; }

    public required string DevicePath { get; init; }

    public string? Transport { get; init; }

    public bool IsRemovable { get; init; }

    public bool IsHotPlug { get; init; }

    public long SizeBytes { get; init; }

    public bool IsReadOnly { get; init; }

    public string? Model { get; init; }

    public string? Vendor { get; init; }

    public IReadOnlyList<StorageVolume> Volumes { get; init; } = [];
}
