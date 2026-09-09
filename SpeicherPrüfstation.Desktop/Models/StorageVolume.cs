using System.Collections.Generic;

namespace SpeicherPrüfstation.Desktop.Models;

public sealed record StorageVolume
{
    public required string Name { get; init; }

    public required string DevicePath { get; init; }

    public required string NodeType { get; init; }

    public long SizeBytes { get; init; }

    public bool IsReadOnly { get; init; }

    public string? FileSystem { get; init; }

    public string? Label { get; init; }

    public IReadOnlyList<string> MountPoints { get; init; } = [];

    public bool IsMounted => MountPoints.Count > 0;
}
