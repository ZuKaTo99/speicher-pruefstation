namespace SpeicherPrüfstation.Desktop.Models;

public enum SmartHealthState
{
    Passed,
    Warning,
    Unavailable,
    Error
}

public sealed record SmartHealthResult
{
    public required string DevicePath { get; init; }

    public required SmartHealthState State { get; init; }

    public required string Summary { get; init; }

    public required string DeviceType { get; init; }

    public required int ExitStatus { get; init; }

    public string? ModelName { get; init; }

    public string? SerialNumber { get; init; }

    public long? CapacityBytes { get; init; }

    public int? LogicalBlockSizeBytes { get; init; }

    public int? TemperatureCelsius { get; init; }

    public bool? SmartAvailable { get; init; }

    public bool? SmartEnabled { get; init; }

    public bool? Passed { get; init; }

    public string RawJson { get; init; } = string.Empty;
}
