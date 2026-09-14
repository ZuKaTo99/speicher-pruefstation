using System.Collections.Generic;

namespace SpeicherPrüfstation.Desktop.Models;

public enum VirusScanState
{
    NoFindings,
    Findings,
    Incomplete,
    Failed,
    Canceled
}

public sealed record VirusFinding(string FilePath, string Signature);

public sealed record VirusScanProgress(
    string Status,
    long ScannedFiles,
    long Findings,
    long Errors,
    long Warnings);

public sealed record VirusScanCleanupResult(
    bool HasPendingMounts,
    IReadOnlyList<string> Messages);

public sealed record VirusScanResult
{
    public required string DevicePath { get; init; }
    public required VirusScanState State { get; init; }
    public required string Summary { get; init; }
    public long ScannedFiles { get; init; }
    public long ErrorCount { get; init; }
    public bool HasPendingMounts { get; init; }
    public IReadOnlyList<VirusFinding> Findings { get; init; } = [];
    public IReadOnlyList<string> Errors { get; init; } = [];
    public IReadOnlyList<string> Warnings { get; init; } = [];
}