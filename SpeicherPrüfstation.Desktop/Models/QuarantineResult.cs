using System.Collections.Generic;

namespace SpeicherPrüfstation.Desktop.Models;

public sealed record QuarantineItemResult(
    string EntryId,
    string OriginalFilePath,
    long SizeBytes,
    string Sha256,
    IReadOnlyList<string> Signatures);

public sealed record QuarantineResult
{
    public required string DirectoryPath { get; init; }
    public bool WasCanceled { get; init; }
    public bool HasPendingMounts { get; init; }
    public IReadOnlyList<QuarantineItemResult> Items { get; init; } = [];
    public IReadOnlyList<string> Errors { get; init; } = [];
    public IReadOnlyList<string> Warnings { get; init; } = [];
}
