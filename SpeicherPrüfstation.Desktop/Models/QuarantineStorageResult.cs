using System;
using System.Collections.Generic;

namespace SpeicherPrüfstation.Desktop.Models;

public sealed record QuarantineStorageEntry(
    string EntryId,
    DateTimeOffset QuarantinedAtUtc,
    string OriginalFilePath,
    string SourceDevicePath,
    string? SourceVendor,
    string? SourceModel,
    long OriginalSizeBytes,
    long StoredSizeBytes,
    IReadOnlyList<string> Signatures);

public sealed record QuarantineStorageSnapshot
{
    public required string DirectoryPath { get; init; }

    public long TotalStoredBytes { get; init; }

    public IReadOnlyList<QuarantineStorageEntry> Entries
    {
        get;
        init;
    } = [];

    public IReadOnlyList<string> Notices
    {
        get;
        init;
    } = [];

    public IReadOnlyList<string> TechnicalProblems
    {
        get;
        init;
    } = [];
}

public sealed record QuarantineDeletionItemResult(
    string EntryId,
    string OriginalFilePath,
    bool WasDeleted,
    long FreedBytes,
    string Message);

public sealed record QuarantineDeletionResult
{
    public bool WasCanceled { get; init; }

    public long FreedBytes { get; init; }

    public long RemainingStoredBytes { get; init; }

    public IReadOnlyList<QuarantineDeletionItemResult> Items
    {
        get;
        init;
    } = [];

    public IReadOnlyList<string> Notices
    {
        get;
        init;
    } = [];

    public IReadOnlyList<string> TechnicalProblems
    {
        get;
        init;
    } = [];
}
