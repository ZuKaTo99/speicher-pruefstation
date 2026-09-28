using System;
using System.Collections.Generic;

namespace SpeicherPrüfstation.Desktop.Services;

internal sealed record StoredQuarantineMetadata(
    int FormatVersion,
    string EntryId,
    DateTimeOffset QuarantinedAtUtc,
    string SourceDevicePath,
    string SourceKernelName,
    string? SourceModel,
    string? SourceVendor,
    long SourceDeviceSizeBytes,
    ulong? SourceDiskSequence,
    string SourceVolumePath,
    string OriginalRelativePath,
    string OriginalDisplayPath,
    IReadOnlyList<string> Signatures,
    long SizeBytes,
    string Sha256,
    string PayloadFileName);

internal sealed record QuarantineFileSnapshot(
    long Length,
    DateTime LastWriteTimeUtc);

internal sealed record ValidatedQuarantineStorageEntry(
    StoredQuarantineMetadata Metadata,
    string MetadataPath,
    string PayloadPath,
    QuarantineFileSnapshot MetadataSnapshot,
    QuarantineFileSnapshot PayloadSnapshot);
    