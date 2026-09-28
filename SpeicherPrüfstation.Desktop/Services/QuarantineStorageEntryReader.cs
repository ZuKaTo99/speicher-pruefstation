using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace SpeicherPrüfstation.Desktop.Services;

internal static class QuarantineStorageEntryReader
{
    private static readonly JsonSerializerOptions MetadataOptions =
        new()
        {
            UnmappedMemberHandling =
                JsonUnmappedMemberHandling.Disallow
        };

    internal static async Task<ValidatedQuarantineStorageEntry>
        ReadAndValidateAsync(
            string quarantineDirectory,
            string entryId,
            CancellationToken cancellationToken)
    {
        if (!QuarantineStorageFileSystem.TryNormalizeEntryId(
                entryId,
                out string normalizedId))
        {
            throw new IOException(
                "Die Eintragskennung ist ungültig.");
        }

        string metadataPath =
            QuarantineStorageFileSystem.ResolveOwnedFilePath(
                quarantineDirectory,
                normalizedId + ".json");

        string payloadPath =
            QuarantineStorageFileSystem.ResolveOwnedFilePath(
                quarantineDirectory,
                normalizedId + ".quarantine");

        QuarantineStorageFileSystem.EnsurePrivateFile(
            metadataPath,
            1,
            QuarantineStorageFileSystem.MaximumMetadataSize,
            "Quarantänemetadaten");

        QuarantineFileSnapshot metadataSnapshot =
            QuarantineStorageFileSystem.CaptureFileSnapshot(
                metadataPath);

        StoredQuarantineMetadata metadata =
            await ReadMetadataAsync(
                    metadataPath,
                    cancellationToken)
                .ConfigureAwait(false);

        QuarantineStorageFileSystem.EnsureUnchanged(
            metadataPath,
            metadataSnapshot,
            "Die Quarantänemetadaten wurden während der Prüfung verändert.");

        ValidateMetadata(normalizedId, metadata);

        long expectedPayloadLength =
            QuarantineStorageFileSystem.CalculatePayloadLength(
                metadata.SizeBytes);

        QuarantineStorageFileSystem.EnsurePrivateFile(
            payloadPath,
            expectedPayloadLength,
            expectedPayloadLength,
            "verschlüsselte Quarantänedatei");

        QuarantineFileSnapshot payloadSnapshot =
            QuarantineStorageFileSystem.CaptureFileSnapshot(
                payloadPath);

        ValidatePayloadHeader(
            payloadPath,
            metadata.SizeBytes);

        QuarantineStorageFileSystem.EnsureUnchanged(
            payloadPath,
            payloadSnapshot,
            "Die verschlüsselte Quarantänedatei wurde während der Prüfung verändert.");

        return new ValidatedQuarantineStorageEntry(
            metadata,
            metadataPath,
            payloadPath,
            metadataSnapshot,
            payloadSnapshot);
    }

    private static async Task<StoredQuarantineMetadata>
        ReadMetadataAsync(
            string path,
            CancellationToken cancellationToken)
    {
        var options =
            new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = FileShare.Read,
                BufferSize = 16 * 1024,
                Options =
                    FileOptions.Asynchronous
                    | FileOptions.SequentialScan
            };

        await using var stream =
            new FileStream(path, options);

        StoredQuarantineMetadata? metadata;

        try
        {
            metadata =
                await JsonSerializer
                    .DeserializeAsync<StoredQuarantineMetadata>(
                        stream,
                        MetadataOptions,
                        cancellationToken)
                    .ConfigureAwait(false);
        }
        catch (JsonException exception)
        {
            throw new IOException(
                "Die Quarantänemetadaten sind ungültig.",
                exception);
        }

        return metadata
               ?? throw new IOException(
                   "Die Quarantänemetadaten sind leer.");
    }

    private static void ValidateMetadata(
        string entryId,
        StoredQuarantineMetadata metadata)
    {
        if (metadata.FormatVersion != 1)
        {
            throw new IOException(
                "Die Version der Quarantänemetadaten wird nicht unterstützt.");
        }

        if (metadata.EntryId != entryId
            || metadata.PayloadFileName
            != entryId + ".quarantine")
        {
            throw new IOException(
                "Kennung und Dateinamen des Quarantäneeintrags stimmen nicht überein.");
        }

        if (metadata.QuarantinedAtUtc == default
            || metadata.QuarantinedAtUtc
            > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            throw new IOException(
                "Der gespeicherte Quarantänezeitpunkt ist ungültig.");
        }

        if (!IsSafeDevicePath(metadata.SourceDevicePath)
            || !IsSafeDevicePath(metadata.SourceVolumePath)
            || !IsSafeText(metadata.SourceKernelName, 255)
            || !IsOptionalSafeText(metadata.SourceVendor, 1024)
            || !IsOptionalSafeText(metadata.SourceModel, 1024)
            || metadata.SourceDeviceSizeBytes < 0)
        {
            throw new IOException(
                "Die gespeicherten Gerätedaten sind ungültig.");
        }

        if (!QuarantineStorageFileSystem.IsSafeRelativePath(
                metadata.OriginalRelativePath)
            || string.IsNullOrWhiteSpace(
                metadata.OriginalDisplayPath)
            || metadata.OriginalDisplayPath.Any(char.IsControl)
            || metadata.OriginalDisplayPath
            != metadata.SourceVolumePath
               + ":/"
               + metadata.OriginalRelativePath)
        {
            throw new IOException(
                "Der gespeicherte Originalpfad ist ungültig.");
        }

        if (metadata.SizeBytes < 0
            || !QuarantineStorageFileSystem.IsSha256(
                metadata.Sha256))
        {
            throw new IOException(
                "Größe oder Prüfsumme des Quarantäneeintrags ist ungültig.");
        }

        if (metadata.Signatures is null
            || metadata.Signatures.Count == 0
            || metadata.Signatures.Count > 10000
            || metadata.Signatures.Any(signature =>
                !IsSafeText(signature, 4096)))
        {
            throw new IOException(
                "Die gespeicherten Erkennungssignaturen sind ungültig.");
        }
    }

    private static void ValidatePayloadHeader(
        string path,
        long expectedOriginalLength)
    {
        Span<byte> header = stackalloc byte[24];

        try
        {
            using var stream =
                new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read);

            stream.ReadExactly(header);
        }
        catch (EndOfStreamException exception)
        {
            throw new IOException(
                "Der Kopf der verschlüsselten Quarantänedatei ist unvollständig.",
                exception);
        }

        if (!header[..4].SequenceEqual(
                QuarantineStorageFileSystem.PayloadMagic)
            || BinaryPrimitives.ReadInt32LittleEndian(
                header.Slice(4, 4))
            != QuarantineStorageFileSystem.EncryptionChunkSize
            || BinaryPrimitives.ReadInt64LittleEndian(
                header.Slice(8, 8))
            != expectedOriginalLength)
        {
            throw new IOException(
                "Der Kopf der verschlüsselten Quarantänedatei ist ungültig.");
        }
    }

    private static bool IsSafeDevicePath(string? value)
    {
        return !string.IsNullOrWhiteSpace(value)
               && value.StartsWith(
                   "/dev/",
                   StringComparison.Ordinal)
               && Path.IsPathFullyQualified(value)
               && !value.Any(char.IsControl)
               && value.Length <= 4096;
    }

    private static bool IsSafeText(
        string? value,
        int maximumLength)
    {
        return !string.IsNullOrWhiteSpace(value)
               && value.Length <= maximumLength
               && !value.Any(char.IsControl);
    }

    private static bool IsOptionalSafeText(
        string? value,
        int maximumLength)
    {
        return value is null
               || value.Length <= maximumLength
               && !value.Any(char.IsControl);
    }
}
