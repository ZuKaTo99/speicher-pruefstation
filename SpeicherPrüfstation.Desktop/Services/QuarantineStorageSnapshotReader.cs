using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

internal static class QuarantineStorageSnapshotReader
{
    internal static async Task<QuarantineStorageSnapshot> ReadAsync(
        CancellationToken cancellationToken)
    {
        string quarantineDirectory =
            QuarantineStorageFileSystem
                .ResolveQuarantineDirectory();

        var entries =
            new List<QuarantineStorageEntry>();

        var notices =
            new List<string>();

        var technicalProblems =
            new List<string>();

        if (!Directory.Exists(quarantineDirectory))
        {
            return new QuarantineStorageSnapshot
            {
                DirectoryPath = quarantineDirectory
            };
        }

        QuarantineStorageFileSystem.EnsurePrivateDirectory(
            quarantineDirectory,
            "Quarantäneordner");

        string[] paths = Directory.GetFileSystemEntries(
            quarantineDirectory,
            "*",
            SearchOption.TopDirectoryOnly);

        var metadataIds =
            new SortedSet<string>(StringComparer.Ordinal);

        var payloadIds =
            new SortedSet<string>(StringComparer.Ordinal);

        foreach (string path in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();

            InspectDirectoryEntry(
                path,
                metadataIds,
                payloadIds,
                technicalProblems);
        }

        foreach (string entryId in metadataIds)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                ValidatedQuarantineStorageEntry entry =
                    await QuarantineStorageEntryReader
                        .ReadAndValidateAsync(
                            quarantineDirectory,
                            entryId,
                            cancellationToken)
                        .ConfigureAwait(false);

                entries.Add(CreatePublicEntry(entry));
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                technicalProblems.Add(
                    $"Quarantäneeintrag {entryId}: "
                    + exception.Message);
            }
        }

        foreach (string entryId in payloadIds)
        {
            if (!metadataIds.Contains(entryId))
            {
                technicalProblems.Add(
                    "Verschlüsselte Quarantänedatei ohne Metadaten: "
                    + entryId);
            }
        }

        string keyPath = Path.Combine(
            quarantineDirectory,
            "quarantine.key");

        if (metadataIds.Count > 0
            && !File.Exists(keyPath))
        {
            technicalProblems.Add(
                "Der Quarantäneschlüssel fehlt.");
        }

        long totalStoredBytes =
            QuarantineStorageFileSystem.CalculateDirectorySize(
                quarantineDirectory,
                technicalProblems);

        return new QuarantineStorageSnapshot
        {
            DirectoryPath = quarantineDirectory,
            TotalStoredBytes = totalStoredBytes,
            Entries = entries
                .OrderByDescending(
                    entry => entry.QuarantinedAtUtc)
                .ThenBy(
                    entry => entry.OriginalFilePath,
                    StringComparer.Ordinal)
                .ToArray(),
            Notices = notices.ToArray(),
            TechnicalProblems =
                technicalProblems.ToArray()
        };
    }

    private static void InspectDirectoryEntry(
        string path,
        ISet<string> metadataIds,
        ISet<string> payloadIds,
        ICollection<string> technicalProblems)
    {
        var info = new FileInfo(path);

        if (info.LinkTarget is not null
            || (File.GetAttributes(path)
                & FileAttributes.ReparsePoint) != 0)
        {
            technicalProblems.Add(
                "Symbolischer Link im Quarantäneordner: "
                + info.Name);
            return;
        }

        if (Directory.Exists(path))
        {
            technicalProblems.Add(
                "Unerwarteter Unterordner im Quarantäneordner: "
                + info.Name);
            return;
        }

        if (info.Name == "quarantine.key")
        {
            try
            {
                QuarantineStorageFileSystem.EnsurePrivateFile(
                    path,
                    QuarantineStorageFileSystem
                        .EncryptionKeySize,
                    QuarantineStorageFileSystem
                        .EncryptionKeySize,
                    "Quarantäneschlüssel");
            }
            catch (Exception exception)
            {
                technicalProblems.Add(
                    "Quarantäneschlüssel: "
                    + exception.Message);
            }

            return;
        }

        if (QuarantineStorageFileSystem
            .TryGetEntryIdFromMetadataName(
                info.Name,
                out string metadataId))
        {
            metadataIds.Add(metadataId);
            return;
        }

        if (QuarantineStorageFileSystem
            .TryGetEntryIdFromPayloadName(
                info.Name,
                out string payloadId))
        {
            payloadIds.Add(payloadId);
            return;
        }

        technicalProblems.Add(
            "Unbekannte Datei im Quarantäneordner: "
            + info.Name);
    }

    private static QuarantineStorageEntry CreatePublicEntry(
        ValidatedQuarantineStorageEntry entry)
    {
        return new QuarantineStorageEntry(
            entry.Metadata.EntryId,
            entry.Metadata.QuarantinedAtUtc,
            entry.Metadata.OriginalDisplayPath,
            entry.Metadata.SourceDevicePath,
            entry.Metadata.SourceVendor,
            entry.Metadata.SourceModel,
            entry.Metadata.SizeBytes,
            checked(
                entry.MetadataSnapshot.Length
                + entry.PayloadSnapshot.Length),
            entry.Metadata.Signatures.ToArray());
    }
}
