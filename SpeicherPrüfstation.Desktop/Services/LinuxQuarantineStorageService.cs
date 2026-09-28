using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

public sealed class LinuxQuarantineStorageService :
    IQuarantineStorageService
{
    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();

    public async Task<QuarantineStorageSnapshot> GetSnapshotAsync(
        CancellationToken cancellationToken = default)
    {
        EnsureSupportedPlatform();

        await QuarantineStorageGate.Operation
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        try
        {
            return await QuarantineStorageSnapshotReader
                .ReadAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            QuarantineStorageGate.Operation.Release();
        }
    }

    public async Task<QuarantineDeletionResult> DeleteAsync(
        IReadOnlyList<string> entryIds,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entryIds);
        EnsureSupportedPlatform();

        if (entryIds.Count == 0)
        {
            throw new ArgumentException(
                "Es wurden keine Quarantäneeinträge ausgewählt.",
                nameof(entryIds));
        }

        await QuarantineStorageGate.Operation
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        try
        {
            return await DeleteCoreAsync(
                    entryIds,
                    progress,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            QuarantineStorageGate.Operation.Release();
        }
    }

    private static async Task<QuarantineDeletionResult>
        DeleteCoreAsync(
            IReadOnlyList<string> entryIds,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
    {
        var items =
            new List<QuarantineDeletionItemResult>();

        var notices =
            new List<string>();

        var technicalProblems =
            new List<string>();

        long freedBytes = 0;
        bool wasCanceled = false;

        string quarantineDirectory =
            QuarantineStorageFileSystem
                .ResolveQuarantineDirectory();

        if (!Directory.Exists(quarantineDirectory))
        {
            technicalProblems.Add(
                "Der Quarantäneordner ist nicht vorhanden.");

            return BuildResult(0);
        }

        QuarantineStorageFileSystem.EnsurePrivateDirectory(
            quarantineDirectory,
            "Quarantäneordner");

        var processedIds =
            new HashSet<string>(StringComparer.Ordinal);

        foreach (string requestedId in entryIds)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                wasCanceled = true;
                break;
            }

            if (!QuarantineStorageFileSystem
                    .TryNormalizeEntryId(
                        requestedId,
                        out string entryId))
            {
                technicalProblems.Add(
                    "Eine ausgewählte Eintragskennung ist ungültig.");
                continue;
            }

            if (!processedIds.Add(entryId))
            {
                technicalProblems.Add(
                    $"Der Quarantäneeintrag {entryId} wurde mehrfach ausgewählt.");
                continue;
            }

            progress?.Report(
                "Quarantäneeintrag wird vor dem Löschen geprüft: "
                + entryId);

            try
            {
                ValidatedQuarantineStorageEntry entry =
                    await QuarantineStorageEntryReader
                        .ReadAndValidateAsync(
                            quarantineDirectory,
                            entryId,
                            cancellationToken)
                        .ConfigureAwait(false);

                cancellationToken
                    .ThrowIfCancellationRequested();

                progress?.Report(
                    "Verschlüsselte Quarantänekopie wird endgültig gelöscht: "
                    + entry.Metadata.OriginalDisplayPath);

                long deletedBytes =
                    DeleteValidatedEntry(entry);

                freedBytes = checked(
                    freedBytes + deletedBytes);

                items.Add(
                    new QuarantineDeletionItemResult(
                        entryId,
                        entry.Metadata.OriginalDisplayPath,
                        true,
                        deletedBytes,
                        "Verschlüsselte Quarantänekopie und Metadaten wurden gelöscht."));
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                wasCanceled = true;
                break;
            }
            catch (Exception exception)
            {
                technicalProblems.Add(
                    $"Quarantäneeintrag {entryId}: "
                    + exception.Message);

                items.Add(
                    new QuarantineDeletionItemResult(
                        entryId,
                        "Nicht sicher auswertbar",
                        false,
                        0,
                        "Nicht gelöscht: "
                        + exception.Message));
            }
        }

        if (wasCanceled)
        {
            notices.Add(
                "Die Bereinigung wurde abgebrochen. Bereits bestätigte Löschungen bleiben wirksam.");
        }

        TryDeleteUnusedKey(
            quarantineDirectory,
            notices,
            technicalProblems);

        long remainingBytes =
            QuarantineStorageFileSystem.CalculateDirectorySize(
                quarantineDirectory,
                technicalProblems);

        return BuildResult(remainingBytes);

        QuarantineDeletionResult BuildResult(
            long remainingStoredBytes)
        {
            return new QuarantineDeletionResult
            {
                WasCanceled = wasCanceled,
                FreedBytes = freedBytes,
                RemainingStoredBytes =
                    remainingStoredBytes,
                Items = items.ToArray(),
                Notices = notices.ToArray(),
                TechnicalProblems =
                    technicalProblems.ToArray()
            };
        }
    }

    private static long DeleteValidatedEntry(
        ValidatedQuarantineStorageEntry entry)
    {
        QuarantineStorageFileSystem.EnsureUnchanged(
            entry.MetadataPath,
            entry.MetadataSnapshot,
            "Die Quarantänemetadaten wurden vor dem Löschen verändert.");

        QuarantineStorageFileSystem.EnsureUnchanged(
            entry.PayloadPath,
            entry.PayloadSnapshot,
            "Die verschlüsselte Quarantänedatei wurde vor dem Löschen verändert.");

        File.Delete(entry.PayloadPath);

        if (File.Exists(entry.PayloadPath)
            || Directory.Exists(entry.PayloadPath))
        {
            throw new IOException(
                "Die verschlüsselte Quarantänedatei ist nach dem Löschaufruf weiterhin vorhanden.");
        }

        try
        {
            File.Delete(entry.MetadataPath);
        }
        catch (Exception exception)
        {
            throw new IOException(
                "Die verschlüsselte Datei wurde gelöscht, ihre Metadaten konnten jedoch nicht entfernt werden.",
                exception);
        }

        if (File.Exists(entry.MetadataPath)
            || Directory.Exists(entry.MetadataPath))
        {
            throw new IOException(
                "Die Quarantänemetadaten sind nach dem Löschaufruf weiterhin vorhanden.");
        }

        return checked(
            entry.MetadataSnapshot.Length
            + entry.PayloadSnapshot.Length);
    }

    private static void TryDeleteUnusedKey(
        string quarantineDirectory,
        ICollection<string> notices,
        ICollection<string> technicalProblems)
    {
        string keyPath = Path.Combine(
            quarantineDirectory,
            "quarantine.key");

        if (!File.Exists(keyPath))
            return;

        bool hasOtherEntries =
            Directory.GetFileSystemEntries(
                    quarantineDirectory,
                    "*",
                    SearchOption.TopDirectoryOnly)
                .Any(path =>
                    !string.Equals(
                        Path.GetFileName(path),
                        "quarantine.key",
                        StringComparison.Ordinal));

        if (hasOtherEntries)
            return;

        try
        {
            QuarantineStorageFileSystem.EnsurePrivateFile(
                keyPath,
                QuarantineStorageFileSystem.EncryptionKeySize,
                QuarantineStorageFileSystem.EncryptionKeySize,
                "Quarantäneschlüssel");

            File.Delete(keyPath);

            if (File.Exists(keyPath))
            {
                throw new IOException(
                    "Der Quarantäneschlüssel ist nach dem Löschaufruf weiterhin vorhanden.");
            }

            notices.Add(
                "Der nicht mehr benötigte Quarantäneschlüssel wurde ebenfalls gelöscht.");
        }
        catch (Exception exception)
        {
            technicalProblems.Add(
                "Der nicht mehr benötigte Quarantäneschlüssel konnte nicht gelöscht werden: "
                + exception.Message);
        }
    }

    private static void EnsureSupportedPlatform()
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException(
                "Die Quarantäneverwaltung ist nur unter Linux verfügbar.");
        }

        if (GetEffectiveUserId() == 0)
        {
            throw new IOException(
                "Bitte die Anwendung als normalen Benutzer starten.");
        }
    }
}
