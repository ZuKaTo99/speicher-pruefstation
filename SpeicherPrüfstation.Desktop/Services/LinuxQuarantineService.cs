using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

public sealed class LinuxQuarantineService : IQuarantineService
{
    private const int EncryptionChunkSize = 1024 * 1024;
    private const int EncryptionKeySize = 32;
    private const int AuthenticationTagSize = 16;
    private const long RequiredFreeSpaceReserve = 16L * 1024 * 1024;

    private static readonly byte[] PayloadMagic = [(byte)'S', (byte)'P', (byte)'Q', (byte)'1'];

    private static readonly UnixFileMode PrivateFileMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private static readonly UnixFileMode PrivateDirectoryMode =
        UnixFileMode.UserRead
        | UnixFileMode.UserWrite
        | UnixFileMode.UserExecute;

    private static readonly JsonSerializerOptions MetadataOptions = new()
    {
        WriteIndented = true
    };

    private readonly LinuxScanMountService _mounts;
    private readonly SemaphoreSlim _operation = new(1, 1);
    private volatile bool _hasPendingMounts;

    public LinuxQuarantineService(
        IStorageDeviceService storageDeviceService)
    {
        ArgumentNullException.ThrowIfNull(storageDeviceService);

        _mounts = new LinuxScanMountService(
            storageDeviceService);
    }

    public bool HasPendingMounts => _hasPendingMounts;

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();

    public async Task<QuarantineResult> QuarantineAsync(
        StorageDevice device,
        IReadOnlyList<VirusFinding> findings,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(findings);

        if (findings.Count == 0)
        {
            throw new ArgumentException(
                "Es wurden keine Funddateien übergeben.",
                nameof(findings));
        }

        if (!await _operation
                .WaitAsync(0, cancellationToken)
                .ConfigureAwait(false))
        {
            throw new InvalidOperationException(
                "Es läuft bereits eine Quarantäneoperation.");
        }

        var items = new List<QuarantineItemResult>();
        var errors = new List<string>();
        var warnings = new List<string>();

        string quarantineDirectory = string.Empty;
        byte[]? encryptionKey = null;

        try
        {
            if (!OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException(
                    "Die Quarantäne ist nur unter Linux verfügbar.");
            }

            if (GetEffectiveUserId() == 0)
            {
                throw new IOException(
                    "Bitte die Anwendung als normalen Benutzer starten.");
            }

            if (_mounts.HasPendingMounts)
            {
                throw new IOException(
                    "Zuerst die ausstehende Einhängung aufräumen.");
            }

            StorageDevice current =
                await _mounts.ValidateSelectionAsync(
                        device,
                        cancellationToken)
                    .ConfigureAwait(false);

            IReadOnlyList<QuarantineTarget> targets =
                MapTargets(current, findings, errors);

            if (targets.Count == 0)
            {
                return new QuarantineResult
                {
                    DirectoryPath = string.Empty,
                    Errors = errors.ToArray()
                };
            }

            quarantineDirectory =
                PrepareQuarantineDirectory();

            byte[] operationKey =
                LoadOrCreateKey(quarantineDirectory);

            encryptionKey = operationKey;

            foreach (IGrouping<string, QuarantineTarget> group
                     in targets.GroupBy(
                         target => target.Volume.DevicePath,
                         StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();

                StorageVolume volume =
                    group.First().Volume;

                try
                {
                    progress?.Report(
                        $"{volume.DevicePath} wird für die "
                        + "Quarantäne lesend eingehängt …");

                    ScanMountLease lease =
                        await _mounts.MountAsync(
                                current,
                                volume,
                                cancellationToken)
                            .ConfigureAwait(false);

                    await WithMountGuardAsync(
                            lease,
                            async token =>
                            {
                                foreach (QuarantineTarget target
                                         in group)
                                {
                                    token.ThrowIfCancellationRequested();

                                    progress?.Report(
                                        "Wird verschlüsselt gesichert: "
                                        + target.DisplayPath);

                                    try
                                    {
                                        QuarantineItemResult item =
                                            await CreateEntryAsync(
                                                    current,
                                                    lease,
                                                    target,
                                                    quarantineDirectory,
                                                    operationKey,
                                                    token)
                                                .ConfigureAwait(false);

                                        items.Add(item);

                                        await _mounts
                                            .EnsureSafeMountAsync(
                                                lease,
                                                token)
                                            .ConfigureAwait(false);
                                    }
                                    catch (OperationCanceledException)
                                    {
                                        throw;
                                    }
                                    catch (Exception exception)
                                    {
                                        errors.Add(
                                            $"{target.DisplayPath}: "
                                            + exception.Message);
                                    }
                                }
                            },
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    errors.Add(
                        $"{volume.DevicePath}: "
                        + "Quarantäneoperation abgebrochen. "
                        + exception.Message);

                    break;
                }
                finally
                {
                    progress?.Report(
                        "Eigene Einhängung wird ausgehängt "
                        + "und kontrolliert …");

                    warnings.AddRange(
                        await _mounts
                            .CleanupAsync(false)
                            .ConfigureAwait(false));

                    _hasPendingMounts =
                        _mounts.HasPendingMounts;
                }

                if (_mounts.HasPendingMounts)
                {
                    break;
                }
            }

            return new QuarantineResult
            {
                DirectoryPath = quarantineDirectory,
                HasPendingMounts =
                    _mounts.HasPendingMounts,
                Items = items.ToArray(),
                Errors = errors.ToArray(),
                Warnings = warnings.ToArray()
            };
        }
        catch (OperationCanceledException)
        {
            warnings.Add(
                "Die Quarantäneoperation wurde abgebrochen. "
                + "Bereits vollständig gesicherte Einträge "
                + "bleiben erhalten.");

            return new QuarantineResult
            {
                DirectoryPath = quarantineDirectory,
                WasCanceled = true,
                HasPendingMounts =
                    _mounts.HasPendingMounts,
                Items = items.ToArray(),
                Errors = errors.ToArray(),
                Warnings = warnings.ToArray()
            };
        }
        finally
        {
            if (encryptionKey is not null)
            {
                CryptographicOperations.ZeroMemory(
                    encryptionKey);
            }

            _hasPendingMounts =
                _mounts.HasPendingMounts;

            _operation.Release();
        }
    }

    public async Task<VirusScanCleanupResult>
        RetryCleanupAsync()
    {
        if (!await _operation
                .WaitAsync(0)
                .ConfigureAwait(false))
        {
            throw new InvalidOperationException(
                "Die laufende Quarantäneoperation "
                + "muss zuerst enden.");
        }

        try
        {
            IReadOnlyList<string> messages =
                await _mounts
                    .CleanupAsync(true)
                    .ConfigureAwait(false);

            return new VirusScanCleanupResult(
                _mounts.HasPendingMounts,
                messages);
        }
        finally
        {
            _hasPendingMounts =
                _mounts.HasPendingMounts;

            _operation.Release();
        }
    }

    private async Task WithMountGuardAsync(
        ScanMountLease lease,
        Func<CancellationToken, Task> action,
        CancellationToken cancellationToken)
    {
        using var operationToken =
            CancellationTokenSource
                .CreateLinkedTokenSource(
                    cancellationToken);

        using var stopWatcher =
            new CancellationTokenSource();

        Exception? mountError = null;
        Task watcher = WatchAsync();

        try
        {
            await action(operationToken.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (mountError is not null)
        {
            throw new IOException(
                "Der Mountzustand hat sich geändert: "
                + mountError.Message,
                mountError);
        }
        finally
        {
            stopWatcher.Cancel();

            await watcher.ConfigureAwait(false);
        }

        if (mountError is not null)
        {
            throw new IOException(
                "Der Mountzustand ist unsicher: "
                + mountError.Message,
                mountError);
        }

        async Task WatchAsync()
        {
            try
            {
                while (true)
                {
                    await Task.Delay(
                            1000,
                            stopWatcher.Token)
                        .ConfigureAwait(false);

                    await _mounts
                        .EnsureSafeMountAsync(
                            lease,
                            stopWatcher.Token)
                        .ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
                when (stopWatcher.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                mountError = exception;
                operationToken.Cancel();
            }
        }
    }

    private static IReadOnlyList<QuarantineTarget>
        MapTargets(
            StorageDevice device,
            IReadOnlyList<VirusFinding> findings,
            ICollection<string> errors)
    {
        var targets =
            new List<QuarantineTarget>();

        foreach (IGrouping<string, VirusFinding> group
                 in findings.GroupBy(
                     finding => finding.FilePath,
                     StringComparer.Ordinal))
        {
            string displayPath = group.Key;

            StorageVolume[] matchingVolumes =
                device.Volumes
                    .Where(volume =>
                        displayPath.StartsWith(
                            volume.DevicePath + ":/",
                            StringComparison.Ordinal))
                    .ToArray();

            if (matchingVolumes.Length != 1)
            {
                errors.Add(
                    $"{displayPath}: "
                    + "Das zugehörige Volume ist "
                    + "nicht eindeutig.");

                continue;
            }

            StorageVolume volume =
                matchingVolumes[0];

            string relativePath =
                displayPath[
                    (volume.DevicePath.Length + 2)..];

            if (!IsSafeRelativePath(relativePath))
            {
                errors.Add(
                    $"{displayPath}: "
                    + "Der gespeicherte Dateipfad "
                    + "ist nicht sicher auswertbar.");

                continue;
            }

            string[] signatures =
                group.Select(
                        finding => finding.Signature)
                    .Where(signature =>
                        !string.IsNullOrWhiteSpace(
                            signature))
                    .Distinct(StringComparer.Ordinal)
                    .ToArray();

            if (signatures.Length == 0)
            {
                errors.Add(
                    $"{displayPath}: "
                    + "Es ist keine Fundsignatur vorhanden.");

                continue;
            }

            targets.Add(
                new QuarantineTarget(
                    volume,
                    relativePath,
                    displayPath,
                    signatures));
        }

        return targets;
    }

    private static async Task<QuarantineItemResult>
        CreateEntryAsync(
            StorageDevice device,
            ScanMountLease lease,
            QuarantineTarget target,
            string quarantineDirectory,
            byte[] encryptionKey,
            CancellationToken cancellationToken)
    {
        string sourcePath =
            ResolveSourcePath(
                lease.Target!,
                target.RelativePath);

        var sourceInfo =
            new FileInfo(sourcePath);

        sourceInfo.Refresh();

        long sourceLength =
            sourceInfo.Length;

        DateTime sourceWriteTimeUtc =
            sourceInfo.LastWriteTimeUtc;

        EnsureFreeSpace(
            quarantineDirectory,
            sourceLength);

        Guid entryId = Guid.NewGuid();
        string entryName =
            entryId.ToString("N");

        string payloadName =
            entryName + ".quarantine";

        string metadataName =
            entryName + ".json";

        string payloadPath =
            Path.Combine(
                quarantineDirectory,
                payloadName);

        string metadataPath =
            Path.Combine(
                quarantineDirectory,
                metadataName);

        string temporaryPayloadPath =
            payloadPath + ".part";

        string temporaryMetadataPath =
            metadataPath + ".part";

        try
        {
            EncryptionResult encrypted =
                await EncryptFileAsync(
                        sourcePath,
                        sourceLength,
                        sourceWriteTimeUtc,
                        temporaryPayloadPath,
                        entryId,
                        encryptionKey,
                        cancellationToken)
                    .ConfigureAwait(false);

            var metadata =
                new QuarantineMetadata(
                    1,
                    entryName,
                    DateTimeOffset.UtcNow,
                    device.DevicePath,
                    device.Name,
                    device.Model,
                    device.Vendor,
                    device.SizeBytes,
                    device.DiskSequence,
                    target.Volume.DevicePath,
                    target.RelativePath,
                    target.DisplayPath,
                    target.Signatures,
                    encrypted.SizeBytes,
                    encrypted.Sha256,
                    payloadName);

            await WriteMetadataAsync(
                    temporaryMetadataPath,
                    metadata,
                    cancellationToken)
                .ConfigureAwait(false);

            File.Move(
                temporaryPayloadPath,
                payloadPath);

            File.Move(
                temporaryMetadataPath,
                metadataPath);

            return new QuarantineItemResult(
                entryName,
                target.DisplayPath,
                encrypted.SizeBytes,
                encrypted.Sha256,
                target.Signatures);
        }
        catch
        {
            DeleteOwnFile(
                temporaryPayloadPath);

            DeleteOwnFile(
                temporaryMetadataPath);

            DeleteOwnFile(payloadPath);
            DeleteOwnFile(metadataPath);

            throw;
        }
    }

    private static async Task<EncryptionResult>
        EncryptFileAsync(
            string sourcePath,
            long expectedLength,
            DateTime expectedWriteTimeUtc,
            string outputPath,
            Guid entryId,
            byte[] encryptionKey,
            CancellationToken cancellationToken)
    {
        var sourceOptions =
            new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = FileShare.Read,
                BufferSize = 128 * 1024,
                Options =
                    FileOptions.Asynchronous
                    | FileOptions.SequentialScan
            };

        var outputOptions =
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                BufferSize = 128 * 1024,
                Options =
                    FileOptions.Asynchronous
                    | FileOptions.SequentialScan,
                UnixCreateMode = PrivateFileMode
            };

        await using var source =
            new FileStream(
                sourcePath,
                sourceOptions);

        await using var output =
            new FileStream(
                outputPath,
                outputOptions);

        File.SetUnixFileMode(
            outputPath,
            PrivateFileMode);

        byte[] noncePrefix =
            RandomNumberGenerator.GetBytes(8);

        byte[] header = new byte[24];

        PayloadMagic.CopyTo(header, 0);

        BinaryPrimitives.WriteInt32LittleEndian(
            header.AsSpan(4, 4),
            EncryptionChunkSize);

        BinaryPrimitives.WriteInt64LittleEndian(
            header.AsSpan(8, 8),
            expectedLength);

        noncePrefix.CopyTo(header, 16);

        await output.WriteAsync(
                header,
                cancellationToken)
            .ConfigureAwait(false);

        byte[] plaintext =
            ArrayPool<byte>.Shared.Rent(
                EncryptionChunkSize);

        byte[] ciphertext =
            ArrayPool<byte>.Shared.Rent(
                EncryptionChunkSize);

        byte[] tag =
            new byte[AuthenticationTagSize];

        byte[] nonce = new byte[12];
        byte[] lengthBuffer = new byte[4];
        byte[] additionalData = new byte[24];

        entryId.TryWriteBytes(
            additionalData.AsSpan(0, 16));

        long totalBytes = 0;
        uint chunkNumber = 0;

        try
        {
            using var hash =
                IncrementalHash.CreateHash(
                    HashAlgorithmName.SHA256);

            using var aes =
                new AesGcm(
                    encryptionKey,
                    AuthenticationTagSize);

            while (true)
            {
                int bytesRead =
                    await source.ReadAsync(
                            plaintext.AsMemory(
                                0,
                                EncryptionChunkSize),
                            cancellationToken)
                        .ConfigureAwait(false);

                if (bytesRead == 0)
                {
                    break;
                }

                hash.AppendData(
                    plaintext.AsSpan(
                        0,
                        bytesRead));

                noncePrefix.CopyTo(nonce, 0);

                BinaryPrimitives.WriteUInt32BigEndian(
                    nonce.AsSpan(8, 4),
                    chunkNumber);

                BinaryPrimitives.WriteUInt32BigEndian(
                    additionalData.AsSpan(16, 4),
                    chunkNumber);

                BinaryPrimitives.WriteInt32BigEndian(
                    additionalData.AsSpan(20, 4),
                    bytesRead);

                aes.Encrypt(
                    nonce,
                    plaintext.AsSpan(
                        0,
                        bytesRead),
                    ciphertext.AsSpan(
                        0,
                        bytesRead),
                    tag,
                    additionalData);

                BinaryPrimitives.WriteInt32LittleEndian(
                    lengthBuffer,
                    bytesRead);

                await output.WriteAsync(
                        lengthBuffer,
                        cancellationToken)
                    .ConfigureAwait(false);

                await output.WriteAsync(
                        ciphertext.AsMemory(
                            0,
                            bytesRead),
                        cancellationToken)
                    .ConfigureAwait(false);

                await output.WriteAsync(
                        tag,
                        cancellationToken)
                    .ConfigureAwait(false);

                totalBytes += bytesRead;

                if (chunkNumber == uint.MaxValue)
                {
                    throw new IOException(
                        "Die Funddatei überschreitet "
                        + "das Quarantäneformat.");
                }

                chunkNumber++;
            }

            if (totalBytes != expectedLength)
            {
                throw new IOException(
                    "Die Funddatei hat sich während "
                    + "des Sicherns verändert.");
            }

            var currentInfo =
                new FileInfo(sourcePath);

            currentInfo.Refresh();

            if (currentInfo.Length != expectedLength
                || currentInfo.LastWriteTimeUtc
                != expectedWriteTimeUtc)
            {
                throw new IOException(
                    "Die Funddatei hat sich während "
                    + "des Sicherns verändert.");
            }

            await output.FlushAsync(
                    cancellationToken)
                .ConfigureAwait(false);

            output.Flush(flushToDisk: true);

            string sha256 =
                Convert.ToHexString(
                        hash.GetHashAndReset())
                    .ToLowerInvariant();

            return new EncryptionResult(
                totalBytes,
                sha256);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                plaintext.AsSpan(
                    0,
                    EncryptionChunkSize));

            CryptographicOperations.ZeroMemory(
                ciphertext.AsSpan(
                    0,
                    EncryptionChunkSize));

            ArrayPool<byte>.Shared.Return(
                plaintext);

            ArrayPool<byte>.Shared.Return(
                ciphertext);
        }
    }

    private static async Task WriteMetadataAsync(
        string path,
        QuarantineMetadata metadata,
        CancellationToken cancellationToken)
    {
        var options =
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                BufferSize = 16 * 1024,
                Options =
                    FileOptions.Asynchronous,
                UnixCreateMode =
                    PrivateFileMode
            };

        await using var stream =
            new FileStream(path, options);

        File.SetUnixFileMode(
            path,
            PrivateFileMode);

        await JsonSerializer.SerializeAsync(
                stream,
                metadata,
                MetadataOptions,
                cancellationToken)
            .ConfigureAwait(false);

        await stream.FlushAsync(
                cancellationToken)
            .ConfigureAwait(false);

        stream.Flush(flushToDisk: true);
    }

    private static string
        PrepareQuarantineDirectory()
    {
        string localData =
            Environment.GetFolderPath(
                Environment.SpecialFolder
                    .LocalApplicationData);

        if (string.IsNullOrWhiteSpace(localData)
            || !Path.IsPathFullyQualified(localData))
        {
            throw new IOException(
                "Der lokale Anwendungsordner "
                + "konnte nicht bestimmt werden.");
        }

        string applicationDirectory =
            Path.Combine(
                localData,
                "SpeicherPrüfstation");

        string quarantineDirectory =
            Path.Combine(
                applicationDirectory,
                "Quarantine");

        Directory.CreateDirectory(
            applicationDirectory,
            PrivateDirectoryMode);

        Directory.CreateDirectory(
            quarantineDirectory,
            PrivateDirectoryMode);

        if (new DirectoryInfo(
                    applicationDirectory)
                .LinkTarget is not null
            || new DirectoryInfo(
                    quarantineDirectory)
                .LinkTarget is not null)
        {
            throw new IOException(
                "Der Quarantäneordner darf kein "
                + "symbolischer Link sein.");
        }

        File.SetUnixFileMode(
            applicationDirectory,
            PrivateDirectoryMode);

        File.SetUnixFileMode(
            quarantineDirectory,
            PrivateDirectoryMode);

        return quarantineDirectory;
    }

    private static byte[] LoadOrCreateKey(
        string quarantineDirectory)
    {
        string keyPath =
            Path.Combine(
                quarantineDirectory,
                "quarantine.key");

        byte[] generatedKey =
            RandomNumberGenerator.GetBytes(
                EncryptionKeySize);

        bool createdNewKeyFile = false;

        try
        {
            var options =
                new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    UnixCreateMode =
                        PrivateFileMode
                };

            using var stream =
                new FileStream(
                    keyPath,
                    options);

            createdNewKeyFile = true;

            File.SetUnixFileMode(
                keyPath,
                PrivateFileMode);

            stream.Write(generatedKey);
            stream.Flush(flushToDisk: true);

            return generatedKey;
        }
        catch (IOException)
            when (!createdNewKeyFile
                  && File.Exists(keyPath))
        {
            CryptographicOperations.ZeroMemory(
                generatedKey);

            var keyInfo =
                new FileInfo(keyPath);

            if (keyInfo.LinkTarget is not null
                || keyInfo.Length
                != EncryptionKeySize)
            {
                throw new IOException(
                    "Der vorhandene Quarantäneschlüssel "
                    + "ist ungültig.");
            }

            byte[] key =
                File.ReadAllBytes(keyPath);

            if (key.Length != EncryptionKeySize)
            {
                throw new IOException(
                    "Der vorhandene Quarantäneschlüssel "
                    + "ist unvollständig.");
            }

            File.SetUnixFileMode(
                keyPath,
                PrivateFileMode);

            return key;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(
                generatedKey);

            if (createdNewKeyFile)
            {
                DeleteOwnFile(keyPath);
            }

            throw;
        }
    }

    private static string ResolveSourcePath(
        string mountRoot,
        string relativePath)
    {
        if (!IsSafeRelativePath(relativePath))
        {
            throw new IOException(
                "Der relative Fundpfad ist ungültig.");
        }

        string normalizedRoot =
            Path.GetFullPath(mountRoot)
                .TrimEnd('/')
            + "/";

        string fullPath =
            Path.GetFullPath(
                Path.Combine(
                    mountRoot,
                    relativePath));

        if (!fullPath.StartsWith(
                normalizedRoot,
                StringComparison.Ordinal))
        {
            throw new IOException(
                "Der Fundpfad verlässt das "
                + "eingehängte Volume.");
        }

        string current = mountRoot;

        foreach (string part
                 in relativePath.Split(
                     '/',
                     StringSplitOptions
                         .RemoveEmptyEntries))
        {
            current =
                Path.Combine(current, part);

            FileAttributes attributes =
                File.GetAttributes(current);

            if ((attributes
                 & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException(
                    "Der Fundpfad enthält einen "
                    + "symbolischen Link.");
            }
        }

        FileAttributes finalAttributes =
            File.GetAttributes(fullPath);

        if ((finalAttributes
             & FileAttributes.Directory) != 0)
        {
            throw new IOException(
                "Der Fundpfad verweist nicht "
                + "auf eine Datei.");
        }

        return fullPath;
    }

    private static bool IsSafeRelativePath(
        string path)
    {
        return !string.IsNullOrWhiteSpace(path)
               && !Path.IsPathRooted(path)
               && !path.Any(char.IsControl)
               && path.Split('/').All(
                   part =>
                       part.Length > 0
                       && part is not "."
                       and not "..");
    }

    private static void EnsureFreeSpace(
        string quarantineDirectory,
        long sourceLength)
    {
        string fullDirectory =
            Path.GetFullPath(
                    quarantineDirectory)
                .TrimEnd('/')
            + "/";

        DriveInfo? drive =
            DriveInfo.GetDrives()
                .Where(candidate =>
                    fullDirectory.StartsWith(
                        Path.GetFullPath(
                                candidate
                                    .RootDirectory
                                    .FullName)
                            .TrimEnd('/')
                        + "/",
                        StringComparison.Ordinal))
                .OrderByDescending(candidate =>
                    candidate
                        .RootDirectory
                        .FullName
                        .Length)
                .FirstOrDefault();

        if (drive is null)
        {
            throw new IOException(
                "Das lokale Dateisystem wurde "
                + "nicht erkannt.");
        }

        long chunkCount =
            sourceLength / EncryptionChunkSize;

        if (sourceLength
            % EncryptionChunkSize != 0)
        {
            chunkCount++;
        }

        long requiredSpace =
            checked(
                sourceLength
                + 24
                + chunkCount
                * (4 + AuthenticationTagSize)
                + RequiredFreeSpaceReserve);

        if (drive.AvailableFreeSpace
            < requiredSpace)
        {
            throw new IOException(
                "Für diese Funddatei ist nicht "
                + "genügend lokaler Speicherplatz frei.");
        }
    }

    private static void DeleteOwnFile(
        string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Der ursprüngliche Fehler
            // bleibt maßgeblich.
        }
    }

    private sealed record QuarantineTarget(
        StorageVolume Volume,
        string RelativePath,
        string DisplayPath,
        IReadOnlyList<string> Signatures);

    private sealed record EncryptionResult(
        long SizeBytes,
        string Sha256);

    private sealed record QuarantineMetadata(
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
}
