using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

internal static class LinuxQuarantineEntryVerifier
{
    private const int EncryptionChunkSize = 1024 * 1024;
    private const int EncryptionKeySize = 32;
    private const int AuthenticationTagSize = 16;
    private const long MaximumMetadataSize = 1024 * 1024;

    private static readonly byte[] PayloadMagic = [(byte)'S', (byte)'P', (byte)'Q', (byte)'1'];

    private static readonly UnixFileMode PrivateFileMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private static readonly UnixFileMode PrivateDirectoryMode =
        UnixFileMode.UserRead
        | UnixFileMode.UserWrite
        | UnixFileMode.UserExecute;

    internal static async Task VerifyAsync(
        StorageDevice device,
        StorageVolume volume,
        string relativePath,
        QuarantineItemResult item,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(volume);
        ArgumentNullException.ThrowIfNull(item);

        if (!Guid.TryParseExact(item.EntryId, "N", out Guid entryId)
            || entryId.ToString("N") != item.EntryId)
        {
            throw new IOException("Die Kennung des Quarantäneeintrags ist ungültig.");
        }

        if (item.SizeBytes < 0 || !IsSha256(item.Sha256))
            throw new IOException("Die Prüfdaten des Quarantäneeintrags sind ungültig.");

        if (!IsSafeRelativePath(relativePath)
            || item.OriginalFilePath != volume.DevicePath + ":/" + relativePath)
        {
            throw new IOException("Der Originalpfad des Quarantäneeintrags ist ungültig.");
        }

        string quarantineDirectory = ResolveQuarantineDirectory();
        string keyPath = Path.Combine(quarantineDirectory, "quarantine.key");
        string metadataPath = Path.Combine(quarantineDirectory, item.EntryId + ".json");
        string payloadPath = Path.Combine(quarantineDirectory, item.EntryId + ".quarantine");

        EnsurePrivateFile(keyPath, EncryptionKeySize, EncryptionKeySize, "Quarantäneschlüssel");
        EnsurePrivateFile(metadataPath, 1, MaximumMetadataSize, "Quarantänemetadaten");

        QuarantineMetadata metadata = await ReadMetadataAsync(
                metadataPath,
                cancellationToken)
            .ConfigureAwait(false);

        ValidateMetadata(device, volume, relativePath, item, metadata);

        long expectedPayloadLength = CalculatePayloadLength(item.SizeBytes);
        EnsurePrivateFile(
            payloadPath,
            expectedPayloadLength,
            expectedPayloadLength,
            "Quarantänedatei");

        byte[] key = await File.ReadAllBytesAsync(keyPath, cancellationToken)
            .ConfigureAwait(false);

        try
        {
            if (key.Length != EncryptionKeySize)
                throw new IOException("Der Quarantäneschlüssel ist unvollständig.");

            await VerifyPayloadAsync(
                    payloadPath,
                    entryId,
                    item.SizeBytes,
                    item.Sha256,
                    key,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static string ResolveQuarantineDirectory()
    {
        string localData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);

        if (string.IsNullOrWhiteSpace(localData)
            || !Path.IsPathFullyQualified(localData))
        {
            throw new IOException("Der lokale Anwendungsordner konnte nicht bestimmt werden.");
        }

        string applicationDirectory = Path.Combine(localData, "SpeicherPrüfstation");
        string quarantineDirectory = Path.Combine(applicationDirectory, "Quarantine");

        EnsurePrivateDirectory(applicationDirectory, "Anwendungsordner");
        EnsurePrivateDirectory(quarantineDirectory, "Quarantäneordner");

        return quarantineDirectory;
    }

    private static void EnsurePrivateDirectory(string path, string description)
    {
        var info = new DirectoryInfo(path);
        if (!info.Exists || info.LinkTarget is not null
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException($"Der {description} fehlt oder ist nicht vertrauenswürdig.");
        }

        if (File.GetUnixFileMode(path) != PrivateDirectoryMode)
            throw new IOException($"Der {description} besitzt keine privaten Zugriffsrechte.");
    }

    private static void EnsurePrivateFile(
        string path,
        long minimumLength,
        long maximumLength,
        string description)
    {
        var info = new FileInfo(path);
        info.Refresh();

        if (!info.Exists || info.LinkTarget is not null
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException($"Die {description} fehlt oder ist nicht vertrauenswürdig.");
        }

        if (info.Length < minimumLength || info.Length > maximumLength)
            throw new IOException($"Die {description} besitzt eine unerwartete Größe.");

        if (File.GetUnixFileMode(path) != PrivateFileMode)
            throw new IOException($"Die {description} besitzt keine privaten Zugriffsrechte.");
    }

    private static async Task<QuarantineMetadata> ReadMetadataAsync(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        QuarantineMetadata? metadata;
        try
        {
            metadata = await JsonSerializer.DeserializeAsync<QuarantineMetadata>(
                    stream,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch (JsonException exception)
        {
            throw new IOException("Die Quarantänemetadaten sind nicht lesbar.", exception);
        }

        return metadata
               ?? throw new IOException("Die Quarantänemetadaten sind leer.");
    }

    private static void ValidateMetadata(
        StorageDevice device,
        StorageVolume volume,
        string relativePath,
        QuarantineItemResult item,
        QuarantineMetadata metadata)
    {
        if (metadata.FormatVersion != 1
            || metadata.EntryId != item.EntryId
            || metadata.SourceDevicePath != device.DevicePath
            || metadata.SourceKernelName != device.Name
            || metadata.SourceModel != device.Model
            || metadata.SourceVendor != device.Vendor
            || metadata.SourceDeviceSizeBytes != device.SizeBytes
            || metadata.SourceDiskSequence != device.DiskSequence
            || metadata.SourceVolumePath != volume.DevicePath
            || metadata.OriginalRelativePath != relativePath
            || metadata.OriginalDisplayPath != item.OriginalFilePath
            || metadata.SizeBytes != item.SizeBytes
            || metadata.Sha256 != item.Sha256
            || metadata.PayloadFileName != item.EntryId + ".quarantine"
            || metadata.Signatures is null
            || !metadata.Signatures.SequenceEqual(item.Signatures, StringComparer.Ordinal))
        {
            throw new IOException(
                "Der Quarantäneeintrag gehört nicht eindeutig zur ausgewählten Funddatei.");
        }
    }

    private static long CalculatePayloadLength(long plaintextLength)
    {
        long chunkCount = plaintextLength == 0
            ? 0
            : checked((plaintextLength - 1) / EncryptionChunkSize + 1);

        return checked(
            24L
            + plaintextLength
            + chunkCount * (4L + AuthenticationTagSize));
    }

    private static async Task VerifyPayloadAsync(
        string path,
        Guid entryId,
        long expectedLength,
        string expectedSha256,
        byte[] key,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        byte[] header = new byte[24];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);

        if (!header.AsSpan(0, 4).SequenceEqual(PayloadMagic)
            || BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(4, 4))
            != EncryptionChunkSize
            || BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(8, 8))
            != expectedLength)
        {
            throw new IOException("Der Kopf der Quarantänedatei ist ungültig.");
        }

        byte[] noncePrefix = header.AsSpan(16, 8).ToArray();
        byte[] plaintext = ArrayPool<byte>.Shared.Rent(EncryptionChunkSize);
        byte[] ciphertext = ArrayPool<byte>.Shared.Rent(EncryptionChunkSize);
        byte[] tag = new byte[AuthenticationTagSize];
        byte[] nonce = new byte[12];
        byte[] lengthBuffer = new byte[4];
        byte[] additionalData = new byte[24];
        byte[] trailing = new byte[1];

        entryId.TryWriteBytes(additionalData.AsSpan(0, 16));

        long totalBytes = 0;
        uint chunkNumber = 0;

        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var aes = new AesGcm(key, AuthenticationTagSize);

            while (totalBytes < expectedLength)
            {
                cancellationToken.ThrowIfCancellationRequested();

                await stream.ReadExactlyAsync(lengthBuffer, cancellationToken)
                    .ConfigureAwait(false);

                int chunkLength = BinaryPrimitives.ReadInt32LittleEndian(lengthBuffer);
                int expectedChunkLength = (int)Math.Min(
                    EncryptionChunkSize,
                    expectedLength - totalBytes);

                if (chunkLength != expectedChunkLength || chunkLength <= 0)
                    throw new IOException("Die Blocklänge der Quarantänedatei ist ungültig.");

                await stream.ReadExactlyAsync(
                        ciphertext.AsMemory(0, chunkLength),
                        cancellationToken)
                    .ConfigureAwait(false);

                await stream.ReadExactlyAsync(tag, cancellationToken).ConfigureAwait(false);

                noncePrefix.CopyTo(nonce, 0);
                BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(8, 4), chunkNumber);
                BinaryPrimitives.WriteUInt32BigEndian(
                    additionalData.AsSpan(16, 4),
                    chunkNumber);
                BinaryPrimitives.WriteInt32BigEndian(
                    additionalData.AsSpan(20, 4),
                    chunkLength);

                try
                {
                    aes.Decrypt(
                        nonce,
                        ciphertext.AsSpan(0, chunkLength),
                        tag,
                        plaintext.AsSpan(0, chunkLength),
                        additionalData);
                }
                catch (CryptographicException exception)
                {
                    throw new IOException(
                        "Die Quarantänedatei hat die Echtheitsprüfung nicht bestanden.",
                        exception);
                }

                hash.AppendData(plaintext.AsSpan(0, chunkLength));
                CryptographicOperations.ZeroMemory(plaintext.AsSpan(0, chunkLength));

                totalBytes += chunkLength;
                if (chunkNumber == uint.MaxValue && totalBytes < expectedLength)
                    throw new IOException("Die Quarantänedatei enthält zu viele Blöcke.");

                chunkNumber++;
            }

            if (await stream.ReadAsync(trailing, cancellationToken).ConfigureAwait(false) != 0)
                throw new IOException("Die Quarantänedatei enthält unerwartete Zusatzdaten.");

            string actualSha256 = Convert.ToHexString(hash.GetHashAndReset())
                .ToLowerInvariant();

            if (actualSha256 != expectedSha256)
                throw new IOException(
                    "Die Quarantänedatei stimmt nicht mit ihrer Prüfsumme überein.");
        }
        catch (EndOfStreamException exception)
        {
            throw new IOException("Die Quarantänedatei ist unvollständig.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext.AsSpan(0, EncryptionChunkSize));
            CryptographicOperations.ZeroMemory(ciphertext.AsSpan(0, EncryptionChunkSize));
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(additionalData);

            ArrayPool<byte>.Shared.Return(plaintext);
            ArrayPool<byte>.Shared.Return(ciphertext);
        }
    }

    private static bool IsSha256(string value) =>
        value.Length == 64
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsSafeRelativePath(string path) =>
        !string.IsNullOrWhiteSpace(path)
        && !Path.IsPathRooted(path)
        && !path.Any(char.IsControl)
        && path.Split('/').All(part => part.Length > 0 && part is not "." and not "..");

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
