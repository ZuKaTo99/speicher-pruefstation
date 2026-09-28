using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SpeicherPrüfstation.Desktop.Services;

internal static class QuarantineStorageFileSystem
{
    internal const int EncryptionChunkSize = 1024 * 1024;
    internal const int EncryptionKeySize = 32;
    internal const int AuthenticationTagSize = 16;
    internal const long MaximumMetadataSize = 1024 * 1024;

    internal static readonly byte[] PayloadMagic =
        [(byte)'S', (byte)'P', (byte)'Q', (byte)'1'];

    private static readonly UnixFileMode PrivateFileMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private static readonly UnixFileMode PrivateDirectoryMode =
        UnixFileMode.UserRead
        | UnixFileMode.UserWrite
        | UnixFileMode.UserExecute;

    internal static string ResolveQuarantineDirectory()
    {
        string localData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);

        if (string.IsNullOrWhiteSpace(localData)
            || !Path.IsPathFullyQualified(localData))
        {
            throw new IOException(
                "Der lokale Anwendungsordner konnte nicht bestimmt werden.");
        }

        string applicationDirectory = Path.Combine(
            localData,
            "SpeicherPrüfstation");

        if (Directory.Exists(applicationDirectory))
        {
            EnsurePrivateDirectory(
                applicationDirectory,
                "Anwendungsordner");
        }

        return Path.Combine(
            applicationDirectory,
            "Quarantine");
    }

    internal static void EnsurePrivateDirectory(
        string path,
        string description)
    {
        var info = new DirectoryInfo(path);

        if (!info.Exists)
            throw new IOException(description + " ist nicht vorhanden.");

        if (info.LinkTarget is not null
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(
                description + " darf kein symbolischer Link sein.");
        }

        if (File.GetUnixFileMode(path) != PrivateDirectoryMode)
        {
            throw new IOException(
                description + " besitzt unsichere Dateirechte.");
        }
    }

    internal static void EnsurePrivateFile(
        string path,
        long minimumLength,
        long maximumLength,
        string description)
    {
        var info = new FileInfo(path);

        if (!info.Exists)
            throw new IOException(description + " fehlt.");

        if (info.LinkTarget is not null
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(
                description + " darf kein symbolischer Link sein.");
        }

        if (info.Length < minimumLength
            || info.Length > maximumLength)
        {
            throw new IOException(
                description + " besitzt eine unerwartete Dateigröße.");
        }

        if (File.GetUnixFileMode(path) != PrivateFileMode)
        {
            throw new IOException(
                description + " besitzt unsichere Dateirechte.");
        }
    }

    internal static string ResolveOwnedFilePath(
        string quarantineDirectory,
        string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)
            || fileName != Path.GetFileName(fileName)
            || fileName.Any(char.IsControl))
        {
            throw new IOException(
                "Der Dateiname des Quarantäneeintrags ist ungültig.");
        }

        string normalizedDirectory =
            Path.GetFullPath(quarantineDirectory).TrimEnd('/') + "/";

        string fullPath = Path.GetFullPath(
            Path.Combine(quarantineDirectory, fileName));

        if (!fullPath.StartsWith(
                normalizedDirectory,
                StringComparison.Ordinal))
        {
            throw new IOException(
                "Der Quarantänepfad verlässt den privaten Speicherordner.");
        }

        return fullPath;
    }

    internal static QuarantineFileSnapshot CaptureFileSnapshot(
        string path)
    {
        var info = new FileInfo(path);
        info.Refresh();

        if (!info.Exists)
            throw new IOException("Die zu prüfende Datei fehlt.");

        return new QuarantineFileSnapshot(
            info.Length,
            info.LastWriteTimeUtc);
    }

    internal static void EnsureUnchanged(
        string path,
        QuarantineFileSnapshot expected,
        string message)
    {
        var info = new FileInfo(path);
        info.Refresh();

        if (!info.Exists
            || info.LinkTarget is not null
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0
            || info.Length != expected.Length
            || info.LastWriteTimeUtc != expected.LastWriteTimeUtc
            || File.GetUnixFileMode(path) != PrivateFileMode)
        {
            throw new IOException(message);
        }
    }

    internal static long CalculateDirectorySize(
        string quarantineDirectory,
        ICollection<string> technicalProblems)
    {
        if (!Directory.Exists(quarantineDirectory))
            return 0;

        long total = 0;

        foreach (string path in Directory.GetFileSystemEntries(
                     quarantineDirectory,
                     "*",
                     SearchOption.TopDirectoryOnly))
        {
            try
            {
                var info = new FileInfo(path);

                if (info.LinkTarget is not null
                    || Directory.Exists(path)
                    || (File.GetAttributes(path)
                        & FileAttributes.ReparsePoint) != 0)
                {
                    continue;
                }

                total = checked(total + info.Length);
            }
            catch (Exception exception)
            {
                technicalProblems.Add(
                    "Die Speicherbelegung konnte für "
                    + Path.GetFileName(path)
                    + " nicht bestimmt werden: "
                    + exception.Message);
            }
        }

        return total;
    }

    internal static long CalculatePayloadLength(long originalSize)
    {
        if (originalSize < 0)
        {
            throw new IOException(
                "Die gespeicherte Originalgröße ist ungültig.");
        }

        long chunkCount = originalSize / EncryptionChunkSize;

        if (originalSize % EncryptionChunkSize != 0)
            chunkCount++;

        return checked(
            24
            + originalSize
            + chunkCount * (4 + AuthenticationTagSize));
    }

    internal static bool TryNormalizeEntryId(
        string? value,
        out string entryId)
    {
        entryId = string.Empty;

        if (!Guid.TryParseExact(value, "N", out Guid parsed))
            return false;

        entryId = parsed.ToString("N");
        return value == entryId;
    }

    internal static bool TryGetEntryIdFromMetadataName(
        string fileName,
        out string entryId)
    {
        const string suffix = ".json";
        entryId = string.Empty;

        return fileName.EndsWith(suffix, StringComparison.Ordinal)
               && TryNormalizeEntryId(
                   fileName[..^suffix.Length],
                   out entryId);
    }

    internal static bool TryGetEntryIdFromPayloadName(
        string fileName,
        out string entryId)
    {
        const string suffix = ".quarantine";
        entryId = string.Empty;

        return fileName.EndsWith(suffix, StringComparison.Ordinal)
               && TryNormalizeEntryId(
                   fileName[..^suffix.Length],
                   out entryId);
    }

    internal static bool IsSha256(string? value)
    {
        return value is not null
               && value.Length == 64
               && value.All(character =>
                   character is >= '0' and <= '9'
                   or >= 'a' and <= 'f');
    }

    internal static bool IsSafeRelativePath(string? path)
    {
        return !string.IsNullOrWhiteSpace(path)
               && !Path.IsPathRooted(path)
               && !path.Any(char.IsControl)
               && path.Split('/').All(part =>
                   part.Length > 0
                   && part is not "." and not "..");
    }
}
