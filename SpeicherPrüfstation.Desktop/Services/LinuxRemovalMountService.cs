using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

internal sealed class RemovalMountLease(StorageDevice device, StorageVolume volume)
{
    internal StorageDevice Device { get; } = device;
    internal StorageVolume Volume { get; } = volume;
    internal bool Created { get; set; }
    internal string? Target { get; set; }
    internal long? MountId { get; set; }
    internal string? MountedDeviceNumber { get; set; }
}

internal sealed class LinuxRemovalMountService(IStorageDeviceService storageDeviceService)
{
    private readonly LinuxScanMountService _selectionValidator =
        new(storageDeviceService);

    private readonly List<RemovalMountLease> _leases = [];

    internal bool HasPendingMounts => _leases.Count > 0;

    internal async Task<StorageDevice> ValidateSelectionAsync(
        StorageDevice expected,
        CancellationToken cancellationToken)
    {
        StorageDevice current = await _selectionValidator
            .ValidateSelectionAsync(expected, cancellationToken)
            .ConfigureAwait(false);

        if (current.IsReadOnly)
            throw new IOException("Das ausgewählte USB-Gerät ist schreibgeschützt.");

        return current;
    }

    internal async Task<RemovalMountLease> MountAsync(
        StorageDevice expected,
        StorageVolume expectedVolume,
        CancellationToken cancellationToken)
    {
        StorageDevice current = await ValidateSelectionAsync(expected, cancellationToken)
            .ConfigureAwait(false);

        StorageVolume volume = current.Volumes.SingleOrDefault(
            candidate => candidate.DevicePath == expectedVolume.DevicePath)
            ?? throw new IOException("Das zu löschende Volume wurde nicht wiedergefunden.");

        if (volume.IsReadOnly)
            throw new IOException($"{volume.DevicePath} ist schreibgeschützt.");

        var options = WritableMountOptions(volume)
            ?? throw new IOException(
                "Dieses Dateisystem ist für das kontrollierte Löschen nicht freigegeben.");

        if (options.Driver == "ntfs" && !File.Exists("/usr/bin/ntfs-3g"))
            throw new IOException("Für das kontrollierte Löschen auf NTFS wird ntfs-3g benötigt.");

        cancellationToken.ThrowIfCancellationRequested();
        LinuxScanMountService.EnsureIdentity(current);

        var lease = new RemovalMountLease(current, volume);
        _leases.Add(lease);

        LinuxCommandOutput output = await LinuxProcessRunner.RunAsync(
                "/usr/bin/udisksctl",
                [
                    "mount", "--block-device", volume.DevicePath,
                    "--filesystem-type", options.Driver,
                    "--options", options.Options
                ],
                CancellationToken.None)
            .ConfigureAwait(false);

        if (output.ExitCode != 0)
        {
            throw new IOException(
                $"{volume.DevicePath} konnte nicht kontrolliert beschreibbar eingehängt werden: "
                + Details(output));
        }

        lease.Created = true;

        IReadOnlyList<ScanMountEntry> mounts = await ReadMountsAsync(CancellationToken.None)
            .ConfigureAwait(false);

        ScanMountEntry[] matching = mounts.Where(
            mount => BaseSource(mount.Source) == volume.DevicePath).ToArray();

        if (matching.Length != 1 || matching[0].Source != volume.DevicePath)
            throw new IOException("Die erzeugte Einhängung ist nicht eindeutig.");

        ScanMountEntry entry = matching[0];
        lease.Target = entry.Target;
        lease.MountId = entry.Id;
        lease.MountedDeviceNumber = entry.DeviceNumber;

        string response = output.StandardOutput.TrimEnd('\r', '\n');
        string expectedResponse = $"Mounted {volume.DevicePath} at {entry.Target}";

        if (entry.Target.Any(char.IsControl)
            || (!string.Equals(response, expectedResponse, StringComparison.Ordinal)
                && !string.Equals(response, expectedResponse + ".", StringComparison.Ordinal)))
        {
            throw new IOException(
                "UDisks-Meldung und Mounttabelle stimmen beim Mountpfad nicht überein.");
        }

        await EnsureWritableMountAsync(lease, CancellationToken.None).ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(output.StandardError))
        {
            throw new IOException(
                "UDisks meldet ein Problem beim beschreibbaren Einhängen: "
                + output.StandardError.Trim());
        }

        cancellationToken.ThrowIfCancellationRequested();
        return lease;
    }

    internal async Task EnsureWritableMountAsync(
        RemovalMountLease lease,
        CancellationToken cancellationToken)
    {
        LinuxScanMountService.EnsureIdentity(lease.Device);

        IReadOnlyList<ScanMountEntry> mounts = await ReadMountsAsync(cancellationToken)
            .ConfigureAwait(false);

        ScanMountEntry[] matching = mounts.Where(
            mount => BaseSource(mount.Source) == lease.Volume.DevicePath).ToArray();

        if (matching.Length != 1
            || matching[0].Source != lease.Volume.DevicePath
            || matching[0].Target != lease.Target)
        {
            throw new IOException("Mountquelle oder Mountpfad ist nicht mehr eindeutig.");
        }

        ScanMountEntry entry = matching[0];
        if (lease.MountId.HasValue
            && (entry.Id != lease.MountId.Value
                || entry.DeviceNumber != lease.MountedDeviceNumber))
        {
            throw new IOException("Die Einhängung wurde während des Löschens ausgetauscht.");
        }

        lease.MountId = entry.Id;
        lease.MountedDeviceNumber = entry.DeviceNumber;

        if (!entry.Target.StartsWith("/run/media/", StringComparison.Ordinal)
            || Path.GetFullPath(entry.Target) != entry.Target
            || !Directory.Exists(entry.Target))
        {
            throw new IOException("Unerwarteter Mountpfad. Das Löschen wird nicht fortgesetzt.");
        }

        for (DirectoryInfo? part = new(entry.Target); part is not null; part = part.Parent)
        {
            if (part.LinkTarget is not null)
                throw new IOException("Der Mountpfad enthält einen symbolischen Link.");
        }

        var vfs = entry.VfsOptions.Split(',').ToHashSet(StringComparer.Ordinal);
        var fs = entry.FsOptions.Split(',').ToHashSet(StringComparer.Ordinal);

        if (!new[] { "rw", "nodev", "nosuid", "noexec" }.All(vfs.Contains)
            || vfs.Contains("ro") || fs.Contains("ro"))
        {
            throw new IOException(
                "Der Mount besitzt nicht alle verlangten Schutz- und Schreiboptionen.");
        }

        if (mounts.Any(mount => mount.Id != entry.Id
            && (mount.Target == entry.Target
                || LinuxScanMountService.IsBelow(mount.Target, entry.Target))))
        {
            throw new IOException("Unter dem Löschpfad liegt eine weitere Einhängung.");
        }

        string? expectedFs = lease.Volume.FileSystem?.ToLowerInvariant();
        bool matchingFs = expectedFs == "ntfs"
            ? entry.FileSystem == "fuseblk"
            : entry.FileSystem == expectedFs;

        if (!matchingFs)
            throw new IOException("Der Dateisystemtreiber entspricht nicht dem erwarteten Volume.");

        LinuxScanMountService.EnsureIdentity(lease.Device);
    }

    internal async Task FlushAsync(RemovalMountLease lease)
    {
        await EnsureWritableMountAsync(lease, CancellationToken.None).ConfigureAwait(false);

        LinuxCommandOutput output = await LinuxProcessRunner.RunAsync(
                "/usr/bin/sync",
                ["--file-system", lease.Target!],
                CancellationToken.None)
            .ConfigureAwait(false);

        if (output.ExitCode != 0 || !string.IsNullOrWhiteSpace(output.StandardError))
            throw new IOException("Die Löschungen konnten nicht sicher synchronisiert werden. "
                                  + Details(output));

        await EnsureWritableMountAsync(lease, CancellationToken.None).ConfigureAwait(false);
    }

    internal async Task<IReadOnlyList<string>> CleanupAsync(bool interactive)
    {
        var warnings = new List<string>();

        foreach (RemovalMountLease lease in _leases.ToArray().Reverse())
        {
            try
            {
                IReadOnlyList<ScanMountEntry> mounts =
                    await ReadMountsAsync(CancellationToken.None).ConfigureAwait(false);

                ScanMountEntry[] matches = mounts.Where(
                    mount => BaseSource(mount.Source) == lease.Volume.DevicePath).ToArray();

                if (matches.Length == 0)
                {
                    _leases.Remove(lease);
                    continue;
                }

                if (!lease.Created || matches.Length != 1
                    || matches[0].Source != lease.Volume.DevicePath
                    || (lease.MountId.HasValue && matches[0].Id != lease.MountId.Value)
                    || (lease.MountedDeviceNumber is not null
                        && matches[0].DeviceNumber != lease.MountedDeviceNumber)
                    || (lease.Target is not null && matches[0].Target != lease.Target))
                {
                    throw new IOException("Die Eigentümerschaft der Einhängung ist nicht eindeutig.");
                }

                LinuxScanMountService.EnsureIdentity(lease.Device);
                ScanMountEntry entry = matches[0];

                if (mounts.Any(mount => mount.Id != entry.Id
                    && (mount.Target == entry.Target
                        || LinuxScanMountService.IsBelow(mount.Target, entry.Target))))
                {
                    throw new IOException("Eine weitere Einhängung blockiert das sichere Aushängen.");
                }

                var arguments = new List<string>
                {
                    "unmount", "--block-device", lease.Volume.DevicePath
                };

                if (!interactive)
                    arguments.Add("--no-user-interaction");

                LinuxCommandOutput output = await LinuxProcessRunner.RunAsync(
                        "/usr/bin/udisksctl",
                        arguments,
                        CancellationToken.None)
                    .ConfigureAwait(false);

                IReadOnlyList<ScanMountEntry> after =
                    await ReadMountsAsync(CancellationToken.None).ConfigureAwait(false);

                if (after.Any(mount => mount.Id == entry.Id
                    || BaseSource(mount.Source) == lease.Volume.DevicePath))
                {
                    throw new IOException("Die Einhängung besteht weiterhin. " + Details(output));
                }

                _leases.Remove(lease);

                if (output.ExitCode != 0 || !string.IsNullOrWhiteSpace(output.StandardError))
                {
                    warnings.Add(
                        $"{lease.Volume.DevicePath} ist ausgehängt, UDisks meldete dabei jedoch: "
                        + Details(output));
                }
            }
            catch (Exception exception)
            {
                warnings.Add(
                    $"{lease.Volume.DevicePath}: Aushängen nicht bestätigt. "
                    + exception.Message
                    + " Dateimanager und andere Zugriffe schließen; anschließend "
                    + "‚Aushängen erneut versuchen‘ wählen.");
            }
        }

        return warnings;
    }

    private static (string Driver, string Options)? WritableMountOptions(StorageVolume volume)
    {
        const string safe = "rw,nodev,nosuid,noexec";

        return volume.FileSystem?.ToLowerInvariant() switch
        {
            "vfat" => ("vfat", safe),
            "exfat" => ("exfat", safe),
            "ntfs" => ("ntfs", safe),
            "ext2" => ("ext2", safe),
            "ext3" => ("ext3", safe),
            "ext4" => ("ext4", safe),
            _ => null
        };
    }

    private static string BaseSource(string source)
    {
        int bracket = source.IndexOf('[');
        return bracket < 0 ? source : source[..bracket];
    }

    private static string Details(LinuxCommandOutput output) =>
        (output.StandardError + " " + output.StandardOutput).Trim() is { Length: > 0 } text
            ? text
            : $"Exit-Code {output.ExitCode}";

    private static async Task<IReadOnlyList<ScanMountEntry>> ReadMountsAsync(
        CancellationToken cancellationToken)
    {
        LinuxCommandOutput output = await LinuxProcessRunner.RunAsync(
                "/usr/bin/findmnt",
                [
                    "--kernel", "--all", "--list", "--json", "--output",
                    "ID,SOURCE,TARGET,MAJ:MIN,VFS-OPTIONS,FS-OPTIONS,FSTYPE"
                ],
                cancellationToken)
            .ConfigureAwait(false);

        if (output.ExitCode != 0 || !string.IsNullOrWhiteSpace(output.StandardError))
        {
            throw new IOException(
                "Die Mounttabelle konnte nicht zuverlässig gelesen werden. "
                + Details(output));
        }

        using JsonDocument document = JsonDocument.Parse(output.StandardOutput);
        var result = new List<ScanMountEntry>();

        foreach (JsonElement row in document.RootElement
                     .GetProperty("filesystems").EnumerateArray())
        {
            if (!long.TryParse(
                    Text(row, "id"),
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out long id)
                || id <= 0)
            {
                throw new IOException("Eine Mount-ID fehlt in der findmnt-Ausgabe.");
            }

            result.Add(new ScanMountEntry(
                id,
                Text(row, "source"),
                Text(row, "target"),
                Text(row, "maj:min"),
                Text(row, "vfs-options"),
                Text(row, "fs-options"),
                Text(row, "fstype")));
        }

        return result;
    }

    private static string Text(JsonElement row, string name)
    {
        if (!row.TryGetProperty(name, out JsonElement value)
            || value.ValueKind == JsonValueKind.Null)
        {
            return string.Empty;
        }

        return value.ValueKind == JsonValueKind.String
            ? value.GetString()!
            : value.ToString();
    }
}
