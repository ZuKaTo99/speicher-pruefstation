using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

internal sealed class ScanMountLease(StorageDevice device, StorageVolume volume)
{
    internal StorageDevice Device { get; } = device;
    internal StorageVolume Volume { get; } = volume;
    internal bool Created { get; set; }
    internal string? Target { get; set; }
    internal long? MountId { get; set; }
    internal string? MountedDeviceNumber { get; set; }
}

internal sealed record ScanMountEntry(
    long Id, string Source, string Target, string DeviceNumber,
    string VfsOptions, string FsOptions, string FileSystem);

internal sealed class LinuxScanMountService(IStorageDeviceService storageDeviceService)
{
    private readonly List<ScanMountLease> _leases = [];
    internal bool HasPendingMounts => _leases.Count > 0;

    internal async Task<StorageDevice> ValidateSelectionAsync(
        StorageDevice expected, CancellationToken cancellationToken)
    {
        if (!Regex.IsMatch(expected.DevicePath, @"^/dev/sd[a-z]+$",
                RegexOptions.CultureInvariant)
            || expected.DevicePath != "/dev/" + expected.Name
            || !string.Equals(expected.Transport, "usb", StringComparison.OrdinalIgnoreCase)
            || !expected.DiskSequence.HasValue || expected.SizeBytes <= 0)
        {
            throw new IOException(
                "Das Gerät ist kein eindeutig erkanntes USB-Blockgerät. "
                + "Bitte Geräte aktualisieren und erneut auswählen.");
        }

        IReadOnlyList<StorageDevice> devices = await storageDeviceService
            .GetUsbStorageDevicesAsync(cancellationToken).ConfigureAwait(false);
        StorageDevice? current = devices.SingleOrDefault(
            value => value.DevicePath == expected.DevicePath);

        if (current is null || current.DiskSequence != expected.DiskSequence
            || current.Name != expected.Name || current.SizeBytes != expected.SizeBytes
            || current.Model != expected.Model || current.Vendor != expected.Vendor
            || !string.Equals(current.Transport, "usb", StringComparison.OrdinalIgnoreCase)
            || !SameVolumes(expected.Volumes, current.Volumes))
        {
            throw new IOException(
                "Das ausgewählte Gerät oder seine Partitionen haben sich geändert. "
                + "Bitte Geräte aktualisieren.");
        }

        EnsureIdentity(current);
        if (current.Volumes.Count == 0)
            throw new IOException("Das Gerät enthält kein erkanntes Volume zum Scannen.");

        foreach (StorageVolume volume in current.Volumes)
        {
            bool wholeDisk = volume.DevicePath == current.DevicePath
                             && volume.NodeType == "disk";
            bool directPartition = volume.NodeType == "part"
                && Regex.IsMatch(volume.DevicePath,
                    "^" + Regex.Escape(current.DevicePath) + @"[1-9][0-9]*$",
                    RegexOptions.CultureInvariant);

            if (!wholeDisk && !directPartition)
                throw new IOException("LVM, RAID und verschachtelte Geräte werden noch nicht gescannt.");
            if (volume.IsMounted)
                throw new IOException($"{volume.DevicePath} ist bereits eingehängt. "
                    + "Bitte zuerst regulär aushängen und Geräte aktualisieren.");
            if (volume.Label?.Any(char.IsControl) == true)
                throw new IOException("Eine Volumebezeichnung enthält nicht unterstützte Steuerzeichen.");

            string kernelName = Path.GetFileName(volume.DevicePath);
            string diskDirectory = ResolveBlockDirectory(current.Name);
            string volumeDirectory = ResolveBlockDirectory(kernelName);
            if (directPartition && Path.GetDirectoryName(volumeDirectory) != diskDirectory)
                throw new IOException("Die Partition gehört nicht eindeutig zum ausgewählten Gerät.");

            EnsureNoHolders(kernelName);
        }

        EnsureNoHolders(current.Name);
        HashSet<string> paths = DevicePaths(current);
        if (File.ReadLines("/proc/swaps").Skip(1).Any(line =>
                paths.Contains(line.Split((char[]?)null,
                    StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "")))
        {
            throw new IOException("Das Gerät wird als Auslagerungsspeicher verwendet.");
        }

        IReadOnlyList<ScanMountEntry> mounts = await ReadMountsAsync(cancellationToken)
            .ConfigureAwait(false);
        if (mounts.Any(mount => paths.Contains(BaseSource(mount.Source))))
            throw new IOException("Mindestens ein Bereich des Geräts ist bereits eingehängt.");

        await EnsureNoFstabEntryAsync(current, cancellationToken).ConfigureAwait(false);
        return current;
    }

    internal static (string Driver, string Options)? MountOptions(StorageVolume volume)
    {
        const string safe = "ro,nodev,nosuid,noexec";
        return volume.FileSystem?.ToLowerInvariant() switch
        {
            "vfat" => ("vfat", safe),
            "exfat" => ("exfat", safe),
            "ntfs" => ("ntfs", safe + ",norecover"),
            "ext2" => ("ext2", safe),
            "ext3" => ("ext3", safe + ",noload"),
            "ext4" => ("ext4", safe + ",noload"),
            _ => null
        };
    }

    internal async Task<ScanMountLease> MountAsync(
        StorageDevice expected, StorageVolume volume, CancellationToken cancellationToken)
    {
        StorageDevice current = await ValidateSelectionAsync(expected, cancellationToken)
            .ConfigureAwait(false);
        var options = MountOptions(volume)
            ?? throw new IOException("Dieses Dateisystem ist für den Lesescan noch nicht freigegeben.");

        if (options.Driver == "ntfs" && !File.Exists("/usr/bin/ntfs-3g"))
            throw new IOException("Für den NTFS-Lesescan mit norecover wird ntfs-3g benötigt.");

        cancellationToken.ThrowIfCancellationRequested();
        EnsureIdentity(current);
        var lease = new ScanMountLease(current, volume);
        _leases.Add(lease);

        // Einen laufenden UDisks-Auftrag nicht durch Töten des Clients verlassen:
        // Der Systemdienst könnte danach noch mounten. Abbruch erst nach Rückkehr.
        LinuxCommandOutput output = await LinuxProcessRunner.RunAsync(
            "/usr/bin/udisksctl",
            ["mount", "--block-device", volume.DevicePath,
             "--filesystem-type", options.Driver, "--options", options.Options],
            CancellationToken.None).ConfigureAwait(false);

        if (output.ExitCode != 0)
            throw new IOException($"{volume.DevicePath} konnte nicht lesend eingehängt werden: "
                + Details(output));

        lease.Created = true;

        // Den tatsächlichen Pfad aus der Kernel-Mounttabelle übernehmen.
        // Satzzeichen in der UDisks-Meldung dürfen den Pfad nicht verändern.
        IReadOnlyList<ScanMountEntry> mounts = await ReadMountsAsync(CancellationToken.None)
            .ConfigureAwait(false);
        ScanMountEntry[] matching = mounts.Where(
            mount => BaseSource(mount.Source) == volume.DevicePath).ToArray();

        if (matching.Length != 1 || matching[0].Source != volume.DevicePath)
            throw new IOException(
                "Die erzeugte Einhängung ist in der Mounttabelle nicht eindeutig.");

        ScanMountEntry entry = matching[0];
        lease.Target = entry.Target;
        lease.MountId = entry.Id;
        lease.MountedDeviceNumber = entry.DeviceNumber;

        // UDisks-Versionen geben die Erfolgsmeldung mit oder ohne Schlusspunkt aus.
        // Nur Zeilenenden entfernen: Leerzeichen und Punkte können zum Pfad gehören.
        string response = output.StandardOutput.TrimEnd('\r', '\n');
        string expectedResponse = $"Mounted {volume.DevicePath} at {entry.Target}";
        if (entry.Target.Any(char.IsControl)
            || (!string.Equals(response, expectedResponse, StringComparison.Ordinal)
                && !string.Equals(response, expectedResponse + ".", StringComparison.Ordinal)))
        {
            throw new IOException(
                "UDisks-Meldung und Mounttabelle stimmen beim Mountpfad nicht überein.");
        }

        // Noch ohne Benutzer-Token: Die gerade erzeugte Einhängung erfassen.
        await EnsureSafeMountAsync(lease, CancellationToken.None).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(output.StandardError))
            throw new IOException("UDisks meldet ein Problem beim Einhängen: "
                + output.StandardError.Trim());
        cancellationToken.ThrowIfCancellationRequested();
        return lease;
    }

    internal async Task EnsureSafeMountAsync(
        ScanMountLease lease, CancellationToken cancellationToken)
    {
        EnsureIdentity(lease.Device);
        IReadOnlyList<ScanMountEntry> mounts = await ReadMountsAsync(cancellationToken)
            .ConfigureAwait(false);
        ScanMountEntry[] matching = mounts.Where(
            mount => BaseSource(mount.Source) == lease.Volume.DevicePath).ToArray();

        if (matching.Length != 1 || matching[0].Source != lease.Volume.DevicePath
            || matching[0].Target != lease.Target)
            throw new IOException("Mountquelle oder Mountpfad ist nicht mehr eindeutig.");

        ScanMountEntry entry = matching[0];
        if (lease.MountId.HasValue && (entry.Id != lease.MountId.Value
            || entry.DeviceNumber != lease.MountedDeviceNumber))
            throw new IOException("Die Einhängung wurde während der Prüfung ausgetauscht.");

        lease.MountId = entry.Id;
        lease.MountedDeviceNumber = entry.DeviceNumber;

        if (!entry.Target.StartsWith("/run/media/", StringComparison.Ordinal)
            || Path.GetFullPath(entry.Target) != entry.Target
            || !Directory.Exists(entry.Target))
            throw new IOException("Unerwarteter Mountpfad. Der Scan wird nicht gestartet.");

        for (DirectoryInfo? part = new(entry.Target); part is not null; part = part.Parent)
            if (part.LinkTarget is not null)
                throw new IOException("Der Mountpfad enthält einen symbolischen Link.");

        var vfs = entry.VfsOptions.Split(',').ToHashSet(StringComparer.Ordinal);
        var fs = entry.FsOptions.Split(',').ToHashSet(StringComparer.Ordinal);
        if (!new[] { "ro", "nodev", "nosuid", "noexec" }.All(vfs.Contains)
            || vfs.Contains("rw") || fs.Contains("rw"))
            throw new IOException("Der Mount besitzt nicht alle verlangten Schutzoptionen.");

        if (mounts.Any(mount => mount.Id != entry.Id
                && (mount.Target == entry.Target || IsBelow(mount.Target, entry.Target))))
            throw new IOException("Unter dem Scanpfad liegt eine weitere Einhängung.");

        string? expectedFs = lease.Volume.FileSystem?.ToLowerInvariant();
        bool matchingFs = expectedFs == "ntfs"
            ? entry.FileSystem == "fuseblk"
            : entry.FileSystem == expectedFs;
        if (!matchingFs)
            throw new IOException("Der Dateisystemtreiber entspricht nicht dem angeforderten Lesemodus.");

        if (expectedFs is "ext3" or "ext4"
            && !fs.Contains("noload") && !fs.Contains("norecovery"))
            throw new IOException("Der Verzicht auf Journal-Wiederherstellung ist nicht bestätigt.");

        EnsureIdentity(lease.Device);
    }

    internal async Task<IReadOnlyList<string>> CleanupAsync(bool interactive)
    {
        var warnings = new List<string>();
        foreach (ScanMountLease lease in _leases.ToArray().Reverse())
        {
            try
            {
                IReadOnlyList<ScanMountEntry> mounts = await ReadMountsAsync(CancellationToken.None)
                    .ConfigureAwait(false);
                ScanMountEntry[] matches = mounts.Where(mount =>
                    BaseSource(mount.Source) == lease.Volume.DevicePath).ToArray();

                if (matches.Length == 0)
                {
                    _leases.Remove(lease);
                    continue;
                }

                // Fremde oder nachträglich ausgetauschte Mounts niemals übernehmen.
                if (!lease.Created || matches.Length != 1
                    || matches[0].Source != lease.Volume.DevicePath
                    || (lease.MountId.HasValue && matches[0].Id != lease.MountId.Value)
                    || (lease.MountedDeviceNumber is not null
                        && matches[0].DeviceNumber != lease.MountedDeviceNumber)
                    || (lease.Target is not null && matches[0].Target != lease.Target))
                    throw new IOException("Die Eigentümerschaft der Einhängung ist nicht eindeutig.");

                EnsureIdentity(lease.Device);
                ScanMountEntry entry = matches[0];
                if (mounts.Any(mount => mount.Id != entry.Id
                    && (mount.Target == entry.Target || IsBelow(mount.Target, entry.Target))))
                    throw new IOException("Eine weitere Einhängung blockiert das sichere Aushängen.");

                var arguments = new List<string>
                {
                    "unmount", "--block-device", lease.Volume.DevicePath
                };
                if (!interactive)
                    arguments.Add("--no-user-interaction");

                LinuxCommandOutput output = await LinuxProcessRunner.RunAsync(
                    "/usr/bin/udisksctl", arguments, CancellationToken.None).ConfigureAwait(false);
                IReadOnlyList<ScanMountEntry> after = await ReadMountsAsync(CancellationToken.None)
                    .ConfigureAwait(false);

                if (after.Any(mount => mount.Id == entry.Id
                    || BaseSource(mount.Source) == lease.Volume.DevicePath))
                    throw new IOException("Die Einhängung besteht weiterhin. " + Details(output));

                _leases.Remove(lease);
                if (output.ExitCode != 0 || !string.IsNullOrWhiteSpace(output.StandardError))
                    warnings.Add($"{lease.Volume.DevicePath} ist ausgehängt, "
                        + "UDisks meldete dabei jedoch: " + Details(output));
            }
            catch (Exception exception)
            {
                warnings.Add($"{lease.Volume.DevicePath}: Aushängen nicht bestätigt. "
                    + exception.Message + " Dateimanager und andere Zugriffe schließen; "
                    + "anschließend ‚Aushängen erneut versuchen‘ wählen.");
            }
        }
        return warnings;
    }

    internal static void EnsureIdentity(StorageDevice device)
    {
        if (!device.DiskSequence.HasValue
            || LinuxStorageDeviceService.ReadDiskSequence(device.Name) != device.DiskSequence)
            throw new IOException("Das USB-Gerät wurde entfernt oder neu angeschlossen.");
    }

    internal static bool IsBelow(string path, string parent) =>
        path.StartsWith(parent.TrimEnd('/') + "/", StringComparison.Ordinal);

    private static string ResolveBlockDirectory(string name) =>
        new DirectoryInfo("/sys/class/block/" + name).ResolveLinkTarget(true)?.FullName
        ?? throw new IOException("Die Kernel-Zuordnung des Blockgeräts fehlt.");

    private static void EnsureNoHolders(string name)
    {
        if (Directory.EnumerateFileSystemEntries(
                "/sys/class/block/" + name + "/holders").Any())
            throw new IOException("Das Gerät wird von einem weiteren Blockgerät verwendet.");
    }

    private static bool SameVolumes(
        IReadOnlyList<StorageVolume> first, IReadOnlyList<StorageVolume> second) =>
        first.Count == second.Count && first.OrderBy(v => v.DevicePath)
            .Zip(second.OrderBy(v => v.DevicePath)).All(pair =>
                pair.First.DevicePath == pair.Second.DevicePath
                && pair.First.NodeType == pair.Second.NodeType
                && pair.First.SizeBytes == pair.Second.SizeBytes
                && pair.First.FileSystem == pair.Second.FileSystem
                && pair.First.Label == pair.Second.Label);

    private static HashSet<string> DevicePaths(StorageDevice device) =>
        device.Volumes.Select(v => v.DevicePath).Append(device.DevicePath)
            .ToHashSet(StringComparer.Ordinal);

    private static string BaseSource(string source)
    {
        int bracket = source.IndexOf('[');
        return bracket < 0 ? source : source[..bracket];
    }

    private static string Details(LinuxCommandOutput output) =>
        (output.StandardError + " " + output.StandardOutput).Trim() is { Length: > 0 } text
            ? text : $"Exit-Code {output.ExitCode}";

    private static async Task<IReadOnlyList<ScanMountEntry>> ReadMountsAsync(
        CancellationToken cancellationToken)
    {
        LinuxCommandOutput output = await LinuxProcessRunner.RunAsync(
            "/usr/bin/findmnt",
            ["--kernel", "--all", "--list", "--json", "--output",
             "ID,SOURCE,TARGET,MAJ:MIN,VFS-OPTIONS,FS-OPTIONS,FSTYPE"],
            cancellationToken).ConfigureAwait(false);
        if (output.ExitCode != 0 || !string.IsNullOrWhiteSpace(output.StandardError))
            throw new IOException("Die Mounttabelle konnte nicht zuverlässig gelesen werden. "
                + Details(output));

        using JsonDocument document = JsonDocument.Parse(output.StandardOutput);
        var result = new List<ScanMountEntry>();
        foreach (JsonElement row in document.RootElement.GetProperty("filesystems").EnumerateArray())
        {
            if (!long.TryParse(Text(row, "id"), NumberStyles.None,
                    CultureInfo.InvariantCulture, out long id) || id <= 0)
                throw new IOException("Eine Mount-ID fehlt in der findmnt-Ausgabe.");

            result.Add(new ScanMountEntry(id, Text(row, "source"), Text(row, "target"),
                Text(row, "maj:min"), Text(row, "vfs-options"), Text(row, "fs-options"),
                Text(row, "fstype")));
        }
        return result;
    }

    private static async Task EnsureNoFstabEntryAsync(
        StorageDevice device, CancellationToken cancellationToken)
    {
        // UDisks ignoriert eigene Optionen bei fstab-Geräten. Deshalb vorher ablehnen.
        LinuxCommandOutput fstab = await LinuxProcessRunner.RunAsync(
            "/usr/bin/findmnt", ["--fstab", "--list", "--json", "--output", "SOURCE"],
            cancellationToken).ConfigureAwait(false);
        if (fstab.ExitCode is not (0 or 1) || !string.IsNullOrWhiteSpace(fstab.StandardError))
            throw new IOException("Die fstab-Zuordnung konnte nicht geprüft werden.");
        if (string.IsNullOrWhiteSpace(fstab.StandardOutput))
            return;

        LinuxCommandOutput blocks = await LinuxProcessRunner.RunAsync(
            "/usr/bin/lsblk",
            ["--json", "--list", "--output", "PATH,UUID,LABEL,PARTUUID,PARTLABEL"],
            cancellationToken).ConfigureAwait(false);
        if (blocks.ExitCode != 0 || !string.IsNullOrWhiteSpace(blocks.StandardError))
            throw new IOException("Die Dateisystemkennungen konnten nicht geprüft werden.");

        HashSet<string> paths = DevicePaths(device);
        var tags = new HashSet<string>(StringComparer.Ordinal);
        using JsonDocument blockDocument = JsonDocument.Parse(blocks.StandardOutput);
        foreach (JsonElement row in blockDocument.RootElement.GetProperty("blockdevices").EnumerateArray())
        {
            if (!paths.Contains(Text(row, "path")))
                continue;
            foreach (string key in new[] { "uuid", "label", "partuuid", "partlabel" })
            {
                string value = Text(row, key);
                if (value.Length > 0)
                    tags.Add(key.ToUpperInvariant() + "=" + value);
            }
        }

        using JsonDocument fstabDocument = JsonDocument.Parse(fstab.StandardOutput);
        foreach (JsonElement row in fstabDocument.RootElement.GetProperty("filesystems").EnumerateArray())
        {
            string source = Text(row, "source");
            int equals = source.IndexOf('=');
            if (equals > 0)
                source = source[..(equals + 1)] + source[(equals + 1)..].Trim('\'', '"');
            if (source.StartsWith("/dev/", StringComparison.Ordinal))
                source = new FileInfo(source).ResolveLinkTarget(true)?.FullName ?? source;
            if (paths.Contains(source) || tags.Contains(source))
                throw new IOException("Dieses USB-Gerät ist in /etc/fstab eingetragen. "
                    + "Es wird nicht automatisch eingehängt oder gescannt.");
        }
    }

    private static string Text(JsonElement row, string name)
    {
        if (!row.TryGetProperty(name, out JsonElement value)
            || value.ValueKind == JsonValueKind.Null)
            return string.Empty;
        return value.ValueKind == JsonValueKind.String ? value.GetString()! : value.ToString();
    }
}
