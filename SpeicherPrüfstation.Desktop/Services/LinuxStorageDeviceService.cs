using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

public sealed class LinuxStorageDeviceService : IStorageDeviceService
{
    private const string LsblkExecutablePath = "/usr/bin/lsblk";

    private const string RequestedColumns =
        "NAME,KNAME,PATH,PKNAME,TYPE,TRAN,RM,HOTPLUG,SIZE,RO,FSTYPE,LABEL,MOUNTPOINTS,MODEL,VENDOR";

    public async Task<IReadOnlyList<StorageDevice>> GetUsbStorageDevicesAsync(
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException(
                "Die Speichergeräteerkennung wird nur unter Linux unterstützt.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        var startInfo = new ProcessStartInfo
        {
            FileName = LsblkExecutablePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            CreateNoWindow = true
        };

        startInfo.ArgumentList.Add("--json");
        startInfo.ArgumentList.Add("--bytes");
        startInfo.ArgumentList.Add("--tree");
        startInfo.ArgumentList.Add("--output");
        startInfo.ArgumentList.Add(RequestedColumns);

        using var process = new Process
        {
            StartInfo = startInfo
        };

        if (!process.Start())
        {
            throw new InvalidOperationException(
                "Der Prozess /usr/bin/lsblk konnte nicht gestartet werden.");
        }

        Task<string> standardOutputTask =
            process.StandardOutput.ReadToEndAsync();

        Task<string> standardErrorTask =
            process.StandardError.ReadToEndAsync();

        try
        {
            await process.WaitForExitAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            TryStopProcess(process);
            throw;
        }

        string standardOutput =
            await standardOutputTask.ConfigureAwait(false);

        string standardError =
            await standardErrorTask.ConfigureAwait(false);

        if (process.ExitCode != 0)
        {
            string details = string.IsNullOrWhiteSpace(standardError)
                ? "Keine Fehlerdetails vorhanden."
                : standardError.Trim();

            throw new InvalidOperationException(
                $"lsblk wurde mit Exit-Code {process.ExitCode} beendet: {details}");
        }

        return ParseUsbStorageDevices(standardOutput);
    }

    private static IReadOnlyList<StorageDevice> ParseUsbStorageDevices(
        string json)
    {
        LsblkJsonResult result;

        try
        {
            result = JsonSerializer.Deserialize<LsblkJsonResult>(json)
                ?? throw new JsonException(
                    "Die lsblk-Ausgabe enthielt kein Ergebnis.");
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException(
                "Die JSON-Ausgabe von lsblk konnte nicht gelesen werden.",
                exception);
        }

        return result.BlockDevices
            .Where(IsSupportedUsbDisk)
            .Select(CreateStorageDevice)
            .OrderBy(
                device => device.DevicePath,
                StringComparer.Ordinal)
            .ToArray();
    }

    private static bool IsSupportedUsbDisk(
        LsblkJsonDevice device)
    {
        return string.Equals(
                   device.NodeType,
                   "disk",
                   StringComparison.OrdinalIgnoreCase)
               && string.Equals(
                   device.Transport,
                   "usb",
                   StringComparison.OrdinalIgnoreCase)
               && !string.IsNullOrWhiteSpace(device.Name)
               && !string.IsNullOrWhiteSpace(device.DevicePath);
    }

    private static StorageDevice CreateStorageDevice(
        LsblkJsonDevice device)
    {
        return new StorageDevice
        {
            Name = NormalizeText(device.Name)!,
            DevicePath = NormalizeText(device.DevicePath)!,
            Transport = NormalizeText(device.Transport),
            IsRemovable = device.IsRemovable,
            IsHotPlug = device.IsHotPlug,
            SizeBytes = device.SizeBytes,
            IsReadOnly = device.IsReadOnly,
            Model = NormalizeText(device.Model),
            Vendor = NormalizeText(device.Vendor),
            Volumes = CreateVolumes(device)
        };
    }

    private static IReadOnlyList<StorageVolume> CreateVolumes(
        LsblkJsonDevice device)
    {
        var volumes = new List<StorageVolume>();

        if (!string.IsNullOrWhiteSpace(device.FileSystem))
        {
            volumes.Add(CreateStorageVolume(device));
        }

        AddChildVolumes(device.Children, volumes);

        return volumes;
    }

    private static void AddChildVolumes(
        IEnumerable<LsblkJsonDevice> children,
        ICollection<StorageVolume> volumes)
    {
        foreach (LsblkJsonDevice child in children)
        {
            bool isPartition = string.Equals(
                child.NodeType,
                "part",
                StringComparison.OrdinalIgnoreCase);

            bool hasFileSystem =
                !string.IsNullOrWhiteSpace(child.FileSystem);

            if (!string.IsNullOrWhiteSpace(child.DevicePath)
                && (isPartition || hasFileSystem))
            {
                volumes.Add(CreateStorageVolume(child));
            }

            AddChildVolumes(child.Children, volumes);
        }
    }

    private static StorageVolume CreateStorageVolume(
        LsblkJsonDevice device)
    {
        IReadOnlyList<string> mountPoints = device.MountPoints
            .Where(mountPoint =>
                !string.IsNullOrWhiteSpace(mountPoint))
            .Select(mountPoint => mountPoint!.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return new StorageVolume
        {
            Name = NormalizeText(device.Name)
                   ?? NormalizeText(device.DevicePath)
                   ?? "Unbekannt",

            DevicePath = NormalizeText(device.DevicePath)
                         ?? throw new InvalidOperationException(
                             "Ein Volume besitzt keinen Gerätepfad."),

            NodeType = NormalizeText(device.NodeType)
                       ?? "unknown",

            SizeBytes = device.SizeBytes,
            IsReadOnly = device.IsReadOnly,
            FileSystem = NormalizeText(device.FileSystem),
            Label = NormalizeText(device.Label),
            MountPoints = mountPoints
        };
    }

    private static string? NormalizeText(string? value)
    {
        string? trimmedValue = value?.Trim();

        return string.IsNullOrEmpty(trimmedValue)
            ? null
            : trimmedValue;
    }

    private static void TryStopProcess(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
            // Der Prozess wurde zwischenzeitlich bereits beendet.
        }
    }
}