using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

public sealed class LinuxVirusScanService : IVirusScanService
{
    private const int MaximumFileSizeMiB = 512;
    private const int MaximumScanSizeMiB = 1024;
    private const long MaximumFileSize = MaximumFileSizeMiB * 1024L * 1024L;

    private readonly LinuxScanMountService _mounts;
    private readonly SemaphoreSlim _operation = new(1, 1);
    private volatile bool _hasPendingMounts;

    public LinuxVirusScanService(IStorageDeviceService storageDeviceService)
    {
        ArgumentNullException.ThrowIfNull(storageDeviceService);
        _mounts = new LinuxScanMountService(storageDeviceService);
    }

    public bool HasPendingMounts => _hasPendingMounts;

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();

    public async Task<VirusScanResult> ScanAsync(
        StorageDevice device,
        IProgress<VirusScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        if (!await _operation.WaitAsync(0, cancellationToken).ConfigureAwait(false))
            throw new InvalidOperationException("Es läuft bereits eine Scan- oder Aufräumoperation.");

        var findings = new List<VirusFinding>();
        var errors = new List<string>();
        var warnings = new List<string>();
        long scannedFiles = 0;
        long additionalToolErrors = 0;
        bool canceled = false;
        int visitedVolumes = 0;
        string? temporaryDirectory = null;
        string status = "USB-Gerät und Voraussetzungen werden geprüft …";
        var progressClock = Stopwatch.StartNew();

        try
        {
            if (_mounts.HasPendingMounts)
                throw new IOException("Zuerst die ausstehende Einhängung aufräumen.");
            if (!OperatingSystem.IsLinux())
                throw new PlatformNotSupportedException("Der Virenscan ist nur unter Linux verfügbar.");
            if (GetEffectiveUserId() == 0)
                throw new IOException("Bitte die Anwendung als normalen Benutzer starten. "
                    + "ClamAV wird nicht als root ausgeführt.");

            Report();
            foreach (string tool in new[] { "clamscan", "udisksctl", "findmnt", "lsblk" })
                if (!File.Exists("/usr/bin/" + tool))
                    throw new IOException($"Das benötigte Werkzeug /usr/bin/{tool} fehlt.");

            UnixFileMode scannerMode = File.GetUnixFileMode("/usr/bin/clamscan");
            if ((scannerMode & (UnixFileMode.SetUser | UnixFileMode.SetGroup)) != 0)
                throw new IOException("clamscan besitzt unerwartete Sonderrechte.");

            LinuxCommandOutput help = await LinuxProcessRunner.RunAsync(
                "/usr/bin/clamscan", ["--help"], cancellationToken).ConfigureAwait(false);
            foreach (string option in new[]
            {
                "--recursive", "--cross-fs", "--follow-dir-symlinks", "--follow-file-symlinks",
                "--alert-encrypted", "--alert-exceeds-max", "--fail-if-cvd-older-than",
                "--max-dir-recursion", "--tempdir"
            })
                if (help.ExitCode != 0 || !help.StandardOutput.Contains(option, StringComparison.Ordinal))
                    throw new IOException("Die installierte ClamAV-Version unterstützt "
                        + $"die benötigte Option {option} nicht.");

            StorageDevice current = await _mounts.ValidateSelectionAsync(device, cancellationToken)
                .ConfigureAwait(false);

            // Nur private temporäre Scannerdateien auf dem Stationsrechner.
            temporaryDirectory = "/tmp/speicher-pruefstation-" + Guid.NewGuid().ToString("N");
            Directory.CreateDirectory(temporaryDirectory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            foreach (StorageVolume volume in current.Volumes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                visitedVolumes++;
                if (LinuxScanMountService.MountOptions(volume) is null)
                {
                    warnings.Add($"{volume.DevicePath}: Dateisystem "
                        + $"‚{volume.FileSystem ?? "nicht erkannt"}‘ wird noch nicht sicher unterstützt.");
                    Report();
                    continue;
                }

                ClamScanOutputParser? parser = null;
                bool stopAfterVolume = false;
                try
                {
                    status = $"{volume.DevicePath} wird lesend eingehängt …";
                    Report();
                    ScanMountLease lease = await _mounts.MountAsync(current, volume, cancellationToken)
                        .ConfigureAwait(false);

                    await WithMountGuardAsync(lease, async token =>
                    {
                        status = $"{volume.DevicePath}: Verzeichnisstruktur wird geprüft …";
                        Report();
                        var preflight = await Task.Run(
                            () => CheckDirectoryTree(lease.Target!, token), token).ConfigureAwait(false);
                        warnings.AddRange(preflight.Warnings);
                        await _mounts.EnsureSafeMountAsync(lease, token).ConfigureAwait(false);

                        parser = new ClamScanOutputParser(lease.Target!, volume.DevicePath);
                        status = $"{volume.DevicePath}: ClamAV prüft Dateien …";
                        Report(parser);

                        LinuxCommandOutput output = await LinuxProcessRunner.RunAsync(
                            "/usr/bin/clamscan",
                            ["--stdout", "--recursive=yes", "--cross-fs=no",
                             "--follow-dir-symlinks=0", "--follow-file-symlinks=0",
                             "--alert-encrypted=yes", "--alert-exceeds-max=yes",
                             "--fail-if-cvd-older-than=7",
                             $"--max-filesize={MaximumFileSizeMiB}M",
                             $"--max-scansize={MaximumScanSizeMiB}M", "--max-files=10000",
                             "--max-recursion=32", "--max-dir-recursion=256",
                             "--max-scantime=120000", "--tempdir=" + temporaryDirectory,
                             "--", lease.Target!],
                            token, (line, isError) =>
                            {
                                parser.ReadLine(line, isError);
                                lock (progressClock)
                                {
                                    if (progressClock.ElapsedMilliseconds < 250)
                                        return;
                                    progressClock.Restart();
                                    Report(parser);
                                }
                            }).ConfigureAwait(false);

                        parser.Complete(output.ExitCode);
                        long accountedFiles = parser.AccountedFiles();
                        if (accountedFiles < preflight.ExpectedFiles)
                            throw new IOException($"ClamAV hat nur {accountedFiles} von mindestens "
                                + $"{preflight.ExpectedFiles} erwarteten nicht leeren Dateien "
                                + "in der Einzelausgabe berücksichtigt.");

                        await _mounts.EnsureSafeMountAsync(lease, token).ConfigureAwait(false);
                    }, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    canceled = true;
                    stopAfterVolume = true;
                }
                catch (Exception exception)
                {
                    errors.Add($"{volume.DevicePath}: {exception.Message}");
                    stopAfterVolume = true;
                }
                finally
                {
                    if (parser is not null)
                    {
                        VirusScanResult partialResult = parser.Snapshot();
                        scannedFiles += partialResult.ScannedFiles;
                        additionalToolErrors += Math.Max(0,
                            partialResult.ErrorCount - partialResult.Errors.Count);
                        findings.AddRange(partialResult.Findings);
                        errors.AddRange(partialResult.Errors);
                        warnings.AddRange(partialResult.Warnings);
                    }

                    status = "Eigene Einhängung wird ausgehängt und kontrolliert …";
                    Report();
                    warnings.AddRange(await _mounts.CleanupAsync(false).ConfigureAwait(false));
                    _hasPendingMounts = _mounts.HasPendingMounts;
                }

                if (stopAfterVolume || _mounts.HasPendingMounts)
                    break;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            canceled = true;
        }
        catch (Exception exception)
        {
            errors.Add(exception.Message);
        }
        finally
        {
            try
            {
                // Auch Fehler während Vorbereitung oder Mountprüfung führen hierher.
                if (_mounts.HasPendingMounts)
                {
                    status = "Ausstehende Einhängung wird aufgeräumt …";
                    Report();
                    warnings.AddRange(await _mounts.CleanupAsync(false).ConfigureAwait(false));
                }

                if (temporaryDirectory is not null)
                {
                    try
                    {
                        // Dieser zufällige private Ordner wurde oben selbst angelegt.
                        Directory.Delete(temporaryDirectory, recursive: true);
                    }
                    catch (Exception exception)
                    {
                        warnings.Add("Temporäre Scannerdateien konnten nicht vollständig entfernt werden: "
                            + temporaryDirectory + ". " + exception.Message);
                    }
                }
            }
            finally
            {
                _hasPendingMounts = _mounts.HasPendingMounts;
                _operation.Release();
            }
        }

        canceled |= cancellationToken.IsCancellationRequested;
        if (!canceled && visitedVolumes < device.Volumes.Count)
            warnings.Add("Nicht alle erkannten Volumes wurden geprüft.");
        if (!canceled && scannedFiles == 0 && errors.Count == 0)
            warnings.Add("Es wurden keine prüfbaren Dateien gemeldet.");

        VirusScanState state = canceled ? VirusScanState.Canceled
            : errors.Count > 0 && scannedFiles == 0 ? VirusScanState.Failed
            : errors.Count > 0 || warnings.Count > 0 || _hasPendingMounts ? VirusScanState.Incomplete
            : findings.Count > 0 ? VirusScanState.Findings
            : VirusScanState.NoFindings;

        string summary = state switch
        {
            VirusScanState.NoFindings => "Keine Funde in den geprüften Dateien gemeldet.",
            VirusScanState.Findings => "ClamAV hat verdächtige Dateien gemeldet. Fundliste prüfen.",
            VirusScanState.Incomplete => "Der Scan war unvollständig. Warnungen und Fehler beachten.",
            VirusScanState.Canceled => "Der Scan wurde abgebrochen. Das Ergebnis ist unvollständig.",
            _ => "Der Virenscan ist fehlgeschlagen. Fehlerdetails beachten."
        };
        if (findings.Count > 0)
            summary += $" Gemeldete Verdachtsfunde: {findings.Count}.";
        if (_hasPendingMounts)
            summary += " Mindestens eine Einhängung muss noch aufgeräumt werden.";

        return new VirusScanResult
        {
            DevicePath = device.DevicePath,
            State = state,
            Summary = summary,
            ScannedFiles = scannedFiles,
            ErrorCount = errors.Count + additionalToolErrors,
            HasPendingMounts = _hasPendingMounts,
            Findings = findings.ToArray(),
            Errors = errors.ToArray(),
            Warnings = warnings.ToArray()
        };

        void Report(ClamScanOutputParser? activeParser = null)
        {
            var counts = activeParser?.Counts() ?? (0L, 0L, 0L, 0L);
            progress?.Report(new VirusScanProgress(status,
                scannedFiles + counts.Item1, findings.Count + counts.Item2,
                errors.Count + additionalToolErrors + counts.Item3,
                warnings.Count + counts.Item4));
        }
    }

    public async Task<VirusScanCleanupResult> RetryCleanupAsync()
    {
        if (!await _operation.WaitAsync(0).ConfigureAwait(false))
            throw new InvalidOperationException("Die laufende Operation muss zuerst beendet werden.");
        try
        {
            IReadOnlyList<string> messages = await _mounts.CleanupAsync(true).ConfigureAwait(false);
            return new VirusScanCleanupResult(_mounts.HasPendingMounts, messages);
        }
        finally
        {
            _hasPendingMounts = _mounts.HasPendingMounts;
            _operation.Release();
        }
    }

    private async Task WithMountGuardAsync(
        ScanMountLease lease, Func<CancellationToken, Task> action,
        CancellationToken cancellationToken)
    {
        using var scanToken = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var stopWatcher = new CancellationTokenSource();
        Exception? mountError = null;
        Task watcher = WatchAsync();
        try
        {
            await action(scanToken.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (mountError is not null)
        {
            throw new IOException("Der Mountzustand hat sich geändert: " + mountError.Message, mountError);
        }
        finally
        {
            stopWatcher.Cancel();
            await watcher.ConfigureAwait(false);
        }
        if (mountError is not null)
            throw new IOException("Der Mountzustand ist unsicher: " + mountError.Message, mountError);

        async Task WatchAsync()
        {
            try
            {
                while (true)
                {
                    await Task.Delay(1000, stopWatcher.Token).ConfigureAwait(false);
                    await _mounts.EnsureSafeMountAsync(lease, stopWatcher.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (stopWatcher.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                mountError = exception;
                scanToken.Cancel();
            }
        }
    }

    private static (IReadOnlyList<string> Warnings, long ExpectedFiles) CheckDirectoryTree(
        string root, CancellationToken cancellationToken)
    {
        var directories = new Stack<(string Path, int Depth)>();
        directories.Push((root, 0));
        long links = 0;
        long largeFiles = 0;
        long expectedFiles = 0;

        while (directories.TryPop(out var directory))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (directory.Depth > 200)
                throw new IOException("Die Verzeichnisstruktur überschreitet die sichere Scan-Tiefe.");

            foreach (string path in Directory.EnumerateFileSystemEntries(directory.Path))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (path.Any(char.IsControl))
                    throw new IOException("Ein Dateiname enthält Steuerzeichen und lässt sich "
                        + "nicht eindeutig aus der ClamAV-Textausgabe auswerten.");

                FileAttributes attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    links++;
                    continue;
                }

                if ((attributes & FileAttributes.Directory) != 0)
                    directories.Push((path, directory.Depth + 1));
                else
                {
                    long length = new FileInfo(path).Length;
                    if (length > MaximumFileSize)
                    {
                        largeFiles++;
                    }
                    else if (length > 0)
                    {
                        // Dateien oberhalb des Limits bleiben als Warnung sichtbar,
                        // gehören aber nicht zur erwarteten Zahl gescannter Dateien.
                        expectedFiles++;
                    }
                }
            }
        }

        var warnings = new List<string>();
        if (links > 0)
            warnings.Add($"{links} symbolische Links werden nicht verfolgt.");
        if (largeFiles > 0)
            warnings.Add($"{largeFiles} Dateien überschreiten das Scanlimit von "
                + $"{MaximumFileSizeMiB} MiB.");

        return (warnings, expectedFiles);
    }
}
