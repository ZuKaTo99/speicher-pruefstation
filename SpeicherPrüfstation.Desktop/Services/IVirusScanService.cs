using System;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

public interface IVirusScanService
{
    bool HasPendingMounts { get; }

    Task<VirusScanResult> ScanAsync(
        StorageDevice device,
        IProgress<VirusScanProgress>? progress = null,
        CancellationToken cancellationToken = default);

    Task<VirusScanCleanupResult> RetryCleanupAsync();
}
