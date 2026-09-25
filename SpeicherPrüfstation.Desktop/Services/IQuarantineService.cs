using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

public interface IQuarantineService
{
    bool HasPendingMounts { get; }

    Task<QuarantineResult> QuarantineAsync(
        StorageDevice device,
        IReadOnlyList<VirusFinding> findings,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    Task<VirusScanCleanupResult> RetryCleanupAsync();
}
