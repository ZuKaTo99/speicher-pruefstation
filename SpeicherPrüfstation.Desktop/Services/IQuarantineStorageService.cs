using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

public interface IQuarantineStorageService
{
    Task<QuarantineStorageSnapshot> GetSnapshotAsync(
        CancellationToken cancellationToken = default);

    Task<QuarantineDeletionResult> DeleteAsync(
        IReadOnlyList<string> entryIds,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);
}
