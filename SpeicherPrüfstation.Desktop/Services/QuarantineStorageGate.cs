using System.Threading;

namespace SpeicherPrüfstation.Desktop.Services;

internal static class QuarantineStorageGate
{
    internal static SemaphoreSlim Operation { get; } =
        new(1, 1);
}
