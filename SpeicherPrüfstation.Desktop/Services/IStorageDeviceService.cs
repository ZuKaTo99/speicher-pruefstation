using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

public interface IStorageDeviceService
{
    Task<IReadOnlyList<StorageDevice>> GetUsbStorageDevicesAsync(CancellationToken cancellationToken = default);
}
