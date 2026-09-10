using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

public interface ISmartHealthService
{
    Task<SmartHealthResult> CheckHealthAsync(
        string devicePath,
        CancellationToken cancellationToken = default);
}