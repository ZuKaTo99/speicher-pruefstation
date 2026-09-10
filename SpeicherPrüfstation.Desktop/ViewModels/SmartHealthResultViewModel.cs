using System;
using SpeicherPrüfstation.Desktop.Formatting;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.ViewModels;

public sealed class SmartHealthResultViewModel
{
    public SmartHealthResultViewModel(
        SmartHealthResult result)
    {
        Result = result
            ?? throw new ArgumentNullException(
                nameof(result));
    }

    public SmartHealthResult Result { get; }

    public string HealthText =>
        Result.State switch
        {
            SmartHealthState.Passed => "Bestanden",
            SmartHealthState.Warning => "Auffällig",
            SmartHealthState.Unavailable =>
                "Nicht verfügbar",
            _ => "Fehler"
        };

    public string SummaryText =>
        Result.Summary;

    public string ModelText =>
        GetTextOrFallback(
            Result.ModelName,
            "Nicht gemeldet");

    public string SerialNumberText =>
        GetTextOrFallback(
            Result.SerialNumber,
            "Nicht gemeldet");

    public string CapacityText =>
        Result.CapacityBytes.HasValue
            ? ByteSizeFormatter.Format(
                Result.CapacityBytes.Value)
            : "Nicht gemeldet";

    public string LogicalBlockSizeText =>
        Result.LogicalBlockSizeBytes.HasValue
            ? ByteSizeFormatter.Format(
                Result.LogicalBlockSizeBytes.Value)
            : "Nicht gemeldet";

    public string TemperatureText =>
        Result.TemperatureCelsius.HasValue
            ? $"{Result.TemperatureCelsius.Value} °C"
            : "Nicht verfügbar";

    public string SmartAvailableText =>
        FormatBoolean(Result.SmartAvailable);

    public string SmartEnabledText =>
        FormatBoolean(Result.SmartEnabled);

    public string DeviceTypeText
    {
        get
        {
            if (string.IsNullOrWhiteSpace(
                    Result.DeviceType))
            {
                return "Nicht erkannt";
            }

            return Result.DeviceType
                .Trim()
                .ToLowerInvariant() switch
            {
                "auto" => "Automatisch",
                "scsi" => "SCSI",
                "sat" => "SAT",
                var value => value.ToUpperInvariant()
            };
        }
    }

    private static string FormatBoolean(
        bool? value)
    {
        return value switch
        {
            true => "Ja",
            false => "Nein",
            null => "Nicht gemeldet"
        };
    }

    private static string GetTextOrFallback(
        string? value,
        string fallback)
    {
        return string.IsNullOrWhiteSpace(value)
            ? fallback
            : value.Trim();
    }
}
