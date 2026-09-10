using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

public sealed class LinuxSmartHealthService
    : ISmartHealthService
{
    private const string PkexecPath =
        "/usr/bin/pkexec";

    private const string SmartctlPath =
        "/usr/bin/smartctl";

    private static readonly string?[] DeviceTypes =
    [
        null,
        "scsi",
        "sat"
    ];

    public async Task<SmartHealthResult> CheckHealthAsync(
        string devicePath,
        CancellationToken cancellationToken = default)
    {
        ValidateDevicePath(devicePath);

        SmartHealthResult? unavailableResult = null;
        SmartHealthResult? errorResult = null;

        foreach (string? deviceType in DeviceTypes)
        {
            CommandOutput output =
                await RunSmartctlAsync(
                    devicePath,
                    deviceType,
                    cancellationToken);

            if ((output.ExitCode is 126 or 127)
                && string.IsNullOrWhiteSpace(
                    output.StandardOutput))
            {
                throw new UnauthorizedAccessException(
                    "Die Berechtigung für die SMART-Prüfung "
                    + "wurde nicht erteilt.");
            }

            SmartHealthResult result =
                ParseResult(
                    devicePath,
                    deviceType,
                    output);

            if (result.State is SmartHealthState.Passed
                or SmartHealthState.Warning)
            {
                return result;
            }

            if (result.State == SmartHealthState.Unavailable)
            {
                unavailableResult ??= result;
            }
            else
            {
                errorResult = result;
            }
        }

        return unavailableResult
               ?? errorResult
               ?? CreateErrorResult(
                   devicePath,
                   null,
                   -1,
                   "Es wurde kein auswertbares "
                   + "SMART-Ergebnis geliefert.",
                   string.Empty);
    }

    private static async Task<CommandOutput>
        RunSmartctlAsync(
            string devicePath,
            string? deviceType,
            CancellationToken cancellationToken)
    {
        var startInfo =
            new ProcessStartInfo
            {
                FileName = PkexecPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
                CreateNoWindow = true
            };

        startInfo.ArgumentList.Add(SmartctlPath);

        if (!string.IsNullOrWhiteSpace(deviceType))
        {
            startInfo.ArgumentList.Add(
                $"--device={deviceType}");
        }

        startInfo.ArgumentList.Add("--info");
        startInfo.ArgumentList.Add("--health");
        startInfo.ArgumentList.Add("--attributes");
        startInfo.ArgumentList.Add("--json");
        startInfo.ArgumentList.Add(devicePath);

        using var process =
            new Process
            {
                StartInfo = startInfo
            };

        bool started = false;

        try
        {
            started = process.Start();

            if (!started)
            {
                throw new InvalidOperationException(
                    "smartctl konnte nicht gestartet werden.");
            }

            Task<string> standardOutputTask =
                process.StandardOutput.ReadToEndAsync();

            Task<string> standardErrorTask =
                process.StandardError.ReadToEndAsync();

            await process.WaitForExitAsync(
                cancellationToken);

            string standardOutput =
                await standardOutputTask;

            string standardError =
                await standardErrorTask;

            return new CommandOutput(
                process.ExitCode,
                standardOutput,
                standardError);
        }
        catch
        {
            if (started)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(
                            entireProcessTree: true);
                    }
                }
                catch
                {
                    // Der ursprüngliche Fehler ist wichtiger.
                }
            }

            throw;
        }
    }

    private static SmartHealthResult ParseResult(
        string devicePath,
        string? requestedDeviceType,
        CommandOutput output)
    {
        string? json =
            ExtractJson(output.StandardOutput);

        if (json is null)
        {
            string message =
                string.IsNullOrWhiteSpace(
                    output.StandardError)
                    ? "smartctl hat keine JSON-Daten geliefert."
                    : output.StandardError.Trim();

            return CreateErrorResult(
                devicePath,
                requestedDeviceType,
                output.ExitCode,
                message,
                output.StandardOutput);
        }

        try
        {
            using JsonDocument document =
                JsonDocument.Parse(json);

            JsonElement root =
                document.RootElement;

            bool? smartAvailable =
                GetBoolean(
                    root,
                    "smart_support",
                    "available");

            bool? smartEnabled =
                GetBoolean(
                    root,
                    "smart_support",
                    "enabled");

            bool? passed =
                GetBoolean(
                    root,
                    "smart_status",
                    "passed");

            int? temperature =
                GetInt32(
                    root,
                    "temperature",
                    "current");

            if (temperature.HasValue
                && temperature.Value <= 0)
            {
                temperature = null;
            }

            string deviceType =
                GetString(
                    root,
                    "device",
                    "type")
                ?? requestedDeviceType
                ?? "auto";

            int exitStatus =
                GetInt32(
                    root,
                    "smartctl",
                    "exit_status")
                ?? output.ExitCode;

            string? toolMessage =
                ReadToolMessages(root);

            SmartHealthState state;
            string summary;

            if (passed is true)
            {
                state = SmartHealthState.Passed;
                summary =
                    "Der Controller meldet keinen "
                    + "SMART-Hardwarefehler.";
            }
            else if (passed is false)
            {
                state = SmartHealthState.Warning;
                summary =
                    "Der Controller meldet einen möglichen "
                    + "SMART-Hardwarefehler.";
            }
            else if (smartAvailable is false)
            {
                state = SmartHealthState.Unavailable;
                summary =
                    "Dieses Gerät stellt über diese "
                    + "Schnittstelle keine SMART-Daten bereit.";
            }
            else if (smartAvailable is true)
            {
                state = SmartHealthState.Unavailable;
                summary =
                    "SMART ist verfügbar, liefert aber keinen "
                    + "eindeutigen Gesamtstatus.";
            }
            else
            {
                state = SmartHealthState.Error;
                summary =
                    toolMessage
                    ?? GetErrorText(output)
                    ?? "Das SMART-Ergebnis konnte nicht "
                    + "ausgewertet werden.";
            }

            return new SmartHealthResult
            {
                DevicePath = devicePath,
                State = state,
                Summary = summary,
                DeviceType = deviceType,
                ExitStatus = exitStatus,
                ModelName =
                    GetString(root, "model_name")
                    ?? GetString(root, "scsi_model_name")
                    ?? GetString(root, "scsi_product"),
                SerialNumber =
                    GetString(root, "serial_number"),
                CapacityBytes =
                    GetInt64(
                        root,
                        "user_capacity",
                        "bytes"),
                LogicalBlockSizeBytes =
                    GetInt32(
                        root,
                        "logical_block_size"),
                TemperatureCelsius = temperature,
                SmartAvailable = smartAvailable,
                SmartEnabled = smartEnabled,
                Passed = passed,
                RawJson = json
            };
        }
        catch (JsonException exception)
        {
            return CreateErrorResult(
                devicePath,
                requestedDeviceType,
                output.ExitCode,
                $"Die SMART-Ausgabe war ungültig: "
                + exception.Message,
                output.StandardOutput);
        }
    }

    private static SmartHealthResult
        CreateErrorResult(
            string devicePath,
            string? deviceType,
            int exitStatus,
            string summary,
            string rawJson)
    {
        return new SmartHealthResult
        {
            DevicePath = devicePath,
            State = SmartHealthState.Error,
            Summary = summary.Trim(),
            DeviceType = deviceType ?? "auto",
            ExitStatus = exitStatus,
            RawJson = rawJson
        };
    }

    private static string? ExtractJson(
        string output)
    {
        int startIndex =
            output.IndexOf('{');

        int endIndex =
            output.LastIndexOf('}');

        if (startIndex < 0
            || endIndex < startIndex)
        {
            return null;
        }

        return output[
            startIndex..(endIndex + 1)];
    }

    private static string? GetErrorText(
        CommandOutput output)
    {
        return string.IsNullOrWhiteSpace(
            output.StandardError)
            ? null
            : output.StandardError.Trim();
    }

    private static string? ReadToolMessages(
        JsonElement root)
    {
        if (!TryGetElement(
                root,
                out JsonElement messages,
                "smartctl",
                "messages")
            || messages.ValueKind
            != JsonValueKind.Array)
        {
            return null;
        }

        var values = new List<string>();

        foreach (JsonElement message
                 in messages.EnumerateArray())
        {
            string? text =
                GetString(
                    message,
                    "string");

            if (!string.IsNullOrWhiteSpace(text))
            {
                values.Add(text.Trim());
            }
        }

        return values.Count == 0
            ? null
            : string.Join(" ", values);
    }

    private static string? GetString(
        JsonElement root,
        params string[] path)
    {
        if (!TryGetElement(
                root,
                out JsonElement element,
                path)
            || element.ValueKind
            != JsonValueKind.String)
        {
            return null;
        }

        return element.GetString();
    }

    private static bool? GetBoolean(
        JsonElement root,
        params string[] path)
    {
        if (!TryGetElement(
                root,
                out JsonElement element,
                path))
        {
            return null;
        }

        return element.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }

    private static int? GetInt32(
        JsonElement root,
        params string[] path)
    {
        if (!TryGetElement(
                root,
                out JsonElement element,
                path)
            || !element.TryGetInt32(
                out int value))
        {
            return null;
        }

        return value;
    }

    private static long? GetInt64(
        JsonElement root,
        params string[] path)
    {
        if (!TryGetElement(
                root,
                out JsonElement element,
                path)
            || !element.TryGetInt64(
                out long value))
        {
            return null;
        }

        return value;
    }

    private static bool TryGetElement(
        JsonElement root,
        out JsonElement element,
        params string[] path)
    {
        element = root;

        foreach (string propertyName in path)
        {
            if (element.ValueKind
                != JsonValueKind.Object
                || !element.TryGetProperty(
                    propertyName,
                    out JsonElement nextElement))
            {
                element = default;
                return false;
            }

            element = nextElement;
        }

        return true;
    }

    private static void ValidateDevicePath(
        string devicePath)
    {
        if (string.IsNullOrWhiteSpace(devicePath)
            || !devicePath.StartsWith(
                "/dev/",
                StringComparison.Ordinal)
            || devicePath.Contains('\0')
            || devicePath.Contains('\r')
            || devicePath.Contains('\n'))
        {
            throw new ArgumentException(
                "Der Gerätepfad ist ungültig.",
                nameof(devicePath));
        }
    }

    private sealed record CommandOutput(
        int ExitCode,
        string StandardOutput,
        string StandardError);
}