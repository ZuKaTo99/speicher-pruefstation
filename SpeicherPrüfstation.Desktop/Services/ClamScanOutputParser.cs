using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.Services;

internal sealed class ClamScanOutputParser(string root, string volumePath)
{
    private sealed record ScannerError(
        string? File,
        string Message,
        bool IsVirusDetectedError);

    private readonly object _sync = new();
    private readonly List<VirusFinding> _findings = [];
    private readonly List<string> _errors = [];
    private readonly List<string> _warnings = [];
    private readonly List<ScannerError> _scannerErrors = [];

    private readonly HashSet<string> _detectedFiles = new(StringComparer.Ordinal);
    private readonly HashSet<string> _malwareFiles = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _maxFileSizeWarnings = new(StringComparer.Ordinal);

    private long _observedFiles;
    private long? _summaryFiles;
    private long? _summaryInfected;
    private long? _summaryErrors;
    private long _normalizedLimitErrors;
    private bool _summaryStarted;
    private bool _completed;

    internal void ReadLine(string line, bool isError)
    {
        lock (_sync)
        {
            if (string.IsNullOrWhiteSpace(line))
                return;

            if (_findings.Count + _errors.Count + _warnings.Count + _scannerErrors.Count >= 10000)
                throw new IOException("Die Grenze von 10.000 Ergebnismeldungen wurde erreicht. "
                    + "Der Scan wird als unvollständig beendet.");

            // Dateimeldungen anhand ihres Inhalts auswerten, auch auf stderr.
            if (line.StartsWith(root + "/", StringComparison.Ordinal))
            {
                int separator = line.LastIndexOf(": ", StringComparison.Ordinal);
                if (separator < root.Length)
                {
                    _warnings.Add("Nicht auswertbare Scannerzeile: " + line);
                    return;
                }

                string file = line[..separator];
                string status = line[(separator + 2)..];
                string displayPath = volumePath + ":/" + Path.GetRelativePath(root, file);

                if (status == "OK")
                {
                    _observedFiles++;
                }
                else if (status.EndsWith(" FOUND", StringComparison.Ordinal))
                {
                    _observedFiles++;
                    _detectedFiles.Add(file);
                    string signature = status[..^6];

                    if (signature.Length == 0)
                    {
                        _errors.Add(displayPath + ": Eine Fundmeldung enthält keinen Signaturnamen.");
                        return;
                    }

                    if (signature.StartsWith("Heuristics.Encrypted.", StringComparison.Ordinal)
                        || signature.StartsWith("Heuristics.Limits.Exceeded", StringComparison.Ordinal))
                    {
                        int warningIndex = _warnings.Count;
                        _warnings.Add($"Nicht vollständig prüfbar: {displayPath} ({signature})");

                        if (signature == "Heuristics.Limits.Exceeded.MaxFileSize")
                            _maxFileSizeWarnings.TryAdd(file, warningIndex);
                    }
                    else
                    {
                        _malwareFiles.Add(file);
                        _findings.Add(new VirusFinding(displayPath, signature));
                    }
                }
                else if (status.EndsWith(" ERROR", StringComparison.Ordinal)
                         || status.Contains("ERROR", StringComparison.Ordinal))
                {
                    // Erst nach der vollständigen Ausgabe einer möglichen Limitmeldung zuordnen.
                    _scannerErrors.Add(new ScannerError(
                        file,
                        displayPath + ": " + status,
                        status == "Virus(es) detected ERROR"));
                }
                else if (status != "Empty file")
                {
                    _warnings.Add(displayPath + ": " + status);
                }
                return;
            }

            if (isError)
            {
                if (line.Contains("error", StringComparison.OrdinalIgnoreCase))
                    _scannerErrors.Add(new ScannerError(null, line, false));
                else
                    _warnings.Add(line);
                return;
            }

            if (line == "----------- SCAN SUMMARY -----------")
            {
                if (_summaryStarted)
                    _errors.Add("Mehrere unerwartete Scan-Zusammenfassungen empfangen.");
                _summaryStarted = true;
                return;
            }

            if (_summaryStarted)
            {
                if (ReadNumber(line, "Scanned files:", out long files))
                {
                    if (_summaryFiles.HasValue)
                        _errors.Add("Doppelte Dateianzahl in der Scanner-Ausgabe.");
                    _summaryFiles = files;
                    return;
                }
                if (ReadNumber(line, "Infected files:", out long infected))
                {
                    if (_summaryInfected.HasValue)
                        _errors.Add("Doppelte Fundanzahl in der Scanner-Ausgabe.");
                    _summaryInfected = infected;
                    return;
                }
                if (ReadNumber(line, "Total errors:", out long errors))
                {
                    if (_summaryErrors.HasValue)
                        _errors.Add("Doppelte Fehleranzahl in der Scanner-Ausgabe.");
                    _summaryErrors = errors;
                    return;
                }
                foreach (string prefix in new[]
                {
                    "Known viruses:", "Engine version:", "Scanned directories:",
                    "Data scanned:", "Data read:", "Time:", "Start Date:", "End Date:"
                })
                    if (line.StartsWith(prefix, StringComparison.Ordinal))
                        return;
            }

            if (line.Contains("ERROR", StringComparison.OrdinalIgnoreCase))
                _scannerErrors.Add(new ScannerError(null, line, false));
            else
                _warnings.Add("Zusätzliche Scanner-Meldung: " + line);
        }
    }

    internal void Complete(int exitCode)
    {
        lock (_sync)
        {
            if (_completed)
                return;

            bool hasSummary = _summaryStarted
                              && _summaryFiles.HasValue
                              && _summaryInfected.HasValue;
            if (!hasSummary)
                _errors.Add("Die vollständige Scan-Zusammenfassung fehlt.");

            // Die Zusammenfassung zählt Dateien, nicht einzelne Signaturmeldungen.
            // Prüflückenmeldungen können außerhalb der Zahl infizierter Dateien liegen.
            long minimumInfected = _malwareFiles.Count;
            long maximumInfected = _detectedFiles.Count;
            if (_summaryInfected.HasValue)
            {
                long infected = _summaryInfected.Value;
                if (infected < minimumInfected || infected > maximumInfected)
                {
                    _errors.Add("Fundliste und ClamAV-Zusammenfassung stimmen nicht überein. "
                        + $"ClamAV: {infected}; Dateien mit Schadsoftwarehinweisen: "
                        + $"{minimumInfected}; einschließlich Prüflückenmeldungen: {maximumInfected}.");
                }
                else if (infected != maximumInfected)
                {
                    _warnings.Add("Abweichende Zählweise bei Prüflücken: "
                        + $"ClamAV meldet {infected} infizierte Dateien; ausgewertet wurden "
                        + $"{minimumInfected} Dateien mit Schadsoftwarehinweisen und "
                        + $"{maximumInfected - minimumInfected} weitere Dateien mit Prüflückenmeldungen.");
                }
            }

            if ((exitCode == 0 && _detectedFiles.Count > 0)
                || (exitCode == 1 && _detectedFiles.Count == 0))
                _errors.Add("Exit-Code und ausgewertete Funde widersprechen sich.");

            if (_summaryFiles.HasValue && _summaryFiles.Value < minimumInfected)
                _errors.Add("Die gemeldete Dateianzahl ist widersprüchlich.");

            // Nur eine vollständig belegte Kombination als Prüflücke einordnen:
            // Exit-Code 2, passende Fehlersumme, für jeden Fehler dieselbe Datei
            // mit MaxFileSize-Meldung und keine Schadsoftwaremeldung für diese Datei.
            bool onlyMatchedLimitErrors = exitCode == 2
                                          && hasSummary
                                          && _errors.Count == 0
                                          && _scannerErrors.Count > 0
                                          && _summaryErrors.HasValue
                                          && _summaryErrors.Value == _scannerErrors.Count;

            if (onlyMatchedLimitErrors)
            {
                foreach (ScannerError error in _scannerErrors)
                {
                    if (!IsMatchedLimitError(error))
                    {
                        onlyMatchedLimitErrors = false;
                        break;
                    }
                }
            }

            if (onlyMatchedLimitErrors)
            {
                _normalizedLimitErrors = _scannerErrors.Count;
                foreach (ScannerError error in _scannerErrors)
                {
                    int warningIndex = _maxFileSizeWarnings[error.File!];
                    _warnings[warningIndex] +=
                        " ClamAV meldete dazu zusätzlich: Virus(es) detected ERROR.";
                }

                _warnings.Add($"ClamAV-Exit-Code 2: Alle {_normalizedLimitErrors} "
                    + "gemeldeten Dateifehler sind den oben aufgeführten "
                    + "Dateigrößen-Limitmeldungen zugeordnet. Der Scan bleibt unvollständig.");
            }
            else
            {
                foreach (ScannerError error in _scannerErrors)
                    _errors.Add(error.Message);
            }

            if (exitCode is not (0 or 1) && !onlyMatchedLimitErrors)
            {
                string reportedErrors = _summaryErrors.HasValue
                    ? _summaryErrors.Value.ToString(CultureInfo.InvariantCulture)
                    : "nicht angegeben";
                _errors.Add($"ClamAV wurde mit Fehlercode {exitCode} beendet. "
                    + $"Fehlersumme laut Zusammenfassung: {reportedErrors}; "
                    + $"ausgewertete Fehlerzeilen: {_scannerErrors.Count}.");
            }

            if (_summaryErrors.GetValueOrDefault() > 0 && _scannerErrors.Count == 0)
                _errors.Add($"ClamAV meldet {_summaryErrors.GetValueOrDefault()} Werkzeugfehler; "
                    + "die zugehörigen Einzelmeldungen fehlen.");

            _completed = true;
        }
    }

    private bool IsMatchedLimitError(ScannerError error) =>
        error.IsVirusDetectedError
        && error.File is not null
        && _maxFileSizeWarnings.ContainsKey(error.File)
        && !_malwareFiles.Contains(error.File);

    private long CurrentErrorCount() =>
        Math.Max(
            Math.Max(0, _summaryErrors.GetValueOrDefault() - _normalizedLimitErrors),
            _errors.Count + (_completed ? 0 : _scannerErrors.Count));

    internal (long Files, long Findings, long Errors, long Warnings) Counts()
    {
        lock (_sync)
            return (_summaryFiles ?? _observedFiles, _findings.Count,
                CurrentErrorCount(), _warnings.Count);
    }

    internal VirusScanResult Snapshot()
    {
        lock (_sync)
        {
            var errors = new List<string>(_errors);
            if (!_completed)
                foreach (ScannerError error in _scannerErrors)
                    errors.Add(error.Message);

            return new VirusScanResult
            {
                DevicePath = volumePath,
                State = VirusScanState.Incomplete,
                Summary = "Teilergebnis",
                ScannedFiles = _summaryFiles ?? _observedFiles,
                ErrorCount = CurrentErrorCount(),
                Findings = _findings.ToArray(),
                Errors = errors.ToArray(),
                Warnings = _warnings.ToArray()
            };
        }
    }

    private static bool ReadNumber(string line, string prefix, out long number)
    {
        number = 0;
        return line.StartsWith(prefix, StringComparison.Ordinal)
               && long.TryParse(line[prefix.Length..].Trim(), NumberStyles.None,
                   CultureInfo.InvariantCulture, out number);
    }
}
