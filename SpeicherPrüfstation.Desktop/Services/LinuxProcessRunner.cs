using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SpeicherPrüfstation.Desktop.Services;

internal sealed record LinuxCommandOutput(
    int ExitCode, string StandardOutput, string StandardError);

internal static class LinuxProcessRunner
{
    internal static async Task<LinuxCommandOutput> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken,
        Action<string, bool>? onLine = null)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = new UTF8Encoding(false, true),
            StandardErrorEncoding = new UTF8Encoding(false, true),
            CreateNoWindow = true
        };

        // Feste Sprache für die dokumentierten Ausgabeformate.
        startInfo.Environment["LC_ALL"] = "C";
        startInfo.Environment["LANG"] = "C";

        foreach (string argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
            throw new IOException($"{executable} konnte nicht gestartet werden.");

        process.StandardInput.Close();
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);

        Task outputTask = ReadAsync(process.StandardOutput, stdout, false);
        Task errorTask = ReadAsync(process.StandardError, stderr, true);

        try
        {
            await process.WaitForExitAsync(lifetime.Token).ConfigureAwait(false);
            await Task.WhenAll(outputTask, errorTask).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return new LinuxCommandOutput(
                process.ExitCode, stdout.ToString(), stderr.ToString());
        }
        catch (Exception original)
        {
            // Erst den Prozess beenden und abwarten, dann darf aufgeräumt werden.
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);

                await process.WaitForExitAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception stopError)
            {
                throw new IOException(
                    $"{executable} konnte nicht sicher beendet werden: "
                    + stopError.Message, original);
            }
            finally
            {
                lifetime.Cancel();
                try
                {
                    await Task.WhenAll(outputTask, errorTask).ConfigureAwait(false);
                }
                catch
                {
                    // Der ursprüngliche Fehler wird unten weitergegeben.
                }
            }

            // Ein Lesefehler darf nicht als Benutzerabbruch erscheinen.
            if (!cancellationToken.IsCancellationRequested)
            {
                if (outputTask.Exception is { } outputError)
                    throw new IOException("Scanner-Ausgabe nicht lesbar.", outputError);
                if (errorTask.Exception is { } errorError)
                    throw new IOException("Fehlerausgabe nicht lesbar.", errorError);
            }

            throw;
        }

        async Task ReadAsync(StreamReader reader, StringBuilder capture, bool isError)
        {
            try
            {
                while (await reader.ReadLineAsync(lifetime.Token)
                           .ConfigureAwait(false) is { } line)
                {
                    if (line.Length > 65536)
                        throw new IOException("Eine Werkzeugmeldung überschreitet die zulässige Länge.");

                    if (onLine is not null)
                    {
                        onLine(line, isError);
                    }
                    else
                    {
                        if (capture.Length + line.Length > 8 * 1024 * 1024)
                            throw new IOException("Die Werkzeugausgabe ist zu groß.");
                        capture.AppendLine(line);
                    }
                }
            }
            catch
            {
                lifetime.Cancel();
                throw;
            }
        }
    }
}
